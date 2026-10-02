#!/usr/bin/env python3
"""
HTTP/3 (QUIC over UDP) benchmark client -- CSC/ECE 573 Project #1.
 
Opens ONE QUIC connection to the peer and pulls the four files over it on the
schedule the assignment specifies (1000 / 100 / 10 / 1 transfers). Each transfer
is timed with time.perf_counter() and the HTTP/3 application-layer bytes moved in
each direction are counted, so the per-file overhead ratio can be reported.
 
Run on computer 2 to fetch the A_* files from computer 1:
    python h3_client.py --host <ip-of-computer-1> --port 4433 --prefix A
 
Run on computer 1 to fetch the B_* files from computer 2:
    python h3_client.py --host <ip-of-computer-2> --port 4433 --prefix B
 
Requires: pip install "aioquic>=1.3.0"
"""
 
import argparse
import asyncio
import csv
import hashlib
import os
import socket
import ssl
import statistics
import time
from contextlib import asynccontextmanager
from typing import Any, Dict, Optional
 
from aioquic.asyncio import QuicConnectionProtocol
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import ConnectionTerminated, QuicEvent, StreamDataReceived
 
# (filename suffix, number of transfers, nominal size in bytes)
SCHEDULE = [
    ("10kB", 1000, 10 * 1000),
    ("100kB", 100, 100 * 1000),
    ("1MB", 10, 1000 * 1000),
    ("10MB", 1, 10 * 1000 * 1000),
]
 
 
@asynccontextmanager
async def quic_connect(
    host: str,
    port: int,
    *,
    configuration: QuicConfiguration,
    create_protocol,
    wait_connected: bool = True,
    local_port: int = 0,
):
    """
    Open one QUIC connection.
 
    This is aioquic's own asyncio.connect() with one fix: aioquic always opens a
    dual-stack AF_INET6 socket, which raises OSError(EAFNOSUPPORT) on hosts where
    IPv6 is disabled. We try IPv6 first and quietly fall back to plain IPv4.
    """
    loop = asyncio.get_running_loop()
 
    infos = await loop.getaddrinfo(host, port, type=socket.SOCK_DGRAM)
    addr = infos[0][4]
 
    sock: Optional[socket.socket] = None
    if socket.has_ipv6:
        try:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            sock.bind(("::", local_port, 0, 0))
            if len(addr) == 2:  # IPv4 peer reached through the dual-stack socket
                addr = ("::ffff:" + addr[0], addr[1], 0, 0)
        except OSError:
            if sock is not None:
                sock.close()
            sock = None
 
    if sock is None:  # IPv6 unavailable on this host
        infos = await loop.getaddrinfo(
            host, port, family=socket.AF_INET, type=socket.SOCK_DGRAM
        )
        addr = infos[0][4]
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("0.0.0.0", local_port))
 
    if configuration.server_name is None:
        configuration.server_name = host
    connection = QuicConnection(configuration=configuration)
 
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: create_protocol(connection), sock=sock
    )
    try:
        protocol.connect(addr, transmit=wait_connected)
        if wait_connected:
            await protocol.wait_connected()
        yield protocol
    finally:
        protocol.close()
        await protocol.wait_closed()
        transport.close()
 
 
class H3BenchClient(QuicConnectionProtocol):
    """One HTTP/3 connection; issues GETs sequentially and counts bytes."""
 
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
 
        # --- byte counters -------------------------------------------------
        # h3_bytes_in / h3_bytes_out are HTTP/3 application-layer bytes: the
        # QPACK-encoded HEADERS frames, the DATA frame headers and payload, and
        # the control/QPACK unidirectional stream traffic. That is exactly
        # "application layer data transferred including header content".
        # udp_bytes_in is the UDP payload actually received, which additionally
        # includes QUIC packet/frame headers, AEAD tags, ACKs and retransmits --
        # handy for discussing where the overhead really goes in the report.
        self.h3_bytes_in = 0
        self.h3_bytes_out = 0
        self.udp_bytes_in = 0
 
        # Count everything the H3 layer hands down to QUIC as stream data.
        _original_send = self._quic.send_stream_data
 
        def _counting_send(stream_id: int, data: bytes, end_stream: bool = False):
            self.h3_bytes_out += len(data)
            return _original_send(stream_id, data, end_stream)
 
        self._quic.send_stream_data = _counting_send  # type: ignore[method-assign]
 
        self._http = H3Connection(self._quic)
        self._streams: Dict[int, Dict[str, Any]] = {}
 
    # -- I/O hooks ----------------------------------------------------------
 
    def datagram_received(self, data, addr) -> None:
        self.udp_bytes_in += len(data)
        super().datagram_received(data, addr)
 
    def quic_event_received(self, event: QuicEvent) -> None:
        if isinstance(event, StreamDataReceived):
            self.h3_bytes_in += len(event.data)
        elif isinstance(event, ConnectionTerminated):
            for state in self._streams.values():
                if not state["waiter"].done():
                    state["waiter"].set_exception(
                        ConnectionError(f"connection closed: {event.reason_phrase}")
                    )
            self._streams.clear()
            return
 
        for h3_event in self._http.handle_event(event):
            stream_id = getattr(h3_event, "stream_id", None)
            state = self._streams.get(stream_id)
            if state is None:
                continue
 
            if isinstance(h3_event, HeadersReceived):
                headers = dict(h3_event.headers)
                state["status"] = headers.get(b":status", b"?")
                state["sha256"] = headers.get(b"x-sha256")
                if h3_event.stream_ended:
                    self._finish(stream_id)
            elif isinstance(h3_event, DataReceived):
                state["received"] += len(h3_event.data)
                if state["sink"] is not None:
                    # Hashed incrementally so a 10 MB body is never buffered.
                    state["sink"].update(h3_event.data)
                if h3_event.stream_ended:
                    self._finish(stream_id)
 
    def _finish(self, stream_id: int) -> None:
        state = self._streams.pop(stream_id, None)
        if state is not None and not state["waiter"].done():
            state["waiter"].set_result(state)
 
    # -- request ------------------------------------------------------------
 
    async def get(self, authority: str, path: str, keep_body: bool = False) -> dict:
        """Issue one GET on a fresh stream of the SAME connection."""
        stream_id = self._quic.get_next_available_stream_id()
        waiter = self._loop.create_future()
        self._streams[stream_id] = {
            "received": 0,
            "status": None,
            "sha256": None,
            "waiter": waiter,
            "sink": hashlib.sha256() if keep_body else None,
        }
 
        self._http.send_headers(
            stream_id,
            [
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b":authority", authority.encode()),
                (b":path", path.encode()),
                (b"user-agent", b"h3-bench"),
            ],
            end_stream=True,
        )
        self.transmit()
        return await asyncio.shield(waiter)
 
 
async def run_benchmark(args: argparse.Namespace) -> None:
    configuration = QuicConfiguration(
        alpn_protocols=H3_ALPN,
        is_client=True,
        max_data=args.max_data,
        max_stream_data=args.max_stream_data,
        max_datagram_size=args.mtu,
        congestion_control_algorithm=args.cc,
        idle_timeout=args.idle_timeout,
    )
 
    if args.ca:
        configuration.load_verify_locations(cafile=args.ca)
    else:
        # Self-signed certificate on the peer: skip verification.
        configuration.verify_mode = ssl.CERT_NONE
 
    authority = f"{args.host}:{args.port}"
    rows = []
    summary = []
 
    async with quic_connect(
        args.host,
        args.port,
        configuration=configuration,
        create_protocol=H3BenchClient,
        wait_connected=True,
    ) as client:
        client = client  # type: H3BenchClient
        print(f"connected to {authority} over HTTP/3 (one QUIC connection)\n")
 
        for suffix, count, nominal in SCHEDULE:
            name = f"{args.prefix}_{suffix}"
            if args.only and suffix not in args.only:
                continue
 
            # Optional untimed warm-up so QPACK's dynamic table and the
            # congestion window are not cold for run #1.
            for _ in range(args.warmup):
                await client.get(authority, f"/{name}")
 
            durations = []
            overheads = []
            actual_size = None
 
            for run_index in range(1, count + 1):
                b_in0 = client.h3_bytes_in
                b_out0 = client.h3_bytes_out
                u_in0 = client.udp_bytes_in
 
                start = time.perf_counter()
                result = await client.get(authority, f"/{name}", keep_body=args.verify)
                elapsed = time.perf_counter() - start
 
                if result["status"] != b"200":
                    raise SystemExit(
                        f"server returned status {result['status']!r} for /{name} "
                        f"-- is the file present in the server's --dir?"
                    )
 
                if args.verify:
                    got = result["sink"].hexdigest().encode()
                    want = result["sha256"]
                    if want is not None and got != want:
                        raise SystemExit(
                            f"INTEGRITY FAILURE on /{name} run {run_index}: "
                            f"expected sha256 {want.decode()}, got {got.decode()}"
                        )
 
                size = result["received"]
                actual_size = size
                h3_down = client.h3_bytes_in - b_in0
                h3_up = client.h3_bytes_out - b_out0
                udp_down = client.udp_bytes_in - u_in0
 
                durations.append(elapsed)
                overheads.append(h3_down / size if size else 0.0)
 
                rows.append(
                    {
                        "protocol": "HTTP/3",
                        "file": name,
                        "file_size_bytes": size,
                        "run": run_index,
                        "seconds": f"{elapsed:.9f}",
                        "throughput_bytes_per_s": f"{size / elapsed:.3f}",
                        "throughput_Mbps": f"{size * 8 / elapsed / 1e6:.4f}",
                        "h3_bytes_down": h3_down,
                        "h3_bytes_up": h3_up,
                        "udp_bytes_down": udp_down,
                        "h3_overhead_ratio": f"{h3_down / size:.6f}" if size else "",
                        "udp_overhead_ratio": f"{udp_down / size:.6f}" if size else "",
                    }
                )
 
                if args.progress and run_index % args.progress == 0:
                    print(f"  {name}: {run_index}/{count}")
 
            mean_t = statistics.mean(durations)
            thr = [actual_size * 8 / d / 1e6 for d in durations]
            summary.append(
                {
                    "protocol": "HTTP/3",
                    "file": name,
                    "file_size_bytes": actual_size,
                    "transfers": len(durations),
                    "mean_seconds": f"{mean_t:.9f}",
                    "median_seconds": f"{statistics.median(durations):.9f}",
                    "min_seconds": f"{min(durations):.9f}",
                    "max_seconds": f"{max(durations):.9f}",
                    "mean_throughput_Mbps": f"{statistics.mean(thr):.4f}",
                    "median_throughput_Mbps": f"{statistics.median(thr):.4f}",
                    "mean_h3_overhead_ratio": f"{statistics.mean(overheads):.6f}",
                }
            )
            print(
                f"{name}: {len(durations)} transfers, "
                f"mean {mean_t * 1000:.3f} ms, "
                f"mean {statistics.mean(thr):.2f} Mbps, "
                f"app-layer overhead ratio {statistics.mean(overheads):.4f}\n"
            )
 
        client.close()
        await client.wait_closed()
 
    per_run = args.out or f"h3_results_{args.prefix}.csv"
    per_file = os.path.splitext(per_run)[0] + "_summary.csv"
 
    with open(per_run, "w", newline="") as fp:
        writer = csv.DictWriter(fp, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
 
    with open(per_file, "w", newline="") as fp:
        writer = csv.DictWriter(fp, fieldnames=list(summary[0].keys()))
        writer.writeheader()
        writer.writerows(summary)
 
    print(f"wrote {len(rows)} per-transfer rows to {per_run}")
    print(f"wrote per-file summary to {per_file}")
 
 
def main() -> None:
    parser = argparse.ArgumentParser(description="HTTP/3 benchmark client")
    parser.add_argument("--host", required=True, help="peer's IP address")
    parser.add_argument("--port", type=int, default=4433)
    parser.add_argument(
        "--prefix",
        required=True,
        choices=["A", "B"],
        help="which file set to fetch from the peer",
    )
    parser.add_argument("--out", help="per-transfer CSV output path")
    parser.add_argument("--ca", help="CA/cert PEM to verify the peer against")
    parser.add_argument("--warmup", type=int, default=0, help="untimed transfers first")
    parser.add_argument(
        "--verify",
        action="store_true",
        help="SHA-256 every received file against the server's digest "
        "(adds client-side hashing cost to the measured time)",
    )
    parser.add_argument(
        "--only", nargs="*", help="run only these sizes, e.g. --only 10kB 1MB"
    )
    parser.add_argument("--progress", type=int, default=100, help="0 to silence")
    parser.add_argument("--mtu", type=int, default=1452)
    parser.add_argument("--cc", default="cubic", choices=["reno", "cubic"])
    parser.add_argument("--max-data", type=int, default=64 * 1024 * 1024)
    parser.add_argument("--max-stream-data", type=int, default=32 * 1024 * 1024)
    parser.add_argument("--idle-timeout", type=float, default=300.0)
    args = parser.parse_args()
 
    asyncio.run(run_benchmark(args))
 
 
if __name__ == "__main__":
    main()
 
