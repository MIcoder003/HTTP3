#!/usr/bin/env python3
"""
HTTP/3 (QUIC over UDP) benchmark client -- CSC/ECE 573 Project #1.

Runs on COMPUTER 2, which stores the B_* files. It opens ONE QUIC connection to
computer 1 and drives BOTH directions over it:

  * GET  /A_<size>  -> downloads an A file   (computer 1 -> computer 2)
  * POST /B_<size>  -> uploads a B file      (computer 2 -> computer 1)

That satisfies "open only one TCP connection (resp., one UDP connection)
between the two computers": there is a single QUIC connection for all 2222
transfers.

    python3 h3_client.py --host <IP-OF-COMPUTER-1> --port 4433 --dir ./files

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

# (filename suffix, number of transfers in EACH direction)
SCHEDULE = [
    ("10kB", 1000),
    ("100kB", 100),
    ("1MB", 10),
    ("10MB", 1),
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
    connect_timeout: float = 15.0,
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
            # Bound the handshake wait. Without this, an unreachable peer (server
            # down, or UDP blocked by a firewall) hangs for the full idle_timeout
            # and then raises a bare ConnectionError.
            try:
                await asyncio.wait_for(
                    protocol.wait_connected(), timeout=connect_timeout
                )
            except (asyncio.TimeoutError, ConnectionError):
                # wait_for() cancels only the shield's outer future, leaving
                # aioquic's inner waiter pending. The connection then terminates
                # during cleanup below and aioquic sets an exception on that
                # unwatched future, which asyncio reports as "Future exception
                # was never retrieved". Detach it so that never happens.
                inner = getattr(protocol, "_connected_waiter", None)
                if inner is not None:
                    protocol._connected_waiter = None
                    if inner.done() and not inner.cancelled():
                        inner.exception()  # retrieve so it is not reported
                raise SystemExit(
                    f"\nCould not complete the QUIC handshake with {host}:{port} "
                    f"within {connect_timeout:.0f}s.\n"
                    f"Check, in this order:\n"
                    f"  1. Is h3_server.py running on {host}?\n"
                    f"  2. Is the server bound to --host 0.0.0.0 "
                    f"(not 127.0.0.1, which only accepts local connections)?\n"
                    f"  3. Is UDP port {port} open in the firewall on BOTH machines?\n"
                    f"     QUIC is UDP, not TCP -- a TCP-only rule will not work.\n"
                    f"  4. Can the machines reach each other at all? "
                    f"Try: ping {host}\n"
                )
        yield protocol
    finally:
        protocol.close()
        await protocol.wait_closed()
        transport.close()


class H3BenchClient(QuicConnectionProtocol):
    """One HTTP/3 connection carrying both downloads (GET) and uploads (POST)."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        # --- byte counters -------------------------------------------------
        # h3_bytes_* are HTTP/3 application-layer bytes: the QPACK-encoded
        # HEADERS frames, the DATA frame headers and payload, and the
        # control/QPACK unidirectional stream traffic. That is exactly the
        # "application layer data transferred from sender to receiver
        # (including header content)" the results table asks for.
        # udp_bytes_* are the UDP payloads actually moved, which additionally
        # include QUIC packet headers, AEAD tags, ACKs and retransmits.
        self.h3_bytes_in = 0
        self.h3_bytes_out = 0
        self.udp_bytes_in = 0
        self.udp_bytes_out = 0

        # Count everything the H3 layer hands down to QUIC as stream data.
        _original_send = self._quic.send_stream_data

        def _counting_send(stream_id: int, data: bytes, end_stream: bool = False):
            self.h3_bytes_out += len(data)
            return _original_send(stream_id, data, end_stream)

        self._quic.send_stream_data = _counting_send  # type: ignore[method-assign]

        self._http = H3Connection(self._quic)
        self._streams: Dict[int, Dict[str, Any]] = {}

    # -- I/O hooks ----------------------------------------------------------

    def connection_made(self, transport) -> None:
        # Wrap sendto() so outbound UDP payload is counted too.
        _original_sendto = transport.sendto

        def _counting_sendto(data, *args, **kwargs):
            self.udp_bytes_out += len(data)
            return _original_sendto(data, *args, **kwargs)

        transport.sendto = _counting_sendto
        super().connection_made(transport)

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
                state["received_bytes_hdr"] = headers.get(b"x-received-bytes")
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

    def _new_stream(self, keep_body: bool):
        stream_id = self._quic.get_next_available_stream_id()
        waiter = self._loop.create_future()
        self._streams[stream_id] = {
            "received": 0,
            "status": None,
            "sha256": None,
            "received_bytes_hdr": None,
            "waiter": waiter,
            "sink": hashlib.sha256() if keep_body else None,
        }
        return stream_id, waiter

    # -- requests -----------------------------------------------------------

    async def get(self, authority: str, path: str, keep_body: bool = False) -> dict:
        """Download one file on a fresh stream of the SAME connection."""
        stream_id, waiter = self._new_stream(keep_body)
        headers = [
            (b":method", b"GET"),
            (b":scheme", b"https"),
            (b":authority", authority.encode()),
            (b":path", path.encode()),
            (b"user-agent", b"h3-bench"),
        ]
        if keep_body:
            # Ask for the integrity digest only when we are going to check it.
            headers.append((b"x-want-digest", b"1"))
        self._http.send_headers(stream_id, headers, end_stream=True)
        self.transmit()
        return await asyncio.shield(waiter)

    async def post(self, authority: str, path: str, body: bytes) -> dict:
        """Upload one file on a fresh stream of the SAME connection."""
        stream_id, waiter = self._new_stream(keep_body=False)
        self._http.send_headers(
            stream_id,
            [
                (b":method", b"POST"),
                (b":scheme", b"https"),
                (b":authority", authority.encode()),
                (b":path", path.encode()),
                (b"content-type", b"application/octet-stream"),
                (b"content-length", str(len(body)).encode()),
                (b"user-agent", b"h3-bench"),
            ],
            end_stream=False,
        )
        self._http.send_data(stream_id, body, end_stream=True)
        self.transmit()
        return await asyncio.shield(waiter)


def load_upload_files(directory: str, prefix: str) -> Dict[str, bytes]:
    """Preload the local files we will upload, so disk I/O is not measured."""
    out: Dict[str, bytes] = {}
    if not os.path.isdir(directory):
        raise SystemExit(
            f"\nERROR: --dir {directory!r} does not exist.\n"
            f"It must contain the {prefix}_* files this computer uploads.\n"
        )
    for suffix, _ in SCHEDULE:
        name = f"{prefix}_{suffix}"
        path = os.path.join(directory, name)
        if not os.path.isfile(path):
            raise SystemExit(
                f"\nERROR: {path!r} not found.\n"
                f"This computer must hold the {prefix}_* files to upload them.\n"
            )
        with open(path, "rb") as fp:
            out[name] = fp.read()
    return out


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

    uploads: Dict[str, bytes] = {}
    upload_digests: Dict[str, bytes] = {}
    if args.upload_prefix:
        uploads = load_upload_files(args.dir, args.upload_prefix)
        upload_digests = {
            n: hashlib.sha256(b).hexdigest().encode() for n, b in uploads.items()
        }

    authority = f"{args.host}:{args.port}"
    rows = []
    summary = []

    async with quic_connect(
        args.host,
        args.port,
        configuration=configuration,
        create_protocol=H3BenchClient,
        wait_connected=True,
        connect_timeout=args.connect_timeout,
    ) as client:
        print(f"connected to {authority} over HTTP/3 (one QUIC connection)\n")

        for suffix, count in SCHEDULE:
            if args.only and suffix not in args.only:
                continue

            # The assignment lists each size as a download then an upload, so
            # run them in that order.
            jobs = []
            if args.download_prefix:
                jobs.append(("download", f"{args.download_prefix}_{suffix}"))
            if args.upload_prefix:
                jobs.append(("upload", f"{args.upload_prefix}_{suffix}"))

            for direction, name in jobs:
                for _ in range(args.warmup):
                    if direction == "download":
                        await client.get(authority, f"/{name}")
                    else:
                        await client.post(authority, f"/{name}", uploads[name])

                durations = []
                overheads = []
                actual_size = None

                for run_index in range(1, count + 1):
                    b_in0 = client.h3_bytes_in
                    b_out0 = client.h3_bytes_out
                    u_in0 = client.udp_bytes_in
                    u_out0 = client.udp_bytes_out

                    start = time.perf_counter()
                    if direction == "download":
                        result = await client.get(
                            authority, f"/{name}", keep_body=args.verify
                        )
                    else:
                        result = await client.post(authority, f"/{name}", uploads[name])
                    elapsed = time.perf_counter() - start

                    if result["status"] != b"200":
                        raise SystemExit(
                            f"server returned status {result['status']!r} for "
                            f"/{name} ({direction}) -- for a download, is the "
                            f"file in the server's --dir?"
                        )

                    h3_down = client.h3_bytes_in - b_in0
                    h3_up = client.h3_bytes_out - b_out0
                    udp_down = client.udp_bytes_in - u_in0
                    udp_up = client.udp_bytes_out - u_out0

                    if direction == "download":
                        size = result["received"]
                        # sender -> receiver is server -> us
                        app_bytes = h3_down
                        udp_bytes = udp_down
                        if args.verify:
                            got = result["sink"].hexdigest().encode()
                            want = result["sha256"]
                            if want is not None and got != want:
                                raise SystemExit(
                                    f"INTEGRITY FAILURE downloading /{name} run "
                                    f"{run_index}: expected {want.decode()}, "
                                    f"got {got.decode()}"
                                )
                    else:
                        size = len(uploads[name])
                        # sender -> receiver is us -> server
                        app_bytes = h3_up
                        udp_bytes = udp_up
                        if args.verify:
                            want = upload_digests[name]
                            got = result["sha256"]
                            if got is not None and got != want:
                                raise SystemExit(
                                    f"INTEGRITY FAILURE uploading /{name} run "
                                    f"{run_index}: server received {got.decode()}, "
                                    f"expected {want.decode()}"
                                )

                    actual_size = size
                    durations.append(elapsed)
                    overheads.append(app_bytes / size if size else 0.0)

                    rows.append(
                        {
                            "protocol": "HTTP/3",
                            "direction": direction,
                            "file": name,
                            "file_size_bytes": size,
                            "run": run_index,
                            "seconds": f"{elapsed:.9f}",
                            "throughput_bytes_per_s": f"{size / elapsed:.3f}",
                            "throughput_Mbps": f"{size * 8 / elapsed / 1e6:.4f}",
                            "app_bytes_sender_to_receiver": app_bytes,
                            "overhead_ratio": f"{app_bytes / size:.6f}" if size else "",
                            "udp_bytes_sender_to_receiver": udp_bytes,
                            "udp_overhead_ratio": (
                                f"{udp_bytes / size:.6f}" if size else ""
                            ),
                            "h3_bytes_down": h3_down,
                            "h3_bytes_up": h3_up,
                        }
                    )

                    if args.progress and run_index % args.progress == 0:
                        print(f"  {name} ({direction}): {run_index}/{count}")

                mean_t = statistics.mean(durations)
                thr = [actual_size * 8 / d / 1e6 for d in durations]
                summary.append(
                    {
                        "protocol": "HTTP/3",
                        "direction": direction,
                        "file": name,
                        "file_size_bytes": actual_size,
                        "transfers": len(durations),
                        "mean_seconds": f"{mean_t:.9f}",
                        "median_seconds": f"{statistics.median(durations):.9f}",
                        "min_seconds": f"{min(durations):.9f}",
                        "max_seconds": f"{max(durations):.9f}",
                        "mean_throughput_Mbps": f"{statistics.mean(thr):.4f}",
                        "median_throughput_Mbps": f"{statistics.median(thr):.4f}",
                        "mean_overhead_ratio": f"{statistics.mean(overheads):.6f}",
                    }
                )
                print(
                    f"{name:9s} {direction:8s} {len(durations):4d} transfers, "
                    f"mean {mean_t * 1000:9.3f} ms, "
                    f"mean {statistics.mean(thr):7.2f} Mbps, "
                    f"overhead ratio {statistics.mean(overheads):.4f}"
                )

        client.close()
        await client.wait_closed()

    per_run = args.out or "h3_results.csv"
    per_file = os.path.splitext(per_run)[0] + "_summary.csv"

    with open(per_run, "w", newline="") as fp:
        writer = csv.DictWriter(fp, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    with open(per_file, "w", newline="") as fp:
        writer = csv.DictWriter(fp, fieldnames=list(summary[0].keys()))
        writer.writeheader()
        writer.writerows(summary)

    print(f"\nwrote {len(rows)} per-transfer rows to {per_run}")
    print(f"wrote per-file summary to {per_file}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="HTTP/3 benchmark client (downloads A files, uploads B files)"
    )
    parser.add_argument("--host", required=True, help="the server's IP address")
    parser.add_argument("--port", type=int, default=4433)
    parser.add_argument(
        "--download-prefix",
        default="A",
        help="prefix of the files fetched FROM the server (empty to skip)",
    )
    parser.add_argument(
        "--upload-prefix",
        default="B",
        help="prefix of the local files sent TO the server (empty to skip)",
    )
    parser.add_argument(
        "--dir", default="./files", help="directory holding the files to upload"
    )
    parser.add_argument("--out", help="per-transfer CSV output path")
    parser.add_argument("--ca", help="CA/cert PEM to verify the peer against")
    parser.add_argument("--warmup", type=int, default=0, help="untimed transfers first")
    parser.add_argument(
        "--verify",
        action="store_true",
        help="SHA-256 check every transfer in both directions "
        "(adds hashing cost to the measured time)",
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
    parser.add_argument(
        "--connect-timeout",
        type=float,
        default=15.0,
        help="seconds to wait for the QUIC handshake before giving up",
    )
    args = parser.parse_args()

    asyncio.run(run_benchmark(args))


if __name__ == "__main__":
    main()