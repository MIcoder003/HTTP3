#!/usr/bin/env python3
"""
HTTP/3 (QUIC over UDP) file server -- CSC/ECE 573 Project #1.

Runs on COMPUTER 1, which stores the A_* files. It does two jobs over the same
QUIC connection:

  * GET  /A_<size>  -> sends the requested A file   (computer 1 -> computer 2)
  * POST /B_<size>  -> receives an uploaded B file  (computer 2 -> computer 1)

Both directions therefore share ONE UDP/QUIC connection, as the assignment
requires ("open only one TCP connection (resp., one UDP connection) between the
two computers").

    python3 h3_server.py --host 0.0.0.0 --port 4433 --dir ./files \
                         --cert cert.pem --key key.pem

Requires: pip install "aioquic>=1.3.0"
"""

import argparse
import asyncio
import hashlib
import logging
import os
from typing import Any, Dict, Optional

from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ProtocolNegotiated, QuicEvent

logger = logging.getLogger("h3-server")

# Files are preloaded into RAM so that disk I/O is not part of what we measure.
FILE_CACHE: Dict[str, bytes] = {}
FILE_SHA256: Dict[str, bytes] = {}


def preload(directory: str) -> None:
    """
    Read every regular file in `directory` into memory once, at startup.

    This happens ONLY at startup: files added later are not picked up, so the
    server must be restarted after creating them. Rather than start up and then
    serve 404s for everything, refuse to run if the directory is missing or
    empty -- that failure is far easier to diagnose.
    """
    if not os.path.isdir(directory):
        raise SystemExit(
            f"\nERROR: --dir {directory!r} does not exist.\n"
            f"Put the assignment's A_* files there first.\n"
        )

    for name in sorted(os.listdir(directory)):
        path = os.path.join(directory, name)
        if os.path.isfile(path):
            with open(path, "rb") as fp:
                FILE_CACHE[name] = fp.read()
            FILE_SHA256[name] = hashlib.sha256(FILE_CACHE[name]).hexdigest().encode()
            logger.info("cached %s (%d bytes)", name, len(FILE_CACHE[name]))

    if not FILE_CACHE:
        raise SystemExit(
            f"\nERROR: no files found in {directory!r}, so every GET would "
            f"return 404.\n"
            f"Put the assignment's A_* files there, then start the server "
            f"again -- files are loaded at startup only.\n"
        )


class H3FileServerProtocol(QuicConnectionProtocol):
    """One instance per QUIC connection. Serves GETs and accepts POSTs."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._http: Optional[H3Connection] = None
        # In-flight uploads, keyed by stream id.
        self._uploads: Dict[int, Dict[str, Any]] = {}

    def quic_event_received(self, event: QuicEvent) -> None:
        # The H3 layer can only be built once ALPN has settled on "h3".
        if isinstance(event, ProtocolNegotiated) and self._http is None:
            self._http = H3Connection(self._quic)

        if self._http is not None:
            for h3_event in self._http.handle_event(event):
                if isinstance(h3_event, HeadersReceived):
                    self._handle_headers(h3_event)
                elif isinstance(h3_event, DataReceived):
                    self._handle_data(h3_event)

    # -- requests -----------------------------------------------------------

    def _handle_headers(self, event: HeadersReceived) -> None:
        headers = dict(event.headers)
        method = headers.get(b":method", b"")
        raw_path = headers.get(b":path", b"/").decode("utf-8", "replace")
        # basename() keeps this from walking out of the serve directory
        name = os.path.basename(raw_path.split("?", 1)[0].lstrip("/"))

        if method == b"GET":
            # Only attach the integrity digest when the client asks for it, so
            # the 64-byte header does not inflate the overhead ratio on the
            # runs that get reported.
            self._serve_file(
                event.stream_id, name, want_digest=b"x-want-digest" in headers
            )
        elif method == b"POST":
            # Start an upload. The body arrives as DataReceived events; hash it
            # incrementally and discard it, so neither RAM nor disk I/O
            # distorts the measurement.
            self._uploads[event.stream_id] = {
                "name": name,
                "hasher": hashlib.sha256(),
                "bytes": 0,
            }
            if event.stream_ended:  # zero-length body
                self._finish_upload(event.stream_id)
        else:
            self._send_status(event.stream_id, b"405")

    def _handle_data(self, event: DataReceived) -> None:
        state = self._uploads.get(event.stream_id)
        if state is None:
            return
        state["hasher"].update(event.data)
        state["bytes"] += len(event.data)
        if event.stream_ended:
            self._finish_upload(event.stream_id)

    def _finish_upload(self, stream_id: int) -> None:
        state = self._uploads.pop(stream_id, None)
        if state is None:
            return
        logger.debug("received %s (%d bytes)", state["name"], state["bytes"])
        # Echo back what we received so the client can verify the upload.
        self._http.send_headers(
            stream_id,
            [
                (b":status", b"200"),
                (b"content-length", b"0"),
                (b"server", b"h3-bench"),
                (b"x-received-bytes", str(state["bytes"]).encode()),
                (b"x-sha256", state["hasher"].hexdigest().encode()),
            ],
            end_stream=True,
        )
        self.transmit()

    def _serve_file(self, stream_id: int, name: str, want_digest: bool = False) -> None:
        body = FILE_CACHE.get(name)
        if body is None:
            self._send_status(stream_id, b"404")
            return

        headers = [
            (b":status", b"200"),
            (b"content-type", b"application/octet-stream"),
            (b"content-length", str(len(body)).encode()),
            (b"server", b"h3-bench"),
        ]
        if want_digest:
            headers.append((b"x-sha256", FILE_SHA256[name]))

        self._http.send_headers(stream_id, headers)
        self._http.send_data(stream_id, body, end_stream=True)
        self.transmit()

    def _send_status(self, stream_id: int, status: bytes) -> None:
        self._http.send_headers(
            stream_id,
            [(b":status", status), (b"content-length", b"0"), (b"server", b"h3-bench")],
            end_stream=True,
        )
        self.transmit()


async def run(args: argparse.Namespace) -> None:
    configuration = QuicConfiguration(
        alpn_protocols=H3_ALPN,
        is_client=False,
        # Generous flow-control windows. The defaults (1 MB) throttle the 10 MB
        # transfer in BOTH directions while it waits for MAX_DATA /
        # MAX_STREAM_DATA updates -- max_stream_data is also what bounds how
        # much the client may upload to us on a single stream.
        max_data=args.max_data,
        max_stream_data=args.max_stream_data,
        # Bigger QUIC packets => fewer per-packet crypto + Python operations.
        max_datagram_size=args.mtu,
        congestion_control_algorithm=args.cc,
        idle_timeout=args.idle_timeout,
    )
    configuration.load_cert_chain(args.cert, args.key)

    await serve(
        args.host,
        args.port,
        configuration=configuration,
        create_protocol=H3FileServerProtocol,
    )
    logger.info("HTTP/3 server listening on udp://%s:%d", args.host, args.port)
    logger.info("serving GET for %d cached file(s); accepting POST uploads",
                len(FILE_CACHE))
    await asyncio.Future()  # run forever


def main() -> None:
    parser = argparse.ArgumentParser(description="HTTP/3 file server")
    parser.add_argument("--host", default="0.0.0.0", help="bind address")
    parser.add_argument("--port", type=int, default=4433, help="UDP port")
    parser.add_argument("--dir", default="./files", help="directory of files to serve")
    parser.add_argument("--cert", default="cert.pem", help="TLS certificate (PEM)")
    parser.add_argument("--key", default="key.pem", help="TLS private key (PEM)")
    parser.add_argument("--mtu", type=int, default=1452, help="max QUIC datagram size")
    parser.add_argument("--cc", default="cubic", choices=["reno", "cubic"])
    parser.add_argument("--max-data", type=int, default=64 * 1024 * 1024)
    parser.add_argument("--max-stream-data", type=int, default=32 * 1024 * 1024)
    parser.add_argument("--idle-timeout", type=float, default=300.0)
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    preload(args.dir)

    try:
        asyncio.run(run(args))
    except KeyboardInterrupt:
        logger.info("shutting down")


if __name__ == "__main__":
    main()