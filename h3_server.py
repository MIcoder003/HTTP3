#!/usr/bin/env python3
"""
HTTP/3 (QUIC over UDP) file server -- CSC/ECE 573 Project #1.

Serves the files sitting in --dir over HTTP/3. Run one copy of this on EACH
computer: computer 1 serves the A_* files, computer 2 serves the B_* files.

    python h3_server.py --host 0.0.0.0 --port 4433 --dir ./files \
                        --cert cert.pem --key key.pem

Requires: pip install "aioquic>=1.3.0"
"""

import argparse
import asyncio
import hashlib
import logging
import os
from typing import Dict, Optional

from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ProtocolNegotiated, QuicEvent

logger = logging.getLogger("h3-server")

# Files are preloaded into RAM so that disk I/O is not part of what we measure.
FILE_CACHE: Dict[str, bytes] = {}
FILE_SHA256: Dict[str, bytes] = {}
SERVE_DIR = "."


def preload(directory: str) -> None:
    """Read every regular file in `directory` into memory once, at startup."""
    for name in sorted(os.listdir(directory)):
        path = os.path.join(directory, name)
        if os.path.isfile(path):
            with open(path, "rb") as fp:
                FILE_CACHE[name] = fp.read()
            FILE_SHA256[name] = hashlib.sha256(FILE_CACHE[name]).hexdigest().encode()
            logger.info("cached %s (%d bytes)", name, len(FILE_CACHE[name]))
    if not FILE_CACHE:
        logger.warning("no files found in %s", directory)


class H3FileServerProtocol(QuicConnectionProtocol):
    """One instance per QUIC connection. Answers GET /<filename>."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._http: Optional[H3Connection] = None

    def quic_event_received(self, event: QuicEvent) -> None:
        # The H3 layer can only be built once ALPN has settled on "h3".
        if isinstance(event, ProtocolNegotiated) and self._http is None:
            self._http = H3Connection(self._quic)

        if self._http is not None:
            for h3_event in self._http.handle_event(event):
                if isinstance(h3_event, HeadersReceived):
                    self._handle_request(h3_event)

    def _handle_request(self, event: HeadersReceived) -> None:
        headers = dict(event.headers)
        method = headers.get(b":method", b"GET")
        raw_path = headers.get(b":path", b"/").decode("utf-8", "replace")

        # basename() keeps this from walking out of the serve directory
        name = os.path.basename(raw_path.split("?", 1)[0].lstrip("/"))
        body = FILE_CACHE.get(name) if method == b"GET" else None

        if body is None:
            self._http.send_headers(
                event.stream_id,
                [
                    (b":status", b"404"),
                    (b"content-length", b"0"),
                    (b"server", b"h3-bench"),
                ],
                end_stream=True,
            )
        else:
            self._http.send_headers(
                event.stream_id,
                [
                    (b":status", b"200"),
                    (b"content-type", b"application/octet-stream"),
                    (b"content-length", str(len(body)).encode()),
                    (b"server", b"h3-bench"),
                    # Lets the client verify integrity with --verify. It is a
                    # fixed 64-byte header, so it does not distort the overhead
                    # comparison between protocols as long as both send it.
                    (b"x-sha256", FILE_SHA256[name]),
                ],
            )
            self._http.send_data(event.stream_id, body, end_stream=True)

        self.transmit()


async def run(args: argparse.Namespace) -> None:
    configuration = QuicConfiguration(
        alpn_protocols=H3_ALPN,
        is_client=False,
        # Generous flow-control windows: the defaults (1 MB) throttle the 10 MB
        # transfer while it waits for MAX_DATA / MAX_STREAM_DATA updates.
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

    global SERVE_DIR
    SERVE_DIR = args.dir
    preload(args.dir)

    try:
        asyncio.run(run(args))
    except KeyboardInterrupt:
        logger.info("shutting down")


if __name__ == "__main__":
    main()