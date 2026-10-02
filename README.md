# HTTP/3 (QUIC) transfer benchmark — CSC/ECE 573 Project #1

Two scripts implement the HTTP/3 half of the assignment:

| File | Role |
|---|---|
| `h3_server.py` | HTTP/3 file server. Runs on **both** computers. |
| `h3_client.py` | Benchmark client. Opens **one** QUIC connection and runs the 1000/100/10/1 schedule. |

## 1. Install

On both computers (Python 3.9+):

```bash
pip install "aioquic>=1.3.0"
```

`aioquic` is the HTTP/3 + QUIC implementation: <https://pypi.org/project/aioquic/> ·
source <https://github.com/aiortc/aioquic>. It pulls in `cryptography` and
`pylsqpack` (QPACK header compression) automatically.

## 2. Generate a certificate

QUIC always runs over TLS 1.3, so the server needs a key pair. A self-signed one
is fine. Run this **once on each computer**, in the same directory as the scripts:

```bash
openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout key.pem -out cert.pem -days 365 -subj "/CN=h3bench"
```

The client does not verify the certificate by default. To verify instead, copy the
peer's `cert.pem` over and pass `--ca peer_cert.pem`.

## 3. Lay out the files

```
computer 1:  files/A_10kB  A_100kB  A_1MB  A_10MB
computer 2:  files/B_10kB  B_100kB  B_1MB  B_10MB
```

Each machine serves only its own set; each machine's client fetches only the
peer's set.

## 4. Run

**Start the server on both computers** (leave running):

```bash
python3 h3_server.py --host 0.0.0.0 --port 4433 --dir ./files \
                     --cert cert.pem --key key.pem
```

**Then run the client on each computer**, pointed at the other:

```bash
# on computer 2 -> pulls the A_* files from computer 1
python3 h3_client.py --host <IP-OF-COMPUTER-1> --port 4433 --prefix A

# on computer 1 -> pulls the B_* files from computer 2
python3 h3_client.py --host <IP-OF-COMPUTER-2> --port 4433 --prefix B
```

Each client performs all 1111 transfers (1000 × 10kB, 100 × 100kB, 10 × 1MB,
1 × 10MB) over a **single QUIC connection**, as the assignment requires.

Open UDP port 4433 in the firewall on both machines.

### Output

* `h3_results_<prefix>.csv` — one row per transfer
* `h3_results_<prefix>_summary.csv` — per-file means/medians, for the results table

Per-transfer columns: `seconds`, `throughput_bytes_per_s`, `throughput_Mbps`,
`h3_bytes_down`, `h3_bytes_up`, `udp_bytes_down`, `h3_overhead_ratio`,
`udp_overhead_ratio`.

### Useful flags

| Flag | Meaning |
|---|---|
| `--verify` | SHA-256 every received file against a digest the server sends. Adds hashing cost to the timing, so leave it **off** for the runs you report. |
| `--only 10kB 1MB` | Run a subset of sizes (for testing). |
| `--warmup N` | N untimed transfers first. Leave at 0 for the reported runs. |
| `--cc reno\|cubic` | Congestion control. Default `cubic`. |
| `--mtu N` | Max QUIC datagram size, default 1452. Lower to ~1200 on a VPN or if you see loss. |
| `--progress N` | Print progress every N transfers; `0` silences. |

## 5. How the two measurements are taken

**Time.** `time.perf_counter()` is read immediately before the HEADERS frame is
handed to QUIC and again when the response stream ends. Throughput is
`file_size / elapsed`. Nothing is timed by hand.

**Application-layer bytes.** The client counts bytes at the HTTP/3 layer in both
directions:

* `h3_bytes_down` — every byte QUIC delivers as stream data: the QPACK-encoded
  HEADERS frame, the DATA frame header, the payload, and the control/QPACK
  unidirectional streams. This is the "application layer data transferred from
  sender to receiver **including header content**" the results table asks for, so
  `h3_overhead_ratio = h3_bytes_down / file_size` is the column to report.
* `h3_bytes_up` — the request headers going the other way.
* `udp_bytes_down` — raw UDP payload received, which additionally includes QUIC
  packet headers, AEAD authentication tags, ACK frames and any retransmissions.
  Not required, but it is the honest measure of wire overhead and makes the
  discussion section much stronger.

## 6. Things worth mentioning in the report

These come out of the instrumentation and are easy to argue from your own data:

* **QPACK compression is visible across runs.** On the first request the response
  headers cost ~48 bytes and the request ~34; once QPACK's dynamic table is
  populated, later requests on the same connection cost ~14 and ~10 bytes. Header
  overhead therefore falls as the run proceeds — a direct consequence of reusing
  one connection.
* **Overhead ratio is dominated by file size.** Measured app-layer ratios were
  ≈1.0015 for 10kB, 1.00018 for 100kB, 1.00003 for 1MB and 1.000007 for 10MB: the
  fixed header cost is amortised away as the payload grows.
* **At the UDP layer the ratio is ~1.025 regardless of size** — roughly 2.5% for
  QUIC packet headers, 16-byte AEAD tags and ACKs. Contrasting the ~1.00003
  app-layer ratio with the ~1.025 UDP ratio is the clearest way to show where
  QUIC's real overhead lives.
* **Throughput rises with file size** (≈51 → 118 → 142 → 157 Mbps in our loopback
  check) because per-transfer costs — request/response round trip, stream setup,
  congestion-window ramp — are amortised over more bytes. For the 10kB case the
  RTT, not the link, is the limit.
* **Expect HTTP/3 to lose to HTTP/2 here, and say why.** `aioquic` runs QUIC's
  loss recovery, congestion control and packet crypto in pure Python in user
  space, while HTTP/2's TCP+TLS path runs in the kernel with hardware-accelerated
  crypto and segmentation offload. That is an implementation artifact, not a
  property of the protocol — an important distinction to draw explicitly.

## 7. Tuning applied (and why)

Defaults were changed where they would otherwise distort the comparison:

* `max_data` 64 MB / `max_stream_data` 32 MB — aioquic's 1 MB defaults stall the
  10 MB transfer while it waits for flow-control credit.
* `max_datagram_size` 1452 — the 1200-byte default wastes a standard 1500-byte
  Ethernet MTU and costs extra per-packet Python work.
* `congestion_control_algorithm="cubic"` — the default is Reno.
* Files are preloaded into RAM at server startup, so disk I/O is not inside the
  measured interval.

## 8. Notes

* `h3_client.py` includes its own `quic_connect()` rather than using
  `aioquic.asyncio.connect()`, because the latter always opens a dual-stack
  AF_INET6 socket and fails with `OSError: [Errno 97] Address family not
  supported` on hosts with IPv6 disabled. Ours tries IPv6 and falls back to IPv4.
* Transfers are issued sequentially, one stream at a time, so the per-transfer
  byte deltas are unambiguous.
* Connection setup (control-stream and QPACK-stream bytes) is attributed to
  whichever transfer is in flight when it arrives. Over 1000 transfers this is
  negligible, but it is why run #1 shows a slightly higher ratio.
