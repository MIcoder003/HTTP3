#!/usr/bin/env bash
# One-time setup for the HTTP/3 benchmark. Run once on EACH computer.
#
#   bash setup.sh A      # on computer 1 -> creates files/A_*
#   bash setup.sh B      # on computer 2 -> creates files/B_*
#
# Creates: the TLS cert/key the QUIC server needs, and the four test files.

set -euo pipefail

PREFIX="${1:-}"
if [[ "$PREFIX" != "A" && "$PREFIX" != "B" ]]; then
    echo "usage: bash setup.sh <A|B>"
    echo "  A = this machine serves the A_* files (computer 1)"
    echo "  B = this machine serves the B_* files (computer 2)"
    exit 1
fi

cd "$(dirname "$0")"

echo "==> installing aioquic"
python3 -m pip install --quiet --upgrade "aioquic>=1.3.0"
python3 -c "import aioquic; print('    aioquic', aioquic.__version__)"

if [[ -f cert.pem && -f key.pem ]]; then
    echo "==> cert.pem / key.pem already exist, keeping them"
else
    echo "==> generating self-signed TLS certificate (QUIC requires TLS 1.3)"
    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout key.pem -out cert.pem -days 365 -subj "/CN=h3bench" 2>/dev/null
    chmod 600 key.pem
    echo "    wrote cert.pem and key.pem"
fi

echo "==> creating test files with prefix ${PREFIX}"
mkdir -p files
python3 - "$PREFIX" <<'PY'
import os, sys
prefix = sys.argv[1]
# Random bytes: incompressible and uncacheable, so the measurement reflects
# the transfer itself. Replace with your own files if the assignment requires
# specific content -- only the sizes matter.
for name, size in (("10kB", 10_000), ("100kB", 100_000),
                   ("1MB", 1_000_000), ("10MB", 10_000_000)):
    path = os.path.join("files", f"{prefix}_{name}")
    if os.path.exists(path) and os.path.getsize(path) == size:
        print(f"    {path} already correct, skipping")
        continue
    with open(path, "wb") as f:
        f.write(os.urandom(size))
    print(f"    wrote {path} ({size:,} bytes)")
PY

echo
echo "Setup complete. Next:"
echo "  1. start the server:  python3 h3_server.py --dir ./files --cert cert.pem --key key.pem"
echo "  2. find your IP:      hostname -I   (Linux)  /  ipconfig getifaddr en0  (macOS)"
echo "  3. open UDP port 4433 in your firewall"
echo "  4. on the OTHER machine, run the client pointed at this one's IP"