#!/usr/bin/env bash
# One-time setup for the HTTP/3 benchmark. Run once on EACH computer.
#
#   bash setup.sh                 # install aioquic + generate the TLS cert
#   bash setup.sh --test-files A  # also generate random A_* stand-in files
#   bash setup.sh --test-files B  # also generate random B_* stand-in files
#
# For the REAL runs use the eight files supplied with the assignment:
#   computer 1 (server): put A_10kB A_100kB A_1MB A_10MB in ./files
#   computer 2 (client): put B_10kB B_100kB B_1MB B_10MB in ./files
# --test-files is only for trying the code out before you have them.

set -euo pipefail
cd "$(dirname "$0")"

GEN_PREFIX=""
if [[ "${1:-}" == "--test-files" ]]; then
    GEN_PREFIX="${2:-}"
    if [[ "$GEN_PREFIX" != "A" && "$GEN_PREFIX" != "B" ]]; then
        echo "usage: bash setup.sh --test-files <A|B>"
        exit 1
    fi
fi

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

mkdir -p files

if [[ -n "$GEN_PREFIX" ]]; then
    echo "==> generating RANDOM TEST files with prefix ${GEN_PREFIX}"
    echo "    (for trying the code out -- use the assignment's files for real runs)"
    python3 - "$GEN_PREFIX" <<'PY'
import os, sys
prefix = sys.argv[1]
for name, size in (("10kB", 10_000), ("100kB", 100_000),
                   ("1MB", 1_000_000), ("10MB", 10_000_000)):
    path = os.path.join("files", f"{prefix}_{name}")
    with open(path, "wb") as f:
        f.write(os.urandom(size))
    print(f"    wrote {path} ({size:,} bytes)")
PY
else
    echo "==> no files generated. Put the assignment's files in ./files :"
    echo "    computer 1 (server): A_10kB A_100kB A_1MB A_10MB"
    echo "    computer 2 (client): B_10kB B_100kB B_1MB B_10MB"
fi

echo
echo "Current contents of ./files :"
ls -l files/ 2>/dev/null | tail -n +2 || echo "    (empty)"