#!/bin/bash
# One-time setup for the bench box: creates the working tree under BENCH_DIR
# (default /srv/bench), the test files, and a self-signed ECDSA P-256 cert for
# 127.0.0.1, and copies the harness + configs there.
# Prerequisites (install however you like): nginx, python3, openssl, oha, a
# caddy binary, and a release build of sluice. See README.md.
set -euo pipefail
BENCH_DIR=${BENCH_DIR:-/srv/bench}
HERE=$(cd "$(dirname "$0")" && pwd)

mkdir -p "$BENCH_DIR"/{www,origin,run,log,results}
cp "$HERE"/configs/* "$HERE"/sampler.py "$HERE"/bench_one.sh "$HERE"/run_all.sh "$HERE"/parse.py "$BENCH_DIR"/
chmod +x "$BENCH_DIR"/bench_one.sh "$BENCH_DIR"/run_all.sh

head -c 1024   /dev/urandom > "$BENCH_DIR/www/1k.bin"
head -c 102400 /dev/urandom > "$BENCH_DIR/www/100k.bin"
cp "$BENCH_DIR/www/1k.bin" "$BENCH_DIR/origin/1k.bin"
chmod -R a+rX "$BENCH_DIR/www" "$BENCH_DIR/origin"

openssl ecparam -name prime256v1 -genkey -noout -out "$BENCH_DIR/key.pem"
openssl req -x509 -key "$BENCH_DIR/key.pem" -out "$BENCH_DIR/cert.pem" -days 30 \
    -subj "/CN=127.0.0.1" -addext "subjectAltName=IP:127.0.0.1" 2>/dev/null

echo "setup done in $BENCH_DIR"
