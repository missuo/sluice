#!/usr/bin/env bash
# End-to-end load test → P50/P90/P99 latency + throughput.
#
# The `cargo bench` micro-benchmarks (benches/hot.rs) cover the CPU-bound hot
# path only. This drives a REAL running proxy with a load generator so you get
# the numbers a micro-bench can't: connection handling, TLS, the async runtime,
# tail latency under concurrency.
#
# Requires `oha` (https://github.com/hatoo/oha) — `cargo install oha` or
# `brew install oha`. Point it at a running sluice instance.
#
#   ./scripts/loadtest.sh https://cache.test:8443/ 50 30s
#
# args: URL [concurrency=50] [duration=20s].  Add --insecure via OHA_EXTRA for
# a self-signed origin:  OHA_EXTRA=--insecure ./scripts/loadtest.sh https://…
set -euo pipefail

URL="${1:?usage: loadtest.sh URL [concurrency] [duration]}"
CONCURRENCY="${2:-50}"
DURATION="${3:-20s}"

if ! command -v oha >/dev/null 2>&1; then
  echo "error: 'oha' not found. Install with: cargo install oha" >&2
  exit 1
fi

echo "load test: $URL  (c=$CONCURRENCY, t=$DURATION)"
# oha prints a latency distribution (incl. p50/p90/p99) and requests/sec.
# shellcheck disable=SC2086
exec oha -c "$CONCURRENCY" -z "$DURATION" --latency-correction --disable-keepalive ${OHA_EXTRA:-} "$URL"
