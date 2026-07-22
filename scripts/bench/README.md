# Benchmark harness: sluice vs nginx vs caddy

Reproducible single-box benchmark comparing sluice, nginx, and caddy on
HTTPS/1.1 with keepalive: static file serving (1 KiB and 100 KiB) and reverse
proxying (1 KiB via a shared plaintext nginx origin). Produced the numbers in
[`benchmarks/production-baseline.md`](../../benchmarks/production-baseline.md).

Everything runs on **127.0.0.1 on high ports** (18000 origin, 18081 sluice,
18083 nginx, 18085 caddy, 19090 sluice metrics), so it can run on a box that
already serves production traffic on :80/:443 without touching it.

## Why HTTPS and not plaintext

sluice listeners are TLS-or-redirect only (no plaintext serving mode), so the
apples-to-apples comparison runs all three servers over HTTPS/1.1 with the
same self-signed ECDSA P-256 cert, HTTP/2 disabled everywhere, keepalive on
(handshakes amortize away; every server pays the same per-request crypto).

## Prerequisites

- Linux with `python3`, `openssl`, `git`, and ~4 GiB free disk (build).
- `nginx` (`apt-get install nginx`; the harness never uses the system
  service — it runs nginx with its own configs/pidfiles).
- A `caddy` static binary and the `oha` load generator
  (github.com/caddyserver/caddy, github.com/hatoo/oha releases).
- A release build of sluice: `cargo build --release`.

## Running

```sh
# 1. Working tree, test files, self-signed cert, harness copy:
BENCH_DIR=/srv/bench scripts/bench/setup.sh

# 2. Full matrix (~35 min: 3 servers x {static 1k, static 100k, proxy 1k}
#    x c={50,200} x (1x10s warmup + 3x30s measured)):
BENCH_DIR=/srv/bench \
SLUICE_BIN=target/release/sluice \
CADDY_BIN=/path/to/caddy \
OHA_BIN=/path/to/oha \
  /srv/bench/run_all.sh | tee /srv/bench/run_all.log

# 3. Aggregate (mean req/s + latency percentiles over the 3 passes, peak RSS,
#    avg CPU%, error counts) as JSON:
python3 /srv/bench/parse.py /srv/bench/results
```

Run as root only on a throwaway/lab box (`SLUICE_ALLOW_ROOT=1` is set by
`run_all.sh`; the nginx configs pin `user root;` so all three servers run
with identical privileges). On a shared box create a bench user instead and
drop `user root;`.

## What it measures

Per (server × workload × concurrency) cell:

- `oha -z 30s -c {50,200} --insecure` — req/s, latency percentiles, status
  and error distributions ("aborted due to deadline" is oha cutting
  in-flight requests at the 30 s mark, not an error).
- `sampler.py` — peak RSS (MiB) and average CPU% (of one core; can exceed
  100) summed over the server process **and its children** (nginx master +
  workers), sampled at 1 Hz from `/proc/<pid>/stat` during each pass.
- Idle RSS is recorded ~3 s after each server starts, before any load.

Methodology guards baked in:

- One server under test at a time, started fresh per phase.
- Phases end with SIGKILL: a SIGTERM'd sluice/caddy lingers draining
  gracefully and (via SO_REUSEPORT) would silently split the next phase's
  traffic with the stale instance.
- Warmup pass discarded; for sluice static this also warms the file-server
  content cache (default `cache-ttl-secs 1`), so the measured passes are the
  hot-cache path — the realistic steady state for repeated static GETs.
- Access logs off everywhere; `keepalive_requests` effectively unlimited;
  worker/thread counts at each server's "use all cores" default.

## Files

- `configs/` — minimal, comparable server configs (sluice KDL, nginx, Caddy,
  shared origin). Docroot/cert paths assume `BENCH_DIR=/srv/bench`; edit the
  configs if you relocate it.
- `setup.sh` — creates the tree, 1 KiB / 100 KiB random test files, and cert.
- `run_all.sh` — the 6-phase matrix driver.
- `bench_one.sh` — one (label, url, concurrency) cell: warmup + 3 passes +
  sampler.
- `sampler.py` — /proc-based RSS + CPU sampler (process tree aware).
- `parse.py` — aggregates results into a single JSON summary.

## Caveats

Load generator, server under test, and origin share the box's cores, so
absolute numbers are depressed and the fastest server is partly
client-starved; treat results as *relative* comparisons under identical
contention, not capacity numbers. Use two boxes (oha on the second) for
absolute throughput ceilings.
