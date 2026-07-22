# Production performance baseline: sluice vs nginx vs caddy

- **Date:** 2026-07-23
- **sluice:** commit `421f3a1` (v0.0.1, `cargo build --release`, rustc 1.97.1) —
  includes the static-path optimization from `5b84668` (fused
  open+fstat+read as one blocking job + bounded per-docroot content cache
  with singleflight, `staticfiles.rs`)
- **Harness:** [`scripts/bench/`](../scripts/bench/) (fully reproducible;
  see its README)
- **Predecessor:** a preliminary run of the same methodology at commit
  `8b6e759` (pre-optimization), referenced below as "before".

## Verdict

- **Reverse proxy** (sluice's core role): **competitive with caddy, much
  slower than nginx.** ~28–29k req/s vs caddy's ~24k (**1.15–1.21x caddy**,
  with less than half caddy's P99 tail) and vs nginx's 73–81k
  (**0.36–0.38x nginx**, ~3.7x the CPU per request).
- **Static files (small, hot):** after the optimization sluice is now
  **1.5–1.6x caddy** and **0.54–0.60x nginx** — up from **0.31x caddy /
  0.12x nginx** before. Tail latency is at nginx's level (P99 6.4 ms vs
  6.8 ms at c=200; caddy 32.8 ms).
- **Static files (large, ≥ content-cache cap):** **0.43–0.46x nginx,
  0.59–0.61x caddy** — files over `CACHE_MAX_FILE` (64 KiB) stream per
  request and only got the fused-read speedup (+18–21%).
- **Memory: sluice is the lightest of the three by a wide margin.** Idle
  17–18 MiB (nginx ~63, caddy ~46); peak under any tested load 29–76 MiB
  (nginx 101–110, caddy 65–89).
- **CPU efficiency:** static 1 KiB now costs sluice ~1.8x nginx's CPU per
  request (was ~8x) and ~0.5x caddy's. Proxying still costs ~3.7x nginx
  per request (unchanged — the optimization targeted the static path).

Zero errors / non-2xx across all 18 cells (~77M requests total);
pass-to-pass stdev ≤ ~3% of the mean everywhere.

## The static optimization, quantified

Same box, same methodology, hot-cache path (repeated GETs of the same file —
the realistic static steady state; the file-server content cache is on by
default with `cache-ttl-secs 1`):

| workload | before (`8b6e759`) | after (`421f3a1`) | change | vs nginx | vs caddy |
|---|---|---|---|---|---|
| static 1 KiB, c=50 | 15,484 req/s | **74,038 req/s** | **4.8x** | 0.13x → **0.60x** | 0.33x → **1.60x** |
| static 1 KiB, c=200 | 15,093 req/s | **74,148 req/s** | **4.9x** | 0.11x → **0.54x** | 0.31x → **1.51x** |
| static 1 KiB P50/P99 @ c200 | 12.8 / 25.0 ms | **2.6 / 6.4 ms** | ~4–5x lower | ≈ nginx P99 | ≪ caddy P99 |
| static 100 KiB, c=50 | 8,272 req/s | 9,748 req/s | 1.18x | 0.40x → 0.46x | 0.53x → 0.61x |
| static 100 KiB, c=200 | 7,884 req/s | 9,510 req/s | 1.21x | 0.36x → 0.43x | 0.50x → 0.59x |

The before-run's anomaly — sluice serving static files at half its own
proxy throughput — is gone: the static path (74k) is now ~2.6x the proxy
path (29k), as it should be. The 100 KiB rows improve only modestly because
100 KiB > `CACHE_MAX_FILE` (64 KiB), so those responses bypass the content
cache and stream per request; at ~1 GiB/s of TLS payload they are
crypto/copy-bound.

## Box & versions

| | |
|---|---|
| Host | 96.47.230.148, KVM guest (virtio-net), loopback traffic only |
| OS | Debian 13 (trixie), kernel 6.12.95+deb13-cloud-amd64 |
| CPU | 8 vCPU, Intel Xeon Platinum 8168 @ 2.70 GHz |
| RAM | 32,102 MiB |
| sluice | `421f3a1` v0.0.1, release build, rustc 1.97.1, OpenSSL TLS |
| nginx | 1.26.3 (Debian package) |
| caddy | v2.11.4 (official static binary) |
| load gen | oha 1.15.0 (rustls client) |
| origin | nginx 1.26.3, separate instance, 4 workers, plaintext :18000 |

## Methodology

HTTPS/1.1 + keepalive with the same self-signed ECDSA P-256 cert for all
three servers, HTTP/2 disabled everywhere. (Plaintext HTTP is not an option:
sluice listeners are TLS-or-redirect by design. With keepalive the handshake
amortizes away and every server pays identical per-request crypto.)

- One server under test at a time, started fresh per phase, SIGKILLed after
  (SIGTERM would leave a gracefully-draining instance sharing the port via
  SO_REUSEPORT and split the next phase's traffic).
- Per cell: 1×10 s warmup (discarded; also warms sluice's file-server
  content cache) + 3×30 s measured passes of
  `oha -z 30s -c {50,200} --insecure`, table cells = mean of 3 passes.
- Peak RSS and average CPU% (of one core; 800% = box saturated) sampled at
  1 Hz from `/proc/<pid>/stat` over the server process **and its children**
  (nginx master + 8 workers). Idle RSS taken ~3 s after startup.
- Access logs off everywhere; `keepalive_requests` effectively unlimited;
  all servers at their "all cores" worker default (sluice `threads 0`,
  nginx `worker_processes auto`, caddy default GOMAXPROCS — all 8).
- Workloads: static 1 KiB and 100 KiB random files from a docroot;
  reverse proxy of the 1 KiB body from a shared plaintext nginx origin.
- Exact configs and driver: `scripts/bench/`.

## Results (mean of 3×30 s passes)

Latencies in ms; RSS in MiB; CPU% of one core, process-tree total.
Errors/non-2xx: **0 in every cell**.

### Reverse proxy, 1 KiB body

| conc | metric | sluice | nginx | caddy |
|---|---|---|---|---|
| 50 | req/s | 28,071 | 73,198 | 24,366 |
| 50 | P50 / P90 / P99 | 1.69 / 2.51 / 3.79 | 0.58 / 1.08 / 2.54 | 1.33 / 4.69 / 9.23 |
| 50 | peak RSS | 42.0 | 101.7 | 65.4 |
| 50 | avg CPU% | 462 | 318 | 516 |
| 200 | req/s | 28,916 | 80,566 | 23,884 |
| 200 | P50 / P90 / P99 | 6.60 / 10.43 / 14.65 | 1.83 / 5.21 / 9.71 | 6.43 / 17.72 / 31.48 |
| 200 | peak RSS | 67.2 | 109.5 | 89.2 |
| 200 | avg CPU% | 464 | 349 | 534 |

### Static, 1 KiB file (sluice: hot content cache — the default)

| conc | metric | sluice | nginx | caddy |
|---|---|---|---|---|
| 50 | req/s | 74,038 | 123,535 | 46,143 |
| 50 | P50 / P90 / P99 | 0.63 / 1.04 / 1.66 | 0.38 / 0.64 / 1.43 | 0.43 / 3.01 / 7.80 |
| 50 | peak RSS | 28.8 | 101.0 | 68.3 |
| 50 | avg CPU% | 475 | 412 | 586 |
| 200 | req/s | 74,148 | 137,478 | 48,954 |
| 200 | P50 / P90 / P99 | 2.57 / 4.26 / 6.43 | 0.90 / 3.63 / 6.78 | 1.46 / 11.27 / 32.83 |
| 200 | peak RSS | 63.7 | 108.2 | 74.0 |
| 200 | avg CPU% | 473 | 475 | 594 |

### Static, 100 KiB file (> 64 KiB content-cache cap: streamed per request)

| conc | metric | sluice | nginx | caddy |
|---|---|---|---|---|
| 50 | req/s | 9,748 | 21,359 | 16,010 |
| 50 | P50 / P90 / P99 | 4.89 / 7.71 / 11.17 | 1.98 / 4.19 / 7.22 | 2.56 / 6.12 / 10.73 |
| 50 | peak RSS | 39.7 | 102.0 | 67.4 |
| 50 | avg CPU% | 467 | 368 | 428 |
| 200 | req/s | 9,510 | 21,955 | 16,105 |
| 200 | P50 / P90 / P99 | 19.56 / 34.16 / 51.40 | 8.36 / 15.13 / 23.75 | 8.30 / 28.21 / 65.52 |
| 200 | peak RSS | 75.5 | 108.4 | 77.9 |
| 200 | avg CPU% | 465 | 383 | 431 |

### Idle RSS (after startup, before load)

| | sluice | nginx | caddy |
|---|---|---|---|
| static config | 17.1 | 62.3 | 45.9 |
| proxy config | 17.9 | 62.9 | 46.6 |

## Key ratios

| workload | sluice vs nginx req/s | sluice vs caddy req/s | sluice vs nginx peak RSS | CPU/req vs nginx |
|---|---|---|---|---|
| proxy 1 KiB | 0.36–0.38x | 1.15–1.21x | 0.41–0.61x | ~3.7x more |
| static 1 KiB (hot) | 0.54–0.60x | 1.51–1.60x | 0.29–0.59x | ~1.8x more |
| static 100 KiB | 0.43–0.46x | 0.59–0.61x | 0.39–0.70x | ~2.9x more |

## Confounders & caveats

- **Single box:** oha, the server under test, and (for proxy) the origin
  share 8 cores; the box saturates during runs. Absolute numbers are
  depressed and the fastest server is partly client-starved (nginx plateaus
  at ~475% CPU while serving 1.9–4.8x sluice's rate). Treat everything as a
  *relative* comparison under identical contention; use a second load-gen
  box for capacity numbers.
- KVM guest, loopback only (no NIC); virtio-net not in the data path.
- TLS stacks differ by design: sluice and nginx use OpenSSL, caddy uses Go
  crypto/tls, the client is rustls. TLS 1.3, ECDSA P-256 everywhere.
- All servers ran as root (uniform privileges; sluice via
  `SLUICE_ALLOW_ROOT=1`, nginx `user root;`).
- The sluice static numbers are the **hot-cache path** (default config,
  1 s TTL): every measured request after warmup is served from the content
  cache with at most ~1 revalidating re-open per file per second. A
  cache-miss-heavy workload (huge file corpus, cold spots) would sit between
  this and the pre-optimization numbers; the 100 KiB rows are a proxy for
  the fully uncached path.
- A production sluice instance listened on :80/:443 throughout but was idle.

## Bottom line

The static optimization did what it set out to do: sluice went from "static
serving is the weak spot" (0.12x nginx, 0.31x caddy, slower than its own
proxy path) to **beating caddy by ~1.5x with nginx-level tail latency**, at
about half of nginx's small-file throughput on this box. As a reverse proxy
sluice remains ~1.2x caddy and ~0.37x nginx in raw req/s, and it stays the
lightest on memory in every cell. Remaining gaps to nginx: proxy CPU per
request (~3.7x) and large-file streaming (~0.45x) — the next candidates if
further throughput work is wanted.
