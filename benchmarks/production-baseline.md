# Production performance baseline: sluice vs nginx vs caddy

- **Date:** 2026-07-23 (fair re-run, post perf-optimization)
- **sluice:** commit `45045bf` (v0.0.1, `cargo build --release
  --no-default-features --features boringssl`, rustc 1.97.1) — includes the
  static-path optimization (`5b84668`) **and** the per-request perf commit
  (`45045bf`): mimalloc global allocator, metric updates fully skipped when
  `metrics-addr` is unset, prebound metric handles, `access-log-format "off"`,
  hot-path allocation cuts, borrowed-key/insert-time-LRU static cache.
- **Harness:** [`scripts/bench/`](../scripts/bench/) (fully reproducible;
  see its README)
- **Predecessors:** same-day run of the same methodology at commit `421f3a1`
  (pre-perf-commit, referenced below as "before"), and a preliminary run at
  `8b6e759` (pre-static-optimization).

## Measurement note: the earlier proxy number was unfair

The `421f3a1` run reported sluice proxy at ~0.37x nginx. That run had sluice
**access logging ON** (info level, one formatted line per request written to a
log file) and **metrics enabled** (per-request Prometheus label hashing),
while nginx ran `access_log off` and caddy had no access logging — an
apples-to-oranges comparison that depressed the sluice numbers. Profiling
(`perf`) confirmed logging + metric label hashing consumed measurable
per-request CPU.

This run is apples-to-apples: sluice `access-log-format "off"`, **no**
`metrics-addr` (the code now skips all metric updates when metrics are
disabled), `RUST_LOG=error`; nginx and caddy unchanged (logs off, no metrics,
as before). nginx and caddy were re-measured in the same run to control for
box drift. One deliberate change rode along: sluice is now built with
**BoringSSL** (matching the production binary) instead of OpenSSL, so the
before→after delta bundles the perf commit + fair logging/metrics config +
TLS backend swap.

## Verdict (updated)

- **Reverse proxy** (sluice's core role): **~0.5x nginx, ~1.5–1.8x caddy.**
  34.9–42.5k req/s vs nginx's 69–78k (**0.51–0.55x**, up from 0.36–0.38x)
  and caddy's 23–24k (**1.45–1.84x**). Sluice's proxy P99 (11.5 ms at c=200)
  is close to nginx's (9.5 ms) and ~3x better than caddy's (32 ms).
  CPU per request is now ~2.4x nginx (was ~3.7x).
- **Static files (small, hot):** **0.80–0.87x nginx, 2.1–2.4x caddy** — up
  from 0.54–0.60x nginx / 1.5–1.6x caddy. At c=200 sluice's P99 (5.7 ms)
  beats nginx's (7.0 ms), and CPU per request is at rough parity with nginx
  (~1.1x). Small-file serving is no longer a weak spot at all.
- **Static files (large, ≥ content-cache cap):** **0.46–0.54x nginx,
  0.66–0.67x caddy** — files over `CACHE_MAX_FILE` (64 KiB) stream per
  request; still the weakest path (crypto/copy-bound, ~2.3–2.4x nginx's
  CPU per request).
- **Memory:** sluice idle RSS 23 MiB (nginx ~63, caddy ~46) — still the
  lightest idle and in most loaded cells, but mimalloc costs some RSS:
  idle grew from ~17 to ~23 MiB, and in the 100 KiB streaming cell at c=200
  sluice's peak (112 MiB) now matches nginx (110) and exceeds caddy (77).

Zero errors / non-2xx across all 19 cells (~88M requests total);
pass-to-pass stdev ≤ 2.1% of the mean for every sluice cell (worst cell
overall: nginx static 1 KiB c=50 at 6.2%).

## The perf commit, quantified (before → after)

Same box, same day, same methodology. "Before" = `421f3a1` with access
logging on + metrics enabled (OpenSSL build); "after" = `45045bf` with
logging/metrics off (BoringSSL build). The delta therefore includes both the
code optimizations and the removal of the unfair logging/metrics overhead.

| workload | before (`421f3a1`) | after (`45045bf`) | change | vs nginx | vs caddy |
|---|---|---|---|---|---|
| proxy 1 KiB, c=50 | 28,071 req/s | **34,902 req/s** | **+24%** | 0.38x → **0.51x** | 1.15x → **1.45x** |
| proxy 1 KiB, c=200 | 28,916 req/s | **42,488 req/s** | **+47%** | 0.36x → **0.55x** | 1.21x → **1.84x** |
| proxy P50/P99 @ c200 | 6.60 / 14.65 ms | **4.34 / 11.49 ms** | −34% / −22% | — | — |
| static 1 KiB, c=50 | 74,038 req/s | **97,188 req/s** | **+31%** | 0.60x → **0.80x** | 1.60x → **2.06x** |
| static 1 KiB, c=200 | 74,148 req/s | **116,346 req/s** | **+57%** | 0.54x → **0.87x** | 1.51x → **2.43x** |
| static 100 KiB, c=50 | 9,748 req/s | 11,333 req/s | +16% | 0.46x → 0.54x | 0.61x → 0.67x |
| static 100 KiB, c=200 | 9,510 req/s | 11,346 req/s | +19% | 0.43x → 0.46x | 0.59x → 0.66x |
| proxy CPU/req vs nginx | ~3.7x | **~2.4x** | — | — | — |
| static 1 KiB CPU/req vs nginx | ~1.8x | **~1.1x** | — | — | — |
| idle RSS | 17–18 MiB | 23 MiB | +6 MiB (mimalloc) | still 0.37x | still 0.50x |

The proxy path — which the earlier logging/metrics overhead hit hardest and
the perf commit targeted (allocation was ~25% of proxy CPU under glibc
malloc) — gained the most at high concurrency: +47% at c=200, moving sluice
from ~0.37x to ~0.55x nginx. The 100 KiB rows improve only modestly because
those responses bypass the content cache and stream per request.

## Work-stealing experiment (exploratory, non-default)

Profiling had flagged cross-thread scheduling as a structural cost of the
proxy path (~3.6 futex/req, ~5.1k cpu-migrations/5s vs nginx's ~0
shared-nothing model). One c=200 proxy cell was run with the experimental
`server { work-stealing false }` knob (same build, same fair config):

| | work-stealing true (default) | work-stealing false |
|---|---|---|
| req/s | 42,488 | **43,766 (+3.0%)** |
| P50 / P90 / P99 | 4.34 / 7.57 / 11.49 | 4.21 / 7.38 / 11.76 |
| avg CPU% | 458 | **430 (−6%)** |
| peak RSS | 70.8 | 70.4 |

Disabling work stealing bought ~3% throughput at ~6% less CPU (≈9% better
CPU-per-request) with a marginally worse P99. Real but modest — it confirms
the futex/migration diagnosis without closing the gap to nginx. The default
stays `true`.

## Box & versions

| | |
|---|---|
| Host | 96.47.230.148, KVM guest (virtio-net), loopback traffic only |
| OS | Debian 13 (trixie), kernel 6.12.95+deb13-cloud-amd64 |
| CPU | 8 vCPU, Intel Xeon Platinum 8168 @ 2.70 GHz |
| RAM | 32,102 MiB |
| sluice | `45045bf` v0.0.1, release build, rustc 1.97.1, **BoringSSL** TLS |
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
- **Access logs off and metrics off everywhere** (sluice:
  `access-log-format "off"`, no `metrics-addr`, `RUST_LOG=error`; nginx:
  `access_log off`; caddy: no log directive); `keepalive_requests`
  effectively unlimited; all servers at their "all cores" worker default
  (sluice `threads 0`, nginx `worker_processes auto`, caddy default
  GOMAXPROCS — all 8).
- Workloads: static 1 KiB and 100 KiB random files from a docroot;
  reverse proxy of the 1 KiB body from a shared plaintext nginx origin.
- Exact configs and driver: `scripts/bench/`.

## Results (mean of 3×30 s passes)

Latencies in ms; RSS in MiB; CPU% of one core, process-tree total.
Errors/non-2xx: **0 in every cell**.

### Reverse proxy, 1 KiB body

| conc | metric | sluice | nginx | caddy |
|---|---|---|---|---|
| 50 | req/s | 34,902 | 69,097 | 24,001 |
| 50 | P50 / P90 / P99 | 1.23 / 2.39 / 4.70 | 0.62 / 1.15 / 2.74 | 1.35 / 4.76 / 9.38 |
| 50 | peak RSS | 55.6 | 102.5 | 66.0 |
| 50 | avg CPU% | 376 | 317 | 510 |
| 200 | req/s | 42,488 | 77,716 | 23,130 |
| 200 | P50 / P90 / P99 | 4.34 / 7.57 / 11.49 | 2.01 / 5.15 / 9.45 | 6.68 / 18.25 / 32.03 |
| 200 | peak RSS | 70.8 | 109.7 | 87.8 |
| 200 | avg CPU% | 458 | 350 | 529 |

### Static, 1 KiB file (sluice: hot content cache — the default)

| conc | metric | sluice | nginx | caddy |
|---|---|---|---|---|
| 50 | req/s | 97,188 | 121,227 | 47,107 |
| 50 | P50 / P90 / P99 | 0.42 / 0.91 / 1.95 | 0.34 / 0.67 / 1.37 | 0.44 / 2.91 / 7.31 |
| 50 | peak RSS | 43.1 | 101.8 | 66.0 |
| 50 | avg CPU% | 378 | 405 | 582 |
| 200 | req/s | 116,346 | 133,934 | 47,817 |
| 200 | P50 / P90 / P99 | 1.41 / 3.21 / 5.69 | 0.93 / 3.72 / 6.97 | 1.58 / 11.42 / 32.78 |
| 200 | peak RSS | 65.1 | 108.8 | 74.1 |
| 200 | avg CPU% | 436 | 473 | 590 |

### Static, 100 KiB file (> 64 KiB content-cache cap: streamed per request)

| conc | metric | sluice | nginx | caddy |
|---|---|---|---|---|
| 50 | req/s | 11,333 | 20,878 | 16,792 |
| 50 | P50 / P90 / P99 | 4.18 / 6.66 / 9.70 | 2.30 / 3.97 / 6.79 | 2.31 / 6.07 / 10.88 |
| 50 | peak RSS | 84.9 | 103.1 | 66.4 |
| 50 | avg CPU% | 466 | 372 | 462 |
| 200 | req/s | 11,346 | 24,475 | 17,091 |
| 200 | P50 / P90 / P99 | 16.29 / 29.03 / 43.90 | 7.67 / 13.46 / 21.35 | 7.68 / 27.01 / 66.03 |
| 200 | peak RSS | 111.6 | 109.6 | 76.8 |
| 200 | avg CPU% | 466 | 419 | 468 |

### Idle RSS (after startup, before load)

| | sluice | nginx | caddy |
|---|---|---|---|
| static config | 23.2 | 62.5 | 45.8 |
| proxy config | 23.4 | 63.1 | 46.9 |

## Key ratios

| workload | sluice vs nginx req/s | sluice vs caddy req/s | sluice vs nginx peak RSS | CPU/req vs nginx |
|---|---|---|---|---|
| proxy 1 KiB | 0.51–0.55x | 1.45–1.84x | 0.54–0.65x | ~2.4x more |
| static 1 KiB (hot) | 0.80–0.87x | 2.06–2.43x | 0.42–0.60x | ~1.1x (parity) |
| static 100 KiB | 0.46–0.54x | 0.66–0.67x | 0.82–1.02x | ~2.3–2.4x more |

## Confounders & caveats

- **Single box:** oha, the server under test, and (for proxy) the origin
  share 8 cores; the box saturates during runs. Absolute numbers are
  depressed and the fastest server is partly client-starved. Treat
  everything as a *relative* comparison under identical contention; use a
  second load-gen box for capacity numbers.
- **The before→after delta is not purely the perf commit:** it bundles
  (a) the code optimizations, (b) turning off sluice's access logging and
  metrics — overhead nginx/caddy never paid in the "before" run — and
  (c) the OpenSSL→BoringSSL build switch. A separate profiling run at the
  old commit with logging suppressed (but metrics still on, different
  origin) measured proxy at ~26–29k req/s, suggesting the code
  optimizations, not just the config fairness, account for most of the
  proxy gain.
- nginx and caddy were re-measured in this run; their numbers moved a few
  percent vs the earlier same-day run (e.g. nginx proxy c=50: 73.2k → 69.1k)
  — normal box variance, which is why all comparisons use same-run numbers.
- KVM guest, loopback only (no NIC); virtio-net not in the data path.
- TLS stacks differ by design: sluice uses BoringSSL (matching production),
  nginx OpenSSL, caddy Go crypto/tls, the client rustls. TLS 1.3, ECDSA
  P-256 everywhere.
- All servers ran as root (uniform privileges; sluice via
  `SLUICE_ALLOW_ROOT=1`, nginx `user root;`).
- The sluice static numbers are the **hot-cache path** (default config,
  1 s TTL). A cache-miss-heavy workload would sit between this and the
  100 KiB rows, which are a proxy for the fully uncached path.
- mimalloc trades some RSS for speed: idle +~6 MiB, and the 100 KiB
  streaming cell at c=200 is the one load cell where sluice's peak RSS
  (112 MiB) is no longer the lowest of the three.
- A production sluice instance listened on :80/:443 throughout but was idle.

## Bottom line

With the measurement made fair (logs/metrics off for everyone) and the
per-request perf work in, sluice's proxy path is **~0.55x nginx and ~1.8x
caddy** at c=200 — up from the (unfairly measured) 0.37x nginx — with
near-nginx tail latency and ~2.4x nginx's CPU per request (down from ~3.7x).
Small-file static serving is now effectively at nginx's level for CPU/req
(0.80–0.87x throughput, better P99 at c=200) and >2x caddy. The remaining
gaps to nginx: proxy throughput (structural futex/scheduling cost — the
`work-stealing false` experiment recovered ~9% CPU/req, confirming the
diagnosis but not closing the gap), and large-file streaming (0.46–0.54x,
crypto/copy-bound). Memory stays sluice's strength at idle and in most
cells, with the noted mimalloc caveat on the streaming path.
