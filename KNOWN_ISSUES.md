# Known Issues & Limitations

This document tracks issues that are **known but not resolved**, with the reason
each one is still open. It is the honest counterpart to the "DONE" list in
[DESIGN.md](DESIGN.md): if a reviewer or user hits one of these, the answer is
here rather than a surprise.

Two categories:

1. **Blocked upstream** — cannot be fixed inside Sluice; the limitation lives in
   Pingora or a dependency.
2. **Deliberately not built** — technically possible, but intentionally deferred
   because the cost isn't justified for the current deployment. Each says what it
   would take to change that.

---

## 1. Blocked upstream (cannot fix in Sluice)

### 1.1 HTTP/3 (QUIC) is not supported
- **Why:** Pingora 0.8 has no QUIC transport. There is no server-side HTTP/3
  listener in the framework to bind, so there is nothing for Sluice to configure.
- **What it would take:** upstream QUIC support in Pingora (a substantial
  contribution to `pingora-core`/`pingora-proxy`), or a second server stack (e.g.
  `quinn` + `h3`) running alongside Pingora and sharing the config/cert stores —
  effectively a second proxy. Out of scope until Pingora ships QUIC.
- **Mitigation:** HTTP/2 is fully supported (`listener { http2 true }`). Behind
  Cloudflare — the real deployment — the CDN edge already terminates HTTP/3 for
  browsers and speaks HTTP/1.1–2 to the origin, so origin H3 buys nothing there.

### 1.2 Rustls TLS backend is unusable
- **Why:** Pingora's Rustls integration does **not** expose a TLS certificate
  callback. Dynamic SNI cert selection (`cert-dir`) and ACME both require choosing
  a certificate *at handshake time* based on the SNI name; without the callback
  that is impossible.
- **What it would take:** upstream work in Pingora to expose a cert-resolver hook
  on the Rustls path (OpenSSL/BoringSSL already have `TlsAccept`).
- **Mitigation:** OpenSSL (the default) and BoringSSL both work and are what we
  ship. Do **not** try to "enable" the Rustls feature — it will not select certs.

### 1.3 ACME renewal is mtime-based, not `notAfter`-based
- **Why:** the renewal loop decides "is this cert old enough to re-issue?" from
  the certificate **file's mtime** (older than 60 days → renew), not by parsing
  the X.509 `notAfter` field. Reading `notAfter` needs ASN.1 access, and Pingora's
  TLS facade does **not re-export** the `asn1` types from the underlying
  OpenSSL/BoringSSL crate, so the cert's real expiry can't be read through the
  dependency surface we have.
- **Impact:** low. Let's Encrypt certs are valid 90 days; renewing at file-age 60
  days leaves a 30-day margin. The only gap is a cert **replaced out-of-band**
  (its mtime resets) — harmless, it just renews on our schedule instead of the
  cert's.
- **What it would take:** Pingora re-exporting `asn1`/`X509` accessors, or adding a
  direct dependency on `openssl`/`x509-parser` purely to read `notAfter`. Deferred
  as not worth a second X.509 stack for a 30-day-margin refinement.

---

## 2. Deliberately not built (cost not justified yet)

### 2.1 `balance ip-hash` ignores server weights
- **What:** `ip-hash` maps a client to a backend by `hash(client_ip) % N`, giving
  every backend an equal share regardless of its `weight=`.
- **Why not fixed:** this is a **design split**, not a bug. `ip-hash` is the simple,
  zero-state modulo variant; **`balance ketama`** is the weighted *and*
  consistent-hash variant (`160 * weight` ring points per backend) and is the
  correct choice when weights or stable-on-membership-change matter. Making
  `ip-hash` weighted would just duplicate Ketama with worse remap behaviour.
- **Guidance:** if you need weighted hashing, use `balance ketama`. This is
  documented in `config.rs` (the `Balance` enum) and README.

### 2.2 Disk-cache reaper does a full directory scan **and sort**
- **What:** the disk cache's background reaper (every 30 s) walks the whole cache
  directory and, when it needs to evict, **sorts** the entries by mtime — so a
  cycle is O(files) to stat plus O(n log n) to sort, not just O(files).
- **Why not fixed:** for the expected cache size this is negligible and is how
  simple on-disk caches (and nginx's cache manager) work. An incremental index
  (in-memory LRU of on-disk entries) would avoid both the scan and the sort but
  adds a crash-consistency problem (index vs. disk divergence after an unclean
  exit) that the stateless scan sidesteps. Not worth the complexity until a large
  cache makes it a *measured* problem.
- **Honest caveat:** "acceptable" here is a design judgement, **not backed by a
  benchmark** at the default million-file ceiling. If you run a very large disk
  cache, measure the reaper cycle time before relying on it.
- **Mitigation:** keep `cache-store { max-files }` reasonable; the cost scales
  with it.

### 2.3 Config file-watch / `cert-dir` hot-reload
- **What:** config reload is **SIGHUP-triggered**, not automatic on file change.
  A `cert-dir` store is built **once at process startup** and is **not re-read on
  SIGHUP** — only the ACME renewal loop hot-swaps certs into the in-memory store.
  So rotating a file in a `cert-dir` requires a **process restart** (a SIGHUP will
  reload routing/other config but will **not** pick up new/rotated cert files).
- **Why not fixed:** SIGHUP is explicit and predictable; a file-watcher adds a
  dependency and races (partial writes).
- **What it would take:** rebuild the `CertStore` inside the SIGHUP reload path
  (and/or a debounced `notify` watcher) feeding the same `ArcSwap`. Small, just
  not yet prioritised.

### 2.4 Full Lua/Rhai scripting / WAF programmability
- **What:** the WAF is **declarative** (`waf { block field=… match=… }` over
  path/query/method/header) — there is no embedded scripting language for
  arbitrary request logic.
- **Why not fixed:** an embedded scripting VM is a large security and performance
  surface (sandbox escapes, per-request allocation, unbounded CPU). For an
  edge proxy whose #1 goal is "no vulnerabilities", a constrained declarative
  matcher is the safer default.
- **What it would take:** a sandboxed, resource-limited engine (Rhai) or a
  compiled-in Rust plugin seam. If pursued, prefer the compiled plugin seam or a
  constrained routing-expression grammar over a general scripting language.

---

## 3. Behavioural notes & smaller known gaps

These are correct-and-intentional behaviours worth writing down (a reviewer or
operator could reasonably expect otherwise), plus small gaps not yet closed.

- **Over-limit chunked body → abort, not a clean 413.** A request whose declared
  `Content-Length` exceeds `max-body` gets a proper `413`. A **chunked / no-
  Content-Length** body that crosses the limit mid-stream is terminated with a
  proxy error (connection reset / 5xx-class) once the cap is passed — the bytes
  are capped either way (no evasion), but a streaming over-limit upload does not
  receive a tidy `413` response.
- **HTTPS upstreams get connect-level health only.** An active `health-check`
  with a `path` performs an HTTP `GET` for **plaintext** backends; for a **TLS**
  (`https://…`) upstream it falls back to a **TCP-connect** check (no TLS
  handshake, no HTTP status assertion). A TLS backend that accepts connections
  but returns errors won't be marked down by the path check.
- **Static-file serving does not follow symlinks under the root.** The file is
  opened race-free by descending from the docroot one component at a time with
  `openat`/`O_NOFOLLOW` (no `canonicalize`→`open` TOCTOU that a writable docroot
  could exploit), and the `Content-Length` is taken by `fstat` on the very fd
  that streams the bytes (length and body can't disagree). The trade-off is
  nginx-`disable_symlinks` semantics: a symlink anywhere **under** the root is
  not served (the docroot itself may be a symlink — it's admin-controlled). Per
  request this is a few `openat` syscalls rather than two `canonicalize` calls.
- **Disk cache: one file per entry, published by a single atomic rename.** Meta
  (prefix + serialized headers) and body live in the SAME `.ent` file, written
  to a fsync'd temp and installed with one `rename` — a crash at any point
  leaves the previous complete entry or nothing, so "old meta + new body" is
  structurally impossible (the earlier two-file layout could produce exactly
  that if it crashed between its two renames with an equal-length body; a
  review caught the then-overstated claim). A file whose length doesn't match
  its stamped sizes is treated as a miss. The reaper walks the tree via the
  pinned root fd and only ever acts on files matching the cache's EXACT naming
  (`<32hex>.ent`, a strictly-numeric `.tmp.<pid>.<seq>.<nanos>`, legacy
  `<32hex>.meta`/`.body`) — a user's stray `keep.txt` or `.tmp.notes` is never
  counted or deleted.
- **Response cache is namespaced by a per-site config epoch.** The cache key
  includes a versioned (`v2`) fingerprint of the site's content-affecting config:
  location matchers, upstream host/port/TLS/SNI/**verify**/Host-rewrite, file
  roots, websocket/read-timeout, and sub-filters. A reload/restart/upgrade that
  changes ANY of these (e.g. flipping `upstream-verify` false→true — a review
  gap that previously kept serving unverified content) gets a fresh namespace
  and can never serve the OLD config's cached bodies; identical config keeps the
  namespace, so the persistent disk cache still survives a plain restart. The
  fingerprint also covers the cache **policy** (TTL, max-object), so a reload
  that changes the TTL doesn't keep serving entries bound by the old policy. Bump
  the `v2` tag whenever the fingerprint format changes.
- **Dynamic-SNI cert lookup is case-insensitive.** Certs are keyed (and looked
  up) by the lowercased SNI, since DNS hostnames are case-insensitive and a
  client may send any case — so `B.TEST` resolves to `b.test`'s cert rather than
  falling back to the wrong one.
- **Private dirs (ACME store, disk cache) are pinned by fd, from the root down.**
  `dirs::SecureDir::provision` walks the path from a trusted anchor (`/` or the
  CWD) creating/opening ONE component at a time with `O_NOFOLLOW` at EVERY level
  (not just the last), then holds the final directory by fd; all later IO is
  `openat`/`mkdirat`/`renameat`/`unlinkat`-relative. So a low-priv user who
  controls a PARENT directory can't reroute provisioning (or any later write) by
  swapping a component for a symlink between `--check` and startup — the open
  fails. A symlink component is followed ONLY if the link is owned by root or by
  us (so system symlinks like macOS `/var` still work; an attacker's link is
  refused). The final dir must be owned by us and is locked to 0700 on its fd.
  Provisioning (which mutates) happens only at startup and is FATAL on failure —
  a bad `cache-store`/ACME dir fails the process, never a silent downgrade to
  in-memory. `--check` runs a read-only `validate` that never creates or chmods
  and fails on any real error (a non-`NotFound` stat error is no longer treated
  as "doesn't exist yet").
- **A cache LOOKUP never creates directories.** Only a miss that actually caches
  (the write path) creates the two shard dirs; a lookup/purge uses a no-create
  open, so an attacker varying the URL can't mint unbounded empty directories.
  The reaper reclaims empty shard dirs every cycle regardless.
- **Rate-limit table is hard-capped with a per-host overflow bucket.** Buckets
  are keyed by (host, client) with IPv6 collapsed to its /64; the per-client
  table is capped at 256k. When full, a NEW client is throttled against a single
  shared **per-host** bucket instead of getting its own entry — memory stays
  bounded (one overflow bucket per configured host) AND rotating clients are
  still limited (collectively), not fail-open. A one-shot warning is logged. It
  is still not a general high-cardinality DDoS limiter (no global request
  ceiling / eviction of the 256k live buckets); a determined flood degrades
  legitimate new clients to the shared bucket's rate.
- **Access log is a fixed line format (no JSON).** The access log emits a fixed
  field layout; there is no `json` access-log mode yet. Tracked as a "still
  later" item in DESIGN.
- **`alias` (migration host aliasing) was removed.** It canonicalized
  `<prefix>-<sub>` to `<sub>` for routing/cache-keying while the bare upstream
  still received the client's original Host — a cross-Host cache-mixing bug. The
  feature is gone rather than patched; use a real `site` per host.
- **Benchmarks: micro yes, macro not committed.** `cargo bench` (benches/hot.rs)
  measures the CPU-bound hot path deterministically (normalize_path ~0.15 µs,
  accept_encoding_key ~0.3 µs, ketama_pick ~20 ns, stable_hash ~8 ns, a 2-site
  config parse ~0.1 ms — indicative, machine-dependent). There is NO committed
  end-to-end throughput / P50-P99 number: `scripts/loadtest.sh` (needs `oha`)
  drives a running server for that, but the results aren't checked in, and the
  reaper's full-scan cost at the million-file ceiling is still un-benchmarked.
- **CI actions are major-tag pinned, not SHA-pinned.** All actions run on Node 24
  (no deprecated Node-20 actions), but they use `@v5`/`@v2`-style tags. Full
  commit-SHA pinning (a moved tag can't inject code) is the stricter posture and
  is not yet applied.
- **`protobuf` 2.28 has a CURRENT RustSec advisory —
  [RUSTSEC-2024-0437](https://rustsec.org/advisories/RUSTSEC-2024-0437.html)
  (uncontrolled recursion → crash), fixed only in protobuf >= 3.7.** It reaches
  us transitively (`prometheus` ← both sluice and `pingora-core`), so the
  upgrade is blocked on upstream pingora/prometheus bumps. The risk is
  **accepted**, not merely historical: Sluice never parses attacker-controlled
  protobuf on the request path (the crate only serves Prometheus text/protobuf
  *encoding*). CI runs `cargo audit` with exactly this one advisory ignored —
  any other advisory fails the build. Re-evaluate on every pingora bump.

---

## How this list is maintained

When a review finds an issue, it is either **fixed** (and the fix verified with a
reproduction) or it lands **here** with a reason. "Silently ignored" is not an
option — an unhandled review item is a bug in this document.
