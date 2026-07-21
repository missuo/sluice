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

### 2.2 Disk-cache reaper does a full directory scan
- **What:** the disk cache's background reaper (every 30 s) walks the whole cache
  directory to enforce the size / file-count / free-space bounds.
- **Why not fixed:** O(files) every 30 s is fine for the expected cache size and is
  how simple on-disk caches (and nginx's cache manager) work. An incremental index
  (in-memory LRU of on-disk entries with usage tracking) would avoid the scan but
  adds a crash-consistency problem (index vs. disk divergence after an unclean
  exit) that the stateless full-scan sidesteps. Not worth the complexity until a
  large cache makes the scan a measured problem.
- **Mitigation:** keep `cache-store { max-files }` reasonable; the scan cost scales
  with it.

### 2.3 Config file-watch / `cert-dir` hot-reload
- **What:** config reload is **SIGHUP-triggered**, not automatic on file change;
  a `cert-dir` is read **once at startup** (only ACME renewals hot-swap the store).
- **Why not fixed:** SIGHUP is explicit and predictable; a file-watcher adds a
  dependency and races (partial writes). Rotating a `cert-dir` file today needs a
  SIGHUP/restart.
- **What it would take:** a debounced `notify`-based watcher feeding the same
  `ArcSwap` reload path. Small, just not yet prioritised.

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

## How this list is maintained

When a review finds an issue, it is either **fixed** (and the fix verified with a
reproduction) or it lands **here** with a reason. "Silently ignored" is not an
option — an unhandled review item is a bug in this document.
