# Sluice — a config-driven edge proxy on Pingora

**Status:** design draft · **Owner:** Vincent · **Date:** 2026-07-20

> A *sluice* is a gated channel that routes and regulates water flow. This is a
> reverse proxy that routes and regulates HTTP traffic — declared in a config
> file, not recompiled per change.

## 1. Motivation

[Pingora](https://github.com/cloudflare/pingora) is a superb library for building
proxies — but it *is* a library: proxy behaviour lives in Rust source, so every
route, timeout, or vhost change means edit → `cargo build` → redeploy. nginx/Caddy
users edit a text file and reload.

**Sluice** is a standalone, general-purpose, **config-file-driven** reverse proxy
built on Pingora: one static binary, one `sluice.kdl`, hot reload, first-class
Prometheus, and GeoIP. Point it at a config and it serves — no recompile.

The primitives are proven: we already run a hand-coded Pingora proxy in production
(fronting a live site behind Cloudflare), which validated host routing, TLS
termination, SSE/websocket passthrough, trusted client-IP from `CF-Connecting-IP`,
Prometheus metrics, and graceful drain. Sluice turns those from hardcoded Rust into
configuration — and is deliberately **not tied to that or any single deployment**;
that site is merely one user of it.

### Why not just adopt something else

| Option | Verdict |
| --- | --- |
| **River** (ISRG, Pingora-based, config-driven) | The right idea; last release v0.5.0 (2024-08), "no expectation of stability", feature-thin (no GeoIP). We **adopt its KDL config approach** (§4) but not the codebase — reference, not base. |
| **Caddy** | Already does config + Prometheus + hot reload + auto-TLS + a MaxMind plugin. **If we only wanted those, we'd use Caddy and write zero Rust.** |
| **Sluice (this)** | A general config-driven Pingora proxy. Justified because we specifically want Pingora's Rust performance/connection model and full programmable control, with config-file ergonomics on top. |

**Explicit bet:** we build on Pingora *because* we want to stay on it and keep
programmable control, not merely to get a config file. If that bet ever feels
wrong, Caddy is the fallback.

## 2. Goals / non-goals

**Goals**
- Behaviour defined in `sluice.kdl`; no recompile for routing/upstream/header/TLS-cert changes.
- Hot reload of routing config without dropping connections (SIGHUP / file-watch).
- First-class Prometheus metrics + structured access log, out of the box.
- GeoIP enrichment: country (free, via `CF-IPCountry`) + optional city/ASN (MaxMind).
- Everything a typical vhost proxy needs, expressed as config: host routing, TLS, HTTP/2,
  SSE/streaming, websockets, per-route body limits, header injection, regex redirects,
  trusted client-IP, migration test-host aliasing, graceful drain.
- Single static binary (BoringSSL), systemd-friendly.

**Non-goals (v1)**
- **Not** a general nginx replacement. We support the directives *we* need, not a
  universal config language. Scope discipline is the #1 risk (see §9).
- ~~No automatic ACME/TLS issuance in v1~~ — **now implemented (M5)** and
  live-verified; behind Cloudflare an Origin CA cert is still the recommended path.
- No Lua/JS scripting layer. Programmable behaviour = Rust plugins compiled in, not runtime scripts.
- No built-in WAF, no load-balancing across many upstream replicas in v1 (single upstream per route; add pools later).

## 3. Architecture

```
                +-------------------- sluice (1 static binary) --------------------+
  client → CF → | listeners (:443 TLS/h2, :80 redirect)                            |
                |     │                                                            |
                |     ▼   ProxyHttp impl                                           |
                |   Router  ── reads ──▶  ArcSwap<Config>  ◀── reload ── file/SIGHUP|
                |     │                        ▲                                   |
                |     ▼                        │                                   |
                |   Upstream (keepalive pool) ─┘                                   |
                |     │            │            │                                  |
                |     ▼            ▼            ▼                                  |
                |  metrics()   geoip()     access-log                              |
                +---------│---------│----------------------------------------------+
                          ▼         ▼
                 :9090 /metrics   MaxMind mmdb (mmap)
```

- **Core:** Pingora `Server` + a single `ProxyHttp` implementation. All request
  behaviour is data-driven from the loaded `Config`, not hardcoded.
- **Config store:** `arc-swap::ArcSwap<Arc<Config>>`. The request path reads a
  cheap `.load()`; reload builds a fresh `Config` and atomically swaps it. In-flight
  requests keep the snapshot they started with.
- **Router:** host → site lookup (hash map built at load), then per-site rules
  (redirects, upstream, timeouts). O(1) host match; regex redirects compiled at load.
- **Reload triggers:** `SIGHUP` and/or `notify` file-watch on `sluice.kdl`. Parse +
  validate a candidate config; on success, swap; on failure, log and keep the old one
  (never take down a running proxy with a bad edit).

### Reload scope (be honest about limits)
Hot-reloadable: sites, upstreams, timeouts, body limits, headers, redirects, alias
prefix, rate limits, geoip settings. **Not** hot-reloadable in v1: listener
addresses and TLS listener setup (socket-level) — those need a graceful restart
(Pingora's SIGQUIT fd-handoff, or systemd restart with drain). nginx has the same
practical split. Cert *file* rotation can be picked up by re-reading on reload if we
reload the TLS context; treat as v1.1.

## 4. Config format & schema (the core design work)

### Format decision: KDL (nginx-like blocks, no YAML indentation)

nginx's config is a bespoke syntax — `directive arg;` statements and `block { … }`
groups, **whitespace-insensitive** (indentation is cosmetic). We want exactly that
ergonomics (braces + directives, no significant indentation like YAML) but *without*
hand-writing and maintaining a custom parser.

**Decision: KDL** (the KDL Document Language) — the same format River uses. KDL gives
the nginx block feel, is whitespace-insensitive, has comments, and — the deciding
factor — the Rust [`kdl`](https://crates.io/crates/kdl) crate (v6) parses **with
source spans**, so `sluice --check` can emit `line:col`-precise diagnostics. It is the
sweet spot between "reads like nginx" and "real validation without a bespoke parser."

> If we ever insist on *byte-for-byte* nginx syntax, we'd hand-write a `nom`/`pest`
> parser — more code, no ecosystem, span/error handling from scratch, marginal gain
> over KDL. Kept as a fallback, not the plan.

### Example `sluice.kdl`

```kdl
server {
    threads 0                          // 0 = all cores
    metrics-addr "127.0.0.1:9090"
    grace-period-secs 30
    graceful-shutdown-secs 300
    upstream-keepalive-pool 256
    upgrade-sock "/run/sluice/upgrade.sock"
}

client-ip {
    trusted-header "cf-connecting-ip"  // drop client XFF chain, trust CF
}

geoip {
    enabled true
    country-header "cf-ipcountry"      // free country code from Cloudflare
    mmdb-asn  "/etc/sluice/GeoLite2-ASN.mmdb"    // optional → asn + asn-org
    mmdb-city "/etc/sluice/GeoLite2-City.mmdb"   // optional → city / lat-lon
    log-fields "country" "asn" "asn-org"         // added to every access log line
    metric-labels "country"                      // low-cardinality only
}

listener "0.0.0.0:443" {
    http2 true
    tls cert="/etc/sluice/fullchain.pem" key="/etc/sluice/privkey.pem"
}
listener "0.0.0.0:80" {
    redirect-to-https true             // unconditional 301, all hosts
}

alias prefix="staging"                 // staging-<sub>.example.com == <sub>.example.com

defaults {
    hsts "max-age=31536000"
    unknown-host 404                   // response for an unmatched Host
}

site "app.example.com" {
    upstream "127.0.0.1:31000"
    websocket true                     // → no upstream read timeout
}

site "api.example.com" {
    upstream "127.0.0.1:31100"
    max-body "32MiB"
    read-timeout-secs 300              // SSE: max gap between chunks
    rate-limit rps=50 burst=100 key="client_ip"
}

site "example.com" {                   // apex with auth-path redirects
    upstream "127.0.0.1:31000"
    redirect match="^(?:/[a-z]{2})?/(login|register|dashboard)(?:/|$)" \
             target="https://app.example.com{uri}" status=301
    redirect match="^/api/auth(?:/|$)" \
             target="https://app.example.com{uri}" status=301
}

site "grafana.example.com" {
    upstream "127.0.0.1:3001"
    websocket true
    access cloudflare-only=true        // 403 unless the peer is a CF edge IP
}
```

Semantics:
- `{uri}` / `{host}` interpolation in redirect targets.
- `max-body` accepts human sizes (`32MiB`); parsed once at load.
- `site` inherits `defaults` unless it overrides them.
- `access cloudflare-only=true` folds the "firewall to CF" idea into L7 (belt to the ufw braces).

### `sluice --check` — validation (nginx -t equivalent, and better)

Two phases, both also run before any hot-reload swap so a bad edit **never** takes
down or mis-configures a running proxy:

1. **Syntax** — KDL parse. The `kdl` crate reports `line:col` + a caret span on
   malformed input (`expected "}" at 14:1`).
2. **Semantic** — walk the parsed document:
   - required fields present (a `site` must have `upstream`);
   - types/units valid (`max-body` is a size; redirect `status` in 300–399);
   - every `match` regex **compiles** (a bad regex fails here, not at 3am in prod);
   - addresses parse; `cert`/`key`/`mmdb` files exist and are readable;
   - no duplicate `site` host; **no unknown directives** (typo `upstreamm` → error,
     not a silent no-op — nginx's biggest footgun avoided).
   Each diagnostic carries the source span, River-style.

`sluice --check -c sluice.kdl` exits non-zero with the diagnostics — wire it into CI
and use it as the pre-reload gate.

## 5. Observability

Built in, not bolted on:
- **Prometheus** at `metrics_addr` (loopback). Core series:
  - `sluice_requests_total{host,status}` — status class
  - `sluice_responses_total{host,code}` — exact code
  - `sluice_request_duration_seconds{host}` — histogram
  - `sluice_inflight_requests` — gauge
  - `sluice_response_bytes_total{host}` / `sluice_request_bytes_total{host}`
  - `sluice_upstream_errors_total{host}`
  - `sluice_requests_by_country_total{country}` — **separate** metric so geo doesn't
    multiply cardinality on the main series
- **Access log** (`logging()` hook): `client country method host path -> status Nms up`.
- Ship a Grafana dashboard JSON in-repo (a ready 20-panel board) + a **Geomap** panel.

## 6. GeoIP

**Opt-in via config; zero cost when off.** No `geoip` block (or `enabled false`) →
Sluice does no geo work at all: no DB mmap, no lookups, no extra log fields, the
per-request path just skips it. Turn it on and **every request log carries the geo
fields** (that's the model the design targets).

### Config

```kdl
geoip {
    enabled true
    country-header "cf-ipcountry"                  // free country code (behind Cloudflare)
    mmdb-asn  "/etc/sluice/GeoLite2-ASN.mmdb"       // optional → enables asn + asn-org
    mmdb-city "/etc/sluice/GeoLite2-City.mmdb"      // optional → enables city + lat/lon
    log-fields "country" "asn" "asn-org"           // what to add to the access log
    metric-labels "country"                        // LOW-cardinality only (see below)
}
```

### Three data sources, layered

| Field | Source | Cost |
| --- | --- | --- |
| `country` (2-letter) | `CF-Connecting-IP` region via the **`CF-IPCountry`** header Cloudflare already sends | free, no DB |
| `asn` + `asn-org` | **GeoLite2-ASN.mmdb** (MaxMind) lookup on the trusted client IP | ~60 MB mmap |
| `city` / `lat` / `lon` | **GeoLite2-City.mmdb** (MaxMind) | ~60–100 MB mmap |

Each is independent: country needs no DB; ASN needs only the ASN db; city needs only
the city db. Enable exactly what you reference. Behind Cloudflare, country from the
header is usually enough — MaxMind is for when you specifically want ASN or city, or
when Sluice is deployed **not** behind Cloudflare.

### ASN design (the part with a footgun)

- GeoLite2-ASN maps IP → `autonomous_system_number` (e.g. `13335`) + organization
  (e.g. `Cloudflare, Inc.`, `China Mobile`). Because we look up `CF-Connecting-IP`
  (the real user), we get the **user's network/ISP** — useful for abuse detection
  (datacenter/hosting ASNs = likely bots), per-ISP analytics, and ASN-keyed rate limits.
- **Cardinality rule (important):** ASN and city are **high-cardinality** (tens of
  thousands of ASNs, free-text org/city names). They go in **logs, never as Prometheus
  labels** — a `{asn}` label would blow up the series count. Country (~250 values) is
  the only geo field allowed in `metric-labels`. `--check` **rejects** `asn`/`city` in
  `metric-labels`. If per-ASN metrics are truly wanted later: a dedicated opt-in
  top-N counter, not a raw label.

### Log enrichment

When enabled, the `logging()` hook appends the `log-fields` to each line:

```
# geoip off
203.0.113.7 POST api.example.com/v1/chat -> 200 42ms up=:31100
# geoip on  (country + asn + asn-org)
203.0.113.7 CN AS4134/CHINANET POST api.example.com/v1/chat -> 200 42ms up=:31100
```

Add a `log-format "text"|"json"` server option so geo fields can be **structured**
(queryable in Loki/ELK by `country`/`asn`) instead of a text blob. JSON recommended
once you're shipping logs anywhere.

### Lookup, performance, reload

- mmap each `.mmdb` once at load into a shared `Arc` (read-only). Lookups are pure
  memory, ~microseconds, no I/O — cheap per request.
- **Reload:** re-open the mmdb on config reload so a `geoipupdate` refresh is picked up.
  (Optional: a periodic re-open timer independent of config reload.)
- **Graceful degrade:** a private/unknown IP not in the db → empty field, not an error;
  the request is never failed by a geo miss. A *missing db file* is caught at `--check`.
- **MMDB source — no MaxMind account.** Pull the `.mmdb` files from the
  **[P3TERX/GeoLite.mmdb](https://github.com/P3TERX/GeoLite.mmdb)** GitHub mirror
  releases (rebuilt every few days). Latest assets:
  `GeoLite2-ASN.mmdb` (~11 MB), `GeoLite2-City.mmdb` (~62 MB),
  `GeoLite2-Country.mmdb` (~8 MB). Stable "always latest" URL:
  ```
  https://github.com/P3TERX/GeoLite.mmdb/releases/latest/download/GeoLite2-ASN.mmdb
  ```
  A weekly cron `curl -fsSL <url> -o /etc/sluice/GeoLite2-ASN.mmdb` refreshes them;
  Sluice re-mmaps on config reload. Needed only when ASN/city is enabled (country uses
  the CF header, no DB). This drops the MaxMind license-key + `geoipupdate` dependency.

## 7. Deployment

- **Pingora version:** `0.8.1` is the latest release (2026-06-04; it carries an
  HTTP/2 memory-exhaustion security fix + Rust 1.84 support) — there is no 0.9+.
  Depend on `pingora = "0.8"`. If we need an unreleased fix, pin to the git `main`
  branch instead of a published tag, but prefer released versions for prod.
- **TLS backend:** default **OpenSSL** — empirically verified working behind
  Cloudflare (OpenSSL 3.5.x origin on Debian 13, 5/5 requests 200, no 525).
  BoringSSL is an optional alternative (Cloudflare's own stack, statically linked)
  built with `--features boringssl` — not required. (The OpenSSL-3 → CF 525
  incident recorded in owo-router's infra docs was **nginx-specific** and its fix
  was OpenSSL 1.1.1w, not BoringSSL; it does not reproduce with Pingora/Sluice.)
  rustls is unusable — pingora's rustls backend lacks the cert callback.
- systemd unit: non-root + `CAP_NET_BIND_SERVICE`, `KillSignal=SIGTERM`
  graceful drain, `RuntimeDirectory` for the upgrade socket.
- Config at `/etc/sluice/sluice.kdl`; certs + mmdb alongside.
- `sluice --check -c sluice.kdl` validates config without starting (CI + pre-reload gate).

## 7b. Automatic TLS (ACME) — assessment

Feasible, but it is the **single largest feature** (auto-TLS is Caddy's whole
identity). What it takes on Pingora:

- **ACME client:** `instant-acme` (async, RFC 8555, Let's Encrypt/ZeroSSL).
- **Challenge:** HTTP-01 is the pragmatic path — serve `/.well-known/acme-
  challenge/<token>` on the existing `:80` listener (which today only redirects),
  then fall through to the redirect. (TLS-ALPN-01 needs a challenge cert swapped
  onto `:443` mid-handshake — harder with Pingora.)
- **Cert store + renewal:** persist account key + issued certs to disk; a
  background task renews ~30 days before expiry.
- **The hard part — dynamic certs:** Pingora binds certs at listener creation
  (`add_tls_with_settings`). Serving a cert obtained *after* startup, and rotating
  on renewal, needs Pingora's **dynamic certificate callback**
  (`TlsSettings::with_callbacks` + an SNI cert resolver reading an
  `ArcSwap<CertStore>` the renewal loop updates). This is advanced Pingora usage
  and the main implementation risk.

Effort: a few days, most of it the dynamic-cert callback + challenge plumbing.

**Recommendation — probably don't build it for the current deployment.** Sluice's
real user runs **behind Cloudflare**: clients see Cloudflare's edge cert (CF owns
public TLS), and the origin uses a **Cloudflare Origin CA cert** — free, valid
**15 years**, zero renewal. ACME buys *nothing* there. It only matters if Sluice is
deployed **directly public** (no CDN in front), as a standalone Caddy-style server.
So: build it when/if there's a non-CF deployment; until then it's cost with no
benefit. Tracked as M5.

## 8. Milestones

- **M0 — core — DONE:** KDL `Config` loader + `--check`; config-driven `ProxyHttp`
  (host routing, redirects, timeouts, body limits, client-IP, HSTS, alias); listeners
  from config; Prometheus + access log.
- **M1 — reload — DONE:** ArcSwap + SIGHUP + fail-safe (bad config keeps old). File-watch
  not done (SIGHUP only).
- **M2 — geo — DONE:** country from `CF-IPCountry`, optional MaxMind ASN/city, country
  metric, log-field enrichment. Grafana board/Geomap not shipped yet.
- **M3 — controls — DONE (partial):** per-site rate limiting (token bucket) +
  `cloudflare-only` access. Cert hot-rotate not done.
- **HTTPS upstreams + Host rewrite — DONE:** `upstream "https://host"` (TLS+SNI+
  verify), Host rewritten to the upstream host; `upstream-host`/`upstream-verify`
  overrides. Verified against a real public HTTPS API. SSE + WebSocket pass through
  unbuffered (tested).
- **M5 — auto-TLS — DONE + LIVE-VERIFIED:** dynamic SNI cert store + Pingora TLS
  callback (certs from a `cert-dir`, hot-swappable, multi-domain) AND the ACME
  client (`instant-acme` 0.8 + HTTP-01, `tls acme=true` + `acme {}`): a background
  thread provisions/renews a cert per site host, the `:80` listener answers the
  HTTP-01 challenge, certs land in the hot-swappable store. **Verified end-to-end
  against live Let's Encrypt** (2026-07-20, staging + production): pointed a
  DNS-only `acme-test.stormcrew.me` at the box and issued a real browser-trusted
  cert over HTTP-01 with zero manual steps (`curl` without `-k` → HTTP 200, TLS
  verify 0), served by the SNI callback. Required upgrading `instant-acme 0.7→0.8`:
  Let's Encrypt now offers a token-less `dns-persist-01` challenge that 0.7.2
  couldn't deserialize (`token` was a required field), breaking issuance entirely.
  **Note:** behind a proxying CDN (orange-cloud Cloudflare) HTTP-01 won't validate
  — use a Cloudflare Origin CA cert (15yr) or DNS-01 there. ACME is for
  direct-public deployments. **Known limitations (see review):** the ACME loop
  currently attempts *every* site host (a CF-fronted host will fail HTTP-01
  forever), and `tls acme=true` needs a `:80 redirect-to-https` listener present
  to answer challenges.
- **M6 — Caddy/nginx parity — DONE:** **path routing** (`location` blocks, prefix
  or `~regex`, first-match; a bare site-level backend is an implicit `/`),
  **multi-upstream load balancing** (`upstream { server…; balance round-robin|
  random|ip-hash }` + connect-failure failover), **response cache** (`pingora-cache`
  in-memory LRU + cache-lock, per-location `cache { ttl-secs }`, honors origin
  Cache-Control), and a config-driven **WAF** (`waf { block field=… match=… }` on
  path/query/method/header). Static files now stream off the async runtime. All
  verified live on the test box (routing, RR distribution, failover, cache HIT vs
  no-store, WAF blocks).
- **M4 (later):** true zero-downtime binary upgrade (SIGQUIT fd-handoff), config
  file-watch, **upstream health checks** (passive down-marking / active probes),
  **per-location header add/remove**, disk-backed cache, Grafana board. Full
  Lua/Rhai **scripting** remains out of scope (a compiled-in plugin seam instead).

"nginx-like general tool" is explicitly out of scope (months, not weeks). Known MVP
gaps to revisit: rate-limiter map has no eviction (grows with distinct client IPs);
reload does not re-read `server{}`/listeners (by design — those need a restart).

## 9. Risks

- **Config-language scope creep** — the classic trap. Mitigate: only add a directive
  when *we* need it; the schema serves our deployments, not the world.
- **Hot-reload correctness** — swapping routing while serving has edge cases
  (in-flight requests, listener/TLS vs routing split). Mitigate: ArcSwap snapshot per
  request, keep listeners out of reload scope in v1, heavy tests.
- **Maintenance burden** — a bespoke proxy is ours to keep alive vs battle-tested
  nginx/Caddy. Justified only by the Pingora bet (§1); revisit if it stops paying off.
- **MaxMind licensing/ops** — account + license key + update cron. Keep it optional.

## 10. Open questions

- ~~Config format~~ — **decided: KDL** (§4). nginx-like ergonomics, whitespace-insensitive,
  span-precise validation via the `kdl` crate, aligns with River.
- Multi-tenant / many-cert SNI: one cert now (wildcard); design for a cert-per-SNI map later?
- Do we want a minimal admin/reload HTTP endpoint, or SIGHUP/file-watch only?
- Repo home: standalone public OSS, or internal first then open?

## 11. Prior art / references

**Cloned locally for reference** (in `~/Projects/`, not dependencies):
- `~/Projects/pingora` — Cloudflare Pingora source (the framework).
- `~/Projects/river` — River source; read `source/river/assets/test-config.kdl` for a
  real KDL config and `source/river/src/config/` for its loader/validator.

What River actually does (grounded in the clone — corrects earlier guesses):
- **Both KDL *and* TOML** config (`config/kdl.rs` + `config/toml.rs`); KDL is primary.
  Confirms KDL is a sound choice; we pick KDL-only for simplicity.
- **Has validation** — `config::internal::validate()` + a config-test/`validate-configs`
  path. Confirms the `sluice --check` pattern.
- Model = **named `services`**, each with its own `listeners` + `connectors`
  (round-robin/Ketama LB, health-check) + `rate-limiting` (token-bucket: `source-ip` /
  `specific-uri` / `any-matching-uri`, `max-buckets`/`tokens-per-bucket`/`refill-*`) +
  `path-control` (`request-filters`/`upstream-request`/`upstream-response` with
  `block-cidr-range`, `remove-header-key-regex`, `upsert-header`). Also a `file-server`
  service type.
- **Deliberate divergence:** River is HAProxy-shaped (named frontends/backends). Sluice
  is nginx-shaped (**route by `Host` into `site` blocks** on shared listeners) — simpler
  for our "many vhosts on :443" case. But we should **borrow River's vocabulary** for
  rate-limiting (token-bucket kinds) and header/CIDR filters (`path-control`) rather than
  invent our own.

**Other:**
- `kdl` crate (config parser, span-preserving) — https://crates.io/crates/kdl
- P3TERX/GeoLite.mmdb (MMDB mirror, no MaxMind account) — https://github.com/P3TERX/GeoLite.mmdb
- Caddy (the pragmatic alternative) — https://caddyserver.com
- An existing hand-coded Pingora proxy of ours (behind Cloudflare) proved the primitives
  Sluice generalises — a reference point, not a component of this project.
- `maxminddb` crate; MaxMind GeoLite2.
