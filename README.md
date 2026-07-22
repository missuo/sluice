# Sluice

A config-driven edge proxy on [Pingora](https://github.com/cloudflare/pingora).
Routes and regulates HTTP traffic from a KDL config file — no recompile per change.

> A *sluice* is a gated channel that routes and regulates water flow.

See [DESIGN.md](DESIGN.md) for the full design. Milestones M0–M3 plus HTTPS
upstreams and auto-TLS are implemented; ACME issuance is verified end-to-end
against live Let's Encrypt (staging + production).

## What works

- **KDL config** (`sluice.kdl`), nginx-like blocks, whitespace-insensitive.
- **`sluice --check`** — syntax (`line:col`) + semantic validation (unknown
  directives, missing/duplicate fields, bad regex, missing cert/mmdb files).
- **Hot reload on SIGHUP** — re-parses the file and atomically swaps; a bad edit
  is rejected and the running config is kept (never takes the proxy down). This
  covers the request path (sites, routing, upstreams, WAF, rate limits, GeoIP)
  **and `cert-dir` certificate rotation** — each `cert-dir` store is re-read
  strictly and swapped per-store atomically, so a rotated cert is served after
  SIGHUP while a malformed / half-rotated / empty directory is rejected and the
  old certs stay live (fail-before-commit). **Listener/TLS topology, the single
  `cert`/`key` files, `cache-store`, ACME, and `server{}` settings are fixed at
  startup** and need a restart to change; a SIGHUP that changes any of them is
  rejected rather than silently ignored (see DESIGN.md §3).
- Host-routed **sites**, then **path-routed `location` blocks** (prefix or
  `~regex`, first match wins) — nginx-style routing to different backends per path.
- **Load-balanced upstream pools**: `upstream { server …; server …; balance … }`
  with **round-robin / random / ip-hash / ketama / least-conn** selection,
  per-server **`weight`**, and connect-failure **failover** to the next member.
  `weight` applies to round-robin / random / ketama / least-conn; **`ip-hash` is
  unweighted** (plain `hash(ip) % N`) — use **`ketama`** for weighted *and*
  consistent hashing. Ketama scaling the pool only remaps ~1/n of clients;
  least-conn sends each request to the least busy backend. **Health checks**: passive by default (skip a
  backend for 10s after a failed connect) and optional **active** probing
  (`health-check { path … interval-secs … }`, like Caddy) that takes an
  unhealthy-but-reachable backend out of rotation proactively.
- **Response cache** (`cache { ttl-secs … }`, backed by `pingora-cache`): in-memory
  LRU with a thundering-herd lock; honors the origin's `Cache-Control` (never
  caches `no-store`/`private`/`Set-Cookie`) and applies the location TTL otherwise.
  Optional **disk backend** (`cache-store { dir … max-size … }`) — a hand-written
  `Storage` impl (Pingora ships only an in-memory one) with atomic writes,
  sharded files, a size-bounding reaper, and **cache that survives restarts**.
- **WAF**: `waf { block field=… match=… }` blocks requests by regex on
  path / query / method / any header (e.g. bad user-agents, injection patterns).
- **regex redirects** with `{uri}`/`{host}`; per-location **body limits**
  (enforced while streaming), **read timeouts**, **websocket** passthrough, **HSTS**.
- **Static file server** (`file-server { root … }`, index files, content-type by
  extension, path-traversal protection, **streamed** off the async runtime) —
  as a whole site or a single `location`.
- **Path `deny`** rules (regex → 403), like nginx `deny`.

> Regexes go in KDL **raw strings** when they contain a backslash:
> `match=r"\.php$"` (a plain `"\.php$"` is an invalid KDL escape).
- **TLS** listeners (OpenSSL by default, BoringSSL optional) + **:80 → https**
  redirect, all from config.
  A single `cert`/`key`, **dynamic SNI certs** (`tls cert-dir="…"`), or
  **auto-TLS via ACME/Let's Encrypt** (`tls acme=true` + an `acme {}` block,
  HTTP-01, like Caddy — for domains that resolve directly to the server with :80
  open; behind Cloudflare use an Origin CA cert instead). ACME-renewed certs
  hot-swap at runtime via the TLS callback — no restart. **`cert-dir` stores also
  reload on SIGHUP** — strict + per-store atomic, so a rotated cert appears after
  SIGHUP while a malformed / half-rotated / empty dir is rejected and the old
  certs stay live. The single `cert`/`key` files are read once at startup;
  rotating those needs a restart.
  Auto-TLS is **verified end-to-end
  against live Let's Encrypt** (staging and production): a browser-trusted cert
  issues over HTTP-01 with zero manual steps and is served by SNI at runtime.
- **HTTPS upstreams** (`upstream "https://api.openai.com"`): TLS + SNI + cert
  verification, and Host rewritten to the upstream host — reverse-proxy external
  APIs (OpenAI/S3). SSE streaming and WebSocket upgrades pass through unbuffered.
- **Response-body rewrite** (`sub-filter from=… to=…`, like nginx `sub_filter`):
  streaming find/replace on text responses (matches across chunk boundaries);
  the origin is asked for an uncompressed response so the body can be rewritten.
- Trusted **client IP** from a configurable header (e.g. `CF-Connecting-IP`),
  dropping the spoofable client XFF chain.
- **Per-site rate limiting** (token bucket per client IP, IPv6 bucketed by /64)
  and **`cloudflare-only`**
  access (403 unless the peer is a Cloudflare edge IP).
- **GeoIP**: country from the `CF-IPCountry` header (free) + optional **MaxMind
  ASN/city** (`maxminddb`); enriches the access log per `log-fields`; country as a
  Prometheus label.
- **Prometheus** metrics + a per-request **access log** (text; JSON is on the roadmap).
- **Request hardening to an nginx/Caddy security bar:**
  - **Strict Host/authority:** exactly one syntactically valid authority per
    request — duplicate `Host` lines, an absolute-form / HTTP/2 `:authority` that
    disagrees with `Host`, and non-numeric/over-range ports are all `400`. Routing,
    the upstream `Host`, and the cache key share one canonical value, so no later
    hop can route on a different host (authz bypass / cross-vhost cache poisoning).
  - **Canonical upstream target:** the request is forwarded in **origin-form** with
    the fully-normalized path (percent-decoded, `.`/`..` resolved, `//` collapsed,
    matrix `;params` dropped, backslashes rejected) — the proxy and origin never
    disagree on the path, and the raw client target is never passed through.
  - **Hop-by-hop stripping:** every `Connection`-nominated header plus the standard
    hop-by-hop set (`Connection`, `Proxy-Connection`, `Keep-Alive`, `TE`, `Trailer`,
    `Transfer-Encoding`, `Upgrade`) is removed **both** upstream and on the response
    before caching — a WebSocket upgrade is preserved only for a `websocket`
    location.
  - **Slowloris / DoS controls:** absolute request-receive deadline
    (`request-timeout-secs`, checked on every body chunk including the last),
    tightened per-read downstream timeout (`downstream-read-timeout-secs`),
    minimum response send rate (`min-send-rate-bytes`), and a per-IP
    **in-flight**-connection cap (`max-conn-per-ip`) enforced both pre-handshake
    (at TCP accept, bounding a partial-ClientHello flood) and post-handshake (an
    exact per-connection guard), on both the TLS and the :80 listener.
    (First-header Slowloris and the fixed TLS-handshake timeout are bounded by
    Pingora — see KNOWN_ISSUES.md §1.4.)
  - **Privilege separation:** refuses to run as **root** unless explicitly allowed;
    ships a hardened **systemd unit** (`examples/sluice.service`) — dedicated user,
    `CAP_NET_BIND_SERVICE` only, `NoNewPrivileges`, `ProtectSystem=strict`, seccomp.
- Multi-core, graceful drain on SIGTERM, upstream keepalive pool.
- **Zero-downtime binary upgrade** (Pingora fd handoff): with an `upgrade-sock`
  set, start the new binary with `-u` (it takes over the listening sockets from
  the running one), then `SIGQUIT` the old process to drain and exit — no dropped
  connections. Verified: 120 continuous requests across an upgrade, 0 failures.

Roadmap (see DESIGN.md): config file-watch, least-conn EWMA, a constrained
request-routing expression language (not full scripting). Items that are blocked
upstream or deliberately deferred — HTTP/3, Rustls, `notAfter`-based ACME renewal,
weighted `ip-hash`, full scripting — and the reason for each are documented in
**[KNOWN_ISSUES.md](KNOWN_ISSUES.md)**.

## Comparison with nginx and Caddy

Legend: ✅ built-in · 🔌 plugin/module · 💰 paid tier only · ❌ not available

| Feature | Sluice | nginx (OSS) | Caddy |
| --- | :---: | :---: | :---: |
| Written in | Rust (Pingora) | C | Go |
| Single binary (dynamically links libc) | ✅ | ✅ | ✅ |
| Config format | KDL | custom DSL | Caddyfile / JSON |
| Config validation | ✅ semantic + `line:col` | ✅ syntax (`-t`) | ✅ |
| Hot config reload | ✅ SIGHUP, fail-safe | ✅ SIGHUP | ✅ (API) |
| Zero-downtime binary upgrade | ✅ (`-u`, fd handoff) | ✅ | ✅ |
| Host (vhost) routing | ✅ | ✅ | ✅ |
| Path routing (`location`) | ✅ prefix/regex | ✅ | ✅ |
| Reverse proxy + keepalive pool | ✅ | ✅ | ✅ |
| HTTPS upstreams + SNI + Host rewrite | ✅ | ✅ | ✅ |
| SSE / streaming (unbuffered) | ✅ default | ⚠️ needs `proxy_buffering off` | ✅ |
| WebSocket passthrough | ✅ | ✅ | ✅ |
| HTTP/2 | ✅ | ✅ | ✅ |
| HTTP/3 (QUIC) | ❌ (Pingora has none) | ✅ | ✅ |
| Load balancing | ✅ RR / random / ip-hash / ketama / least-conn | ✅ + least-conn | ✅ + least-conn |
| Weighted backends | ✅ | ✅ | ✅ |
| Consistent hashing (Ketama) | ✅ | 🔌 (`hash consistent`) | ✅ |
| Passive health checks | ✅ | ✅ | ✅ |
| Active health checks | ✅ | 💰 (NGINX Plus) | ✅ |
| Response cache | ✅ in-memory LRU **+ disk** | ✅ disk-backed | 🔌 (Souin) |
| Static file server | ✅ streamed | ✅ (sendfile) | ✅ |
| Automatic TLS (ACME) | ✅ HTTP-01 | 🔌 (certbot, external) | ✅ (flagship) |
| Dynamic SNI / multi-cert | ✅ | ✅ | ✅ |
| Rate limiting | ✅ token bucket | ✅ (`limit_req`) | 🔌 |
| WAF | ✅ regex rules (path/query/method/header) | 🔌 (ModSecurity) | 🔌 (Coraza) |
| GeoIP (country / ASN / city) | ✅ built-in | 🔌 (geoip2) | 🔌 |
| Prometheus metrics | ✅ built-in | ⚠️ basic `stub_status` / 🔌 exporter | ✅ built-in |
| Trusted client-IP + anti-spoofing | ✅ | ⚠️ manual (`realip`) | ⚠️ manual |
| Request-body size cap (streaming) | ✅ | ✅ | ✅ |
| Strict Host/authority + hop-by-hop stripping | ✅ | ⚠️ partial | ✅ |
| Slowloris / connection caps | ✅ (deadline + per-IP cap) | ✅ (`*_timeout`, `limit_conn`) | ✅ |
| Runs unprivileged by default + systemd sandbox | ✅ (refuses root) | ⚠️ master as root | ⚠️ manual |
| Response-body rewrite | ✅ (`sub-filter`) | ✅ (`sub_filter`) | 🔌 |
| Scripting | ❌ (Rust plugins) | ✅ njs / 🔌 Lua | ❌ (Go plugins) |
| TLS backends | OpenSSL / BoringSSL | OpenSSL | Go crypto / BoringSSL |

Sluice's niche is a **Cloudflare-fronted edge / API gateway**: it ships the
things you'd otherwise bolt onto nginx with modules or pay NGINX Plus for
(active health checks, GeoIP, Prometheus, anti-spoof client-IP, a WAF), with
Caddy-style auto-TLS and config validation, on Pingora's Rust connection model.
It is deliberately **not** a general nginx replacement — no HTTP/3 (Pingora has
no QUIC), no scripting, and a smaller directive set (see DESIGN.md §2).

## Build

```bash
cargo build                                              # dev (openssl)
cargo build --release --no-default-features --features boringssl   # prod
```

The BoringSSL build (`boring-sys`) needs a few tools beyond a C toolchain — on a
fresh Debian:

```bash
apt-get install -y build-essential cmake clang libclang-dev pkg-config \
                   git golang-go nasm ninja-build
```

(`git` is used to apply BoringSSL patches; `go`/`nasm`/`ninja` build it.)

## Run

```bash
sluice --check -c examples/sluice.kdl     # validate
sluice -c /etc/sluice/sluice.kdl          # run
```

See [`examples/sluice.kdl`](examples/sluice.kdl) for a full annotated config.

### Deploy (privilege separation)

sluice **refuses to run as root** (uid 0). It terminates TLS and parses
attacker-controlled input, so it must run as a dedicated, sandboxed account — not
as root where any flaw is a host compromise. Deploy it under the shipped hardened
systemd unit, which runs it as a `sluice` user with only `CAP_NET_BIND_SERVICE`
(so it can still bind `:80`/`:443`), `NoNewPrivileges`, `ProtectSystem=strict`,
private state directories, and a seccomp filter:

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin sluice
sudo install -o sluice -g sluice -m 0700 -d /var/lib/sluice/acme /var/cache/sluice
sudo install -m0644 examples/sluice.service /etc/systemd/system/sluice.service
sudo systemctl daemon-reload && sudo systemctl enable --now sluice
```

See [`examples/sluice.service`](examples/sluice.service) for the full unit and
setup notes. If you genuinely cannot use it, `server { allow-root true }` (or
`SLUICE_ALLOW_ROOT=1`) overrides the refusal — discouraged.
