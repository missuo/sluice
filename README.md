# Sluice

**A config-driven, security-hardened TLS edge proxy on [Pingora](https://github.com/cloudflare/pingora) — a lean alternative to nginx and Caddy.**

[![CI](https://github.com/missuo/sluice/actions/workflows/ci.yml/badge.svg)](https://github.com/missuo/sluice/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/missuo/sluice)](https://github.com/missuo/sluice/releases)

Sluice terminates TLS and routes/regulates HTTP from a single [KDL](https://kdl.dev)
config — no recompile per change. It's built for the **TLS-terminating
reverse-proxy / behind-CDN edge**: automatic HTTPS, a request path hardened to the
nginx/Caddy security bar, and the **lowest memory footprint** of the three.

> A *sluice* is a gated channel that routes and regulates water flow.

## Why sluice

- **Automatic HTTPS** — Let's Encrypt over ACME HTTP-01, verified end-to-end
  against live LE (staging + production); zero manual cert steps.
- **Security-hardened by default** — strict Host/authority, Content-Length and
  Transfer-Encoding validation; fd-pinned, no-symlink static and cache paths;
  Slowloris/DoS deadlines; per-IP connection caps; privilege separation.
- **Lightest RAM of the mainstream proxies** — idle ≈ 23 MiB vs nginx ≈ 63,
  Caddy ≈ 46.
- **One KDL config, hot-reloadable** — `sluice --check` validates before deploy;
  SIGHUP atomically reloads routing / WAF / cache policy / `cert-dir` certs and
  **rejects a bad edit** (the running config is never taken down).

## Features

- **Auto-TLS (ACME/Let's Encrypt, HTTP-01)**, a single `cert`/`key`, or **dynamic
  SNI multi-cert** via `cert-dir` (hot-reloaded on SIGHUP). Renewal is scheduled
  from the certificate's real X.509 `notAfter`.
- **Reverse proxy** with HTTP/1.1 + **HTTP/2**, keepalive pooling, **HTTPS
  upstreams** (TLS + SNI + cert verification + Host rewrite), and unbuffered
  SSE/streaming.
- **Load balancing** — round-robin / random / ip-hash / **ketama** (weighted
  consistent hashing) / least-conn, per-server weights, connect-failure failover,
  and **verified active health checks** (a real TLS + HTTP status check for HTTPS
  backends, not just a TCP connect).
- **Static file server** — fd-pinned docroot opened component-by-component with
  `O_NOFOLLOW` (no symlink ever followed, no path re-resolved), plus a bounded
  per-docroot **hot-file cache** for small files.
- **Response cache** — in-memory LRU with a thundering-herd lock **and an optional
  disk backend** (`cache-store`) that survives restarts; honors origin
  `Cache-Control`.
- **Declarative WAF** (`waf { block field=… match=… }` on path/query/method/any
  header), **per-site rate limiting** (token bucket per client IP, IPv6 by /64),
  **`max-body`** streaming size caps, and regex **`deny`** rules.
- **`sub-filter`** streaming response-body rewrite (matches across chunk
  boundaries), **WebSocket** passthrough, regex **redirects**, and **HSTS**.
- **Observability** — Prometheus metrics and a per-request access log selectable
  as **`text` / `json` / `off`** (`json` is fully escaped; both log the path only,
  never the query string or credentials).
- **GeoIP** — country from the `CF-IPCountry` header (free) plus optional MaxMind
  ASN/city; trusted **client-IP** from a configurable header with anti-spoofing.
- **Operations** — `--check` config validation, SIGHUP hot reload, **zero-downtime
  binary upgrade** (Pingora fd handoff), graceful drain, a hardened **systemd
  unit**, and refusal to run as root.

**Honestly not (yet):** no **HTTP/3** (Pingora has no QUIC — fine behind a CDN
that terminates H3); **OpenSSL / BoringSSL only, no Rustls**; no plaintext-HTTP
serving (every listener is TLS or a `:80 → https` redirect); no embedded
scripting. See [KNOWN_ISSUES.md](KNOWN_ISSUES.md) for the maintained list.

## Performance

Fair, reproducible benchmark — sluice vs **nginx 1.26** vs **Caddy 2.11**,
HTTPS/1.1 keepalive on an 8-core box, all three with access logs off. Full data
and methodology in **[benchmarks/production-baseline.md](benchmarks/production-baseline.md)**.

| Workload | vs nginx | vs Caddy | Notes |
|----------|:-------:|:-------:|-------|
| **Reverse proxy** (core role) | ~0.5× | **~1.5–1.8×** | P99 close to nginx, ~3× better than Caddy |
| **Static, small hot-cache** | **~0.8–0.87×** | **~2.2×** | P99 at/under nginx's |
| Static, large (> 64 KiB, uncached) | ~0.5× | ~0.66× | streamed per request; the weakest path |
| **Idle memory (RSS)** | **~23 MiB** | | nginx ≈ 63 MiB · Caddy ≈ 46 MiB |

Sluice is an excellent fit for a **TLS-terminating reverse proxy / API gateway,
especially behind a CDN**, where its low RAM and hardening shine. For a
static-heavy, directly-exposed, maximum-QPS edge, **nginx still wins raw
throughput**.

## Install

Prebuilt, self-contained binaries (BoringSSL statically linked) are attached to
each [GitHub Release](https://github.com/missuo/sluice/releases): **Linux
x86_64 / aarch64** and **macOS (Apple Silicon)**. No Windows or macOS-Intel build.

```bash
# pick your platform:
#   sluice-x86_64-linux | sluice-aarch64-linux | sluice-aarch64-macos
curl -fsSL -o sluice \
  https://github.com/missuo/sluice/releases/latest/download/sluice-x86_64-linux
chmod +x sluice
sudo install -m 0755 sluice /usr/local/bin/sluice
sluice --version
```

For a full production setup — a dedicated unprivileged user, the hardened systemd
unit, TLS/ACME, and migration from nginx/Caddy — follow the deployment guide:
**[skills/deploy-sluice/SKILL.md](skills/deploy-sluice/SKILL.md)**.

## Quick start

A minimal reverse proxy with automatic HTTPS (`/etc/sluice/sluice.kdl`):

```kdl
acme {
    contact "admin@example.com"        // Let's Encrypt registration email
}
listener "0.0.0.0:80" {
    redirect-to-https true             // :80 → 301 https + ACME HTTP-01 challenge
}
listener "0.0.0.0:443" {
    http2 true
    tls acme=true                      // auto-issued, auto-renewed certificate
}
site "app.example.com" {
    acme true                          // opt this host into ACME issuance
    upstream "127.0.0.1:8080"          // your backend
}
```

```bash
sluice --check -c /etc/sluice/sluice.kdl    # validate before deploying
sluice -c /etc/sluice/sluice.kdl            # run
```

`:443` serves your backend over an auto-issued, auto-renewing certificate; `:80`
redirects to HTTPS and answers the HTTP-01 challenge. (HTTP-01 needs the domain to
resolve to this host with port 80 reachable and **not** behind a proxying CDN —
behind Cloudflare, use a Cloudflare Origin CA cert via `tls cert=…/key=…` instead.)

## Configuration

- **Full directive reference + copy-paste recipes:**
  [skills/deploy-sluice/reference/config.md](skills/deploy-sluice/reference/config.md)
  (every `server` / `site` / `location` / `listener` directive, cross-checked
  against the code) — covering load balancing + health checks, response/disk
  cache, WAF + rate limiting, `sub-filter`, WebSockets, DoS-hardening presets, and
  text/JSON logging.
- **Annotated example config:** [examples/sluice.kdl](examples/sluice.kdl).

## Security

Sluice is built to an nginx/Caddy security bar and treats every request as
attacker-controlled. It enforces **exactly one canonical Host/authority** per
request (duplicate/ambiguous `Host` or `:authority` → `400`), forwards the
**fully normalized origin-form path** so the proxy and origin never disagree,
performs strict **Content-Length** and **Transfer-Encoding** validation and
**hop-by-hop header stripping** (closing request-smuggling/desync classes), and
isolates the response cache across auth/credentials, `Vary`, range, and upgrades.
The static and cache directories are **fd-pinned and opened with `O_NOFOLLOW`**
(no symlink is ever followed, no path re-resolved). Slowloris/DoS is bounded by
absolute request deadlines, per-read/write timeouts, a minimum send rate, a
configurable TLS-handshake timeout, and a per-IP in-flight connection cap. In
production it **refuses to run as root** and ships a hardened systemd unit
(dedicated user, `CAP_NET_BIND_SERVICE` only, `NoNewPrivileges`,
`ProtectSystem=strict`, seccomp). Honest, current limitations are tracked in
**[KNOWN_ISSUES.md](KNOWN_ISSUES.md)**.

## Comparison with nginx and Caddy

Legend: ✅ built-in · 🔌 plugin/module · 💰 paid tier only · ❌ not available

| Feature | Sluice | nginx (OSS) | Caddy |
| --- | :---: | :---: | :---: |
| Written in | Rust (Pingora) | C | Go |
| Config format | KDL | custom DSL | Caddyfile / JSON |
| Config validation | ✅ semantic + `line:col` | ✅ syntax (`-t`) | ✅ |
| Hot config reload | ✅ SIGHUP, fail-safe | ✅ SIGHUP | ✅ (API) |
| Zero-downtime binary upgrade | ✅ (`-u`, fd handoff) | ✅ | ✅ |
| Host + path routing | ✅ prefix/regex | ✅ | ✅ |
| Reverse proxy + keepalive pool | ✅ | ✅ | ✅ |
| HTTPS upstreams + SNI + Host rewrite | ✅ | ✅ | ✅ |
| HTTP/2 | ✅ | ✅ | ✅ |
| HTTP/3 (QUIC) | ❌ (Pingora has none) | ✅ | ✅ |
| Load balancing | ✅ RR / random / ip-hash / ketama / least-conn | ✅ | ✅ |
| Consistent hashing (Ketama) | ✅ | 🔌 | ✅ |
| Active health checks | ✅ (verified TLS+HTTP) | 💰 (NGINX Plus) | ✅ |
| Response cache | ✅ in-memory LRU **+ disk** | ✅ disk-backed | 🔌 (Souin) |
| Static file server | ✅ fd-pinned, hot-cache | ✅ (sendfile) | ✅ |
| Automatic TLS (ACME) | ✅ HTTP-01 | 🔌 (certbot) | ✅ (flagship) |
| Rate limiting | ✅ token bucket | ✅ (`limit_req`) | 🔌 |
| WAF | ✅ regex rules | 🔌 (ModSecurity) | 🔌 (Coraza) |
| GeoIP (country / ASN / city) | ✅ built-in | 🔌 (geoip2) | 🔌 |
| Prometheus metrics | ✅ built-in | ⚠️ `stub_status` / 🔌 | ✅ built-in |
| Strict Host/authority + hop-by-hop stripping | ✅ | ⚠️ partial | ✅ |
| Runs unprivileged + systemd sandbox | ✅ (refuses root) | ⚠️ master as root | ⚠️ manual |
| Response-body rewrite | ✅ (`sub-filter`) | ✅ (`sub_filter`) | 🔌 |
| Scripting | ❌ | ✅ njs / 🔌 Lua | ❌ |
| TLS backends | OpenSSL / BoringSSL | OpenSSL | Go crypto / BoringSSL |

Sluice's niche is a **Cloudflare-fronted edge / API gateway**: it ships built-in
what you'd otherwise bolt onto nginx with modules or pay NGINX Plus for (active
health checks, GeoIP, Prometheus, anti-spoof client-IP, a WAF), with Caddy-style
auto-TLS and config validation. It is deliberately **not** a general nginx
replacement — no HTTP/3, no scripting, and a smaller directive set.

## Build from source

```bash
# Dev build (default OpenSSL backend):
cargo build

# Release build with BoringSSL, statically linked (the self-contained binary
# shipped in Releases):
cargo build --release --no-default-features --features boringssl
```

The BoringSSL build (`boring-sys`) compiles BoringSSL from source, so it needs a
C/C++ toolchain plus cmake, clang, Go, and (on x86_64) nasm/ninja:

```bash
# Debian/Ubuntu:
apt-get install -y build-essential cmake clang libclang-dev pkg-config \
                   git golang-go nasm ninja-build
```

Sluice **vendors a minimally-patched `pingora-core`** (a small set of documented,
marker-delimited functional fixes — see
[vendor/pingora-core/PATCH.md](vendor/pingora-core/PATCH.md)) applied via
`[patch.crates-io]`.

## License & credits

Licensed under the **Apache License 2.0** (see [LICENSE](LICENSE)).

Sluice is built on **[Cloudflare Pingora](https://github.com/cloudflare/pingora)**
— it uses Pingora's async proxy/connection framework and vendors a
minimally-patched `pingora-core`. Thanks to the Pingora team.
