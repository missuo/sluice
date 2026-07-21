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
  is rejected and the running config is kept (never takes the proxy down).
- Host-routed **sites**, then **path-routed `location` blocks** (prefix or
  `~regex`, first match wins) — nginx-style routing to different backends per path.
- **Load-balanced upstream pools**: `upstream { server …; server …; balance … }`
  with **round-robin / random / ip-hash** selection and connect-failure
  **failover** to the next member. **Health checks**: passive by default (skip a
  backend for 10s after a failed connect) and optional **active** probing
  (`health-check { path … interval-secs … }`, like Caddy) that takes an
  unhealthy-but-reachable backend out of rotation proactively.
- **Response cache** (`cache { ttl-secs … }`, backed by `pingora-cache`): in-memory
  LRU with a thundering-herd lock; honors the origin's `Cache-Control` (never
  caches `no-store`/`private`/`Set-Cookie`) and applies the location TTL otherwise.
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
- **TLS** listeners (BoringSSL) + **:80 → https** redirect, all from config.
  A single `cert`/`key`, **dynamic SNI certs** (`tls cert-dir="…"`), or
  **auto-TLS via ACME/Let's Encrypt** (`tls acme=true` + an `acme {}` block,
  HTTP-01, like Caddy — for domains that resolve directly to the server with :80
  open; behind Cloudflare use an Origin CA cert instead). Certs hot-swap at
  runtime via the TLS callback — no restart. Auto-TLS is **verified end-to-end
  against live Let's Encrypt** (staging and production): a browser-trusted cert
  issues over HTTP-01 with zero manual steps and is served by SNI at runtime.
- **HTTPS upstreams** (`upstream "https://api.openai.com"`): TLS + SNI + cert
  verification, and Host rewritten to the upstream host — reverse-proxy external
  APIs (OpenAI/S3). SSE streaming and WebSocket upgrades pass through unbuffered.
- Trusted **client IP** from a configurable header (e.g. `CF-Connecting-IP`),
  dropping the spoofable client XFF chain.
- Migration **host aliasing** (`staging-<sub>` behaves like `<sub>`).
- **Per-site rate limiting** (token bucket per client IP) and **`cloudflare-only`**
  access (403 unless the peer is a Cloudflare edge IP).
- **GeoIP**: country from the `CF-IPCountry` header (free) + optional **MaxMind
  ASN/city** (`maxminddb`); enriches the access log per `log-fields`; country as a
  Prometheus label.
- **Prometheus** metrics + structured **access log**.
- Multi-core, graceful drain on SIGTERM, upstream keepalive pool.

Roadmap (see DESIGN.md): true zero-downtime binary upgrade (SIGQUIT fd-handoff),
config file-watch, upstream pools/health-checks, ACME.

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
