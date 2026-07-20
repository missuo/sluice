# Sluice

A config-driven edge proxy on [Pingora](https://github.com/cloudflare/pingora).
Routes and regulates HTTP traffic from a KDL config file — no recompile per change.

> A *sluice* is a gated channel that routes and regulates water flow.

See [DESIGN.md](DESIGN.md) for the full design. Milestones M0–M3 are implemented.

## What works

- **KDL config** (`sluice.kdl`), nginx-like blocks, whitespace-insensitive.
- **`sluice --check`** — syntax (`line:col`) + semantic validation (unknown
  directives, missing/duplicate fields, bad regex, missing cert/mmdb files).
- **Hot reload on SIGHUP** — re-parses the file and atomically swaps; a bad edit
  is rejected and the running config is kept (never takes the proxy down).
- Host-routed **sites** → upstreams; **regex redirects** with `{uri}`/`{host}`;
  per-site **body limits**, **read timeouts**, **websocket** passthrough, **HSTS**.
- **Static file server** per site (`file-server { root … }`, index files,
  content-type by extension, path-traversal protection) — an alternative to `upstream`.
- **Path `deny`** rules (regex → 403), like nginx `deny`.
- **TLS** listeners (BoringSSL) + **:80 → https** redirect, all from config.
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

## Run

```bash
sluice --check -c examples/sluice.kdl     # validate
sluice -c /etc/sluice/sluice.kdl          # run
```

See [`examples/sluice.kdl`](examples/sluice.kdl) for a full annotated config.
