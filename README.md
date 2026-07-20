# Sluice

A config-driven edge proxy on [Pingora](https://github.com/cloudflare/pingora).
Routes and regulates HTTP traffic from a KDL config file — no recompile per change.

> A *sluice* is a gated channel that routes and regulates water flow.

See [DESIGN.md](DESIGN.md) for the full design. This is an early MVP (M0).

## What works today (M0)

- **KDL config** (`sluice.kdl`), nginx-like blocks, whitespace-insensitive.
- **`sluice --check`** — syntax (`line:col`) + semantic validation (unknown
  directives, missing/duplicate fields, bad regex, missing cert files).
- Host-routed **sites** → upstreams; **regex redirects** with `{uri}`/`{host}`;
  per-site **body limits**, **read timeouts**, **websocket** passthrough, **HSTS**.
- **TLS** listeners (BoringSSL) + **:80 → https** redirect, all from config.
- Trusted **client IP** from a configurable header (e.g. `CF-Connecting-IP`),
  dropping the spoofable client XFF chain.
- Migration **host aliasing** (`staging-<sub>` behaves like `<sub>`).
- **Prometheus** metrics + structured **access log** (incl. GeoIP country from
  the `CF-IPCountry` header).
- Multi-core, graceful drain on SIGTERM, upstream keepalive pool.

Not yet (see DESIGN.md milestones): hot reload (M1), MaxMind ASN/city (M2),
per-site rate limiting + `cloudflare-only` access (M3).

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
