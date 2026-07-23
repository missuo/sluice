# sluice KDL configuration — complete reference + recipes

This reference is exhaustive and cross-checked against `src/config.rs` (the KDL
schema). Every directive below exists in the code. Do **not** invent others.

The config file is [KDL](https://kdl.dev). A node has an optional positional
**argument** (e.g. `site "example.com"`), optional **properties**
(`key=value`, e.g. `tls cert="..."`), and an optional `{ … }` **block** of child
nodes. Sizes accept suffixes: `B`, `KB`/`MB`/`GB` (SI) and `KiB`/`MiB`/`GiB`
(binary), e.g. `"32MiB"`.

**KDL formatting rule (important):** a `{` must be followed by a newline, each
child node goes on **its own line**, and `}` is on its own line. Do NOT put a
child node on the same line as `{`. Node *properties* (`key=value`) DO go on the
node's own line. So `tls cert="a" key="b"` is one line (two properties), but a
block like `listener` opens with `{`, then children each on a new line:

```kdl
listener "0.0.0.0:443" {
    http2 true
    tls acme=true
}
```

Sluice **cannot serve plaintext HTTP** — every `listener` must have a `tls` block
**or** `redirect-to-https true`. Plan for TLS (ACME or cert files) up front.

---

## Top-level nodes

| Node | Repeat | Purpose |
|------|--------|---------|
| `server { … }` | once | Process-wide settings, timeouts, DoS knobs. |
| `client-ip { … }` | once | Trusted client-IP header + trusted proxy CIDRs. |
| `geoip { … }` | once | Country/ASN/city enrichment (MaxMind + CF header). |
| `acme { … }` | once | Automatic TLS via Let's Encrypt (HTTP-01). |
| `cache-store { … }` | once | Disk-backed response cache (default is in-memory). |
| `defaults { … }` | once | Default HSTS header + unmatched-Host status. |
| `listener "addr" { … }` | many | A bound socket (`:443` TLS or `:80` redirect). (The Prometheus endpoint binds via `server { metrics-addr … }`, not a listener node.) |
| `site "host" { … }` | many | One vhost. Routing selects the site by the **exact HTTP `Host`/authority**; `cert-dir` certificate selection is a *separate* decision by **case-insensitive TLS SNI** (Host need not equal SNI). |

---

## `server { … }`

All children appear at most once. Defaults shown.

| Directive | Type | Default | Meaning |
|-----------|------|---------|---------|
| `threads` | int ≥0 | `0` | Worker threads; `0` = all cores. |
| `metrics-addr` | string | (off) | Bind a Prometheus `/metrics` endpoint, e.g. `"127.0.0.1:9090"`. |
| `access-log-format` | `"off"`\|`"text"`\|`"json"` | `"text"` | Access-log line format. `json` = one structured object per request. `off` skips per-request log assembly entirely (lowest overhead; use it when a separate access log isn't needed). |
| `grace-period-secs` | int ≥0 | `30` | Graceful-shutdown grace period. |
| `graceful-shutdown-secs` | int ≥0 | `300` | Max drain time on shutdown/upgrade. |
| `upstream-keepalive-pool` | int ≥0 | `256` | Upstream keepalive connection pool size. |
| `upgrade-sock` | string | (off) | Unix socket for zero-downtime binary upgrade (`-u`). Parent dir must be service-owned `0700`. |
| `allow-root` | bool | `false` | Allow running as uid 0 (discouraged). Same as `SLUICE_ALLOW_ROOT=1`. |
| `user` / `group` | string | (none) | **Reserved / ineffective in the current binary.** They are only applied when Pingora daemonizes, and the sluice CLI never daemonizes (systemd runs it in the foreground), so they do **not** drop privileges. Use the systemd unit's `User=`/`Group=` for privilege separation. |
| `downstream-read-timeout-secs` | int ≥1 | `15` | Per-read receive timeout (Slowloris). |
| `request-timeout-secs` | int ≥1 | `30` | Absolute wall-clock deadline to receive a full request body. |
| `downstream-write-timeout-secs` | int ≥0 | `60` | Per-write response timeout (slow-read client). `0` disables. |
| `min-send-rate-bytes` | int ≥0 | `0` | Minimum downstream send rate (bytes/s); `0` = off. Adaptive H1 anti-slow-read. |
| `max-conn-per-ip` | int ≥0 | `0` | Max concurrent connections per client IP; `0` = off. **Leave 0 behind Cloudflare** (all peers share CF IPs). |
| `tls-handshake-timeout-secs` | int ≥1 | `10` | Downstream TLS handshake deadline (partial-ClientHello Slowloris). |
| `h2-idle-timeout-secs` | int ≥0 | `60` | Close an idle downstream HTTP/2 connection (no active streams). `0` disables. |
| `h2-handshake-timeout-secs` | int ≥1 | `10` | Deadline for the HTTP/2 connection preface. |
| `upstream-dns-timeout-secs` | int ≥1 | `5` | Deadline to resolve an upstream hostname. |
| `upstream-dns-ttl-secs` | int ≥1 | `30` | Fresh TTL for a cached upstream DNS answer. |
| `upstream-dns-stale-secs` | int ≥0 | `300` | Serve a stale DNS answer this long while the resolver is failing; `0` = never. |
| `upstream-dns-max-concurrent` | int ≥1 | `8` | Cap on concurrent blocking resolutions. |
| `work-stealing` | bool | `true` | **Experimental.** Tokio work-stealing across worker threads. `false` pins each connection to its starting worker; on a directly-exposed, high-concurrency proxy this can trade a few % more throughput and lower CPU/request for slightly worse tail latency. Leave `true` unless you A/B-measure a win. |

> **Reloadable on SIGHUP** (read from the per-request config snapshot):
> `request-timeout-secs`, `downstream-read-timeout-secs`,
> `downstream-write-timeout-secs`, `min-send-rate-bytes`,
> `upstream-dns-timeout-secs`, `upstream-dns-ttl-secs`,
> `upstream-dns-stale-secs`, `access-log-format`, plus all site/location
> routing, WAF, cache policy, and `cert-dir` certificate rotation.
>
> **Startup-bound — require a restart:** `threads`, `metrics-addr`,
> `grace-period-secs`, `graceful-shutdown-secs`, `upstream-keepalive-pool`,
> `upgrade-sock`, `allow-root`, `user`/`group`, `max-conn-per-ip`,
> `tls-handshake-timeout-secs`, `h2-idle-timeout-secs`,
> `h2-handshake-timeout-secs`, `upstream-dns-max-concurrent`,
> `work-stealing`, the disk cache, and the `acme` block. A SIGHUP that
> changes any of them is **rejected** and the old config is kept (check the
> journal for the reject line).

### DoS-hardening knob presets

**Directly exposed (no CDN in front):**
```kdl
server {
    max-conn-per-ip 100
    tls-handshake-timeout-secs 10
    h2-handshake-timeout-secs 10
    h2-idle-timeout-secs 60
    downstream-read-timeout-secs 15
    downstream-write-timeout-secs 60
    request-timeout-secs 30
    min-send-rate-bytes 1024
}
```

**Behind Cloudflare (all peers are CF edge IPs):**
```kdl
server {
    max-conn-per-ip 0
    tls-handshake-timeout-secs 10
    h2-handshake-timeout-secs 10
    h2-idle-timeout-secs 60
    request-timeout-secs 30
}
client-ip {
    trusted-header "CF-Connecting-IP"
}
```

---

## `client-ip { … }`

Anti-spoofing: only honor the client-IP header when the TCP peer is a trusted
proxy.

| Directive | Type | Meaning |
|-----------|------|---------|
| `trusted-header` | string | Header carrying the real client IP (e.g. `"CF-Connecting-IP"`). |
| `trusted-proxies` | strings | CIDRs allowed to set that header. Default = Cloudflare ranges. |

```kdl
client-ip {
    trusted-header "CF-Connecting-IP"
    trusted-proxies "173.245.48.0/20" "103.21.244.0/22"
}
```

---

## `geoip { … }`

| Directive | Type | Meaning |
|-----------|------|---------|
| `enabled` | bool | Turn geoip on/off. |
| `country-header` | string | Header with country code (e.g. `"CF-IPCountry"`, free behind CF). |
| `mmdb-asn` | string | Path to a MaxMind ASN `.mmdb`. |
| `mmdb-city` | string | Path to a MaxMind City `.mmdb`. |
| `log-fields` | strings | Any of `"country"` `"asn"` `"asn-org"` `"city"` to add to the access log. |
| `metric-labels` | strings | `"country"` only — adds a Prometheus country label (low cardinality). |

```kdl
geoip {
    country-header "CF-IPCountry"
    mmdb-asn "/var/lib/sluice/GeoLite2-ASN.mmdb"
    log-fields "country" "asn"
    metric-labels "country"
}
```

---

## `acme { … }` — automatic TLS (Let's Encrypt, HTTP-01)

| Directive | Type | Default | Meaning |
|-----------|------|---------|---------|
| `enabled` | bool | `true` | Enable the ACME worker. |
| `contact` | string | (required) | Registration email, e.g. `"admin@example.com"`. |
| `staging` | bool | `false` | Use the LE staging CA (untrusted, high rate limits) for testing. |
| `cache-dir` | string | `/var/lib/sluice/acme` | Where account keys + certs are stored. **Must be a real path with no symlink components** (fd-pinned, 0700, owned by the run user). |

```kdl
acme {
    contact "admin@example.com"
    // staging true          // uncomment while testing issuance
}
```

ACME requires **all** of: this `acme { }` block, a `site` with `acme true`, a
`:443` listener with `tls acme=true`, **and** a `:80` listener with
`redirect-to-https true` (HTTP-01 challenges are answered there). The domain must
resolve to this server with port 80 reachable and **not** proxied by an
orange-cloud CDN (Cloudflare proxying breaks HTTP-01 — use a CF Origin CA cert or
DNS-01 for those hosts). ACME is **opt-in per site** so CF-fronted hosts aren't
enrolled and left failing forever.

---

## `cache-store { … }` — disk response cache

Omit for the default in-memory LRU. When present, cached responses persist to
disk (survive restarts, hold far more than RAM).

| Directive | Type | Default | Meaning |
|-----------|------|---------|---------|
| `dir` | string | (required) | Cache directory. **Real path, no symlinks** (fd-pinned). |
| `max-size` | size | `10GiB` | Soft cap on total on-disk size (reaper evicts oldest). |
| `max-files` | int | `1000000` | Cap on cache file count (inode-exhaustion guard). |
| `min-free` | size | `1GiB` | Keep at least this much filesystem free. |

```kdl
cache-store {
    dir "/var/cache/sluice"
    max-size "20GiB"
    min-free "2GiB"
}
```

---

## `defaults { … }`

| Directive | Type | Default | Meaning |
|-----------|------|---------|---------|
| `hsts` | string | (none) | Default `Strict-Transport-Security` value for all sites (override per-site with `hsts`). |
| `unknown-host` | status 100–599 | `404` | Status returned when the request `Host` matches no `site`. |

```kdl
defaults {
    hsts "max-age=31536000; includeSubDomains"
    unknown-host 404
}
```

---

## `listener "addr" { … }`

The argument is the bind address (`"0.0.0.0:443"`, `"[::]:80"`, `"127.0.0.1:443"`).

| Directive | Type | Default | Meaning |
|-----------|------|---------|---------|
| `http2` | bool | `false` | Enable HTTP/2 (ALPN h2) on this TLS listener. |
| `redirect-to-https` | bool | `false` | Make this a plain `:80` → 301 `https://` redirector (and ACME HTTP-01 responder). Mutually exclusive with `tls`. |
| `tls { … }` | props | — | TLS config (see below). A listener needs `tls` **or** `redirect-to-https true`. |

### `tls` node properties (choose exactly one cert source)

| Property | Meaning |
|----------|---------|
| `cert="path" key="path"` | Static PEM cert + private key (read once at startup; rotating them needs a restart). |
| `cert-dir="path"` | Directory of `<host>.crt` + `<host>.key` pairs, selected by SNI. **Hot-reloads on SIGHUP.** |
| `acme=true` | Auto-TLS via the `acme { }` block. Cannot combine with `cert`/`key`/`cert-dir`. |

```kdl
listener "0.0.0.0:80" {
    redirect-to-https true
}
listener "0.0.0.0:443" {
    http2 true
    tls acme=true
}
```

---

## `site "host" { … }`

The argument is the exact HTTP `Host`/authority this vhost answers (routing is by
Host, not TLS SNI — with `cert-dir`, certificate selection is a separate,
case-insensitive SNI decision). One `site` per hostname; use `cert-dir` for many
hostnames' certificates. Children:

| Directive | Type | Meaning |
|-----------|------|---------|
| `upstream …` | shorthand or block | Reverse-proxy backend(s). See **Upstreams**. |
| `file-server { … }` | block | Serve static files. See **file-server**. |
| `location "match" { … }` | many | Path-routed sub-blocks (see below). |
| `deny "regex"` | many | Return 403 for paths matching this regex (nginx `deny`). |
| `redirect match="regex" target="…" status=<int>` | many | Regex redirect; `{uri}`/`{host}` placeholders in `target`. |
| `rate-limit rps=<num> burst=<num>` | once | Token-bucket per client IP. `rps`/`burst` accept floats. |
| `access cloudflare-only=true` | once | 403 unless the peer is a Cloudflare edge IP. |
| `waf { … }` | once | Declarative WAF (see **WAF**). |
| `hsts "value"` | once | Per-site `Strict-Transport-Security`. |
| `acme true` | once | Provision an ACME cert for this host (opt-in). |
| `websocket true` | once | Allow WebSocket upgrades to the upstream. |
| `max-body "size"` | once | Reject request bodies over this size (streamed → **413**). |
| `read-timeout-secs <int>` | once | Upstream read timeout for this site. |
| `upstream-host "name"` | once | Override the `Host` sent upstream. |
| `upstream-verify true\|false` | once | Override upstream TLS certificate verification. |
| `sub-filter from="…" to="…"` | many | Streaming response body find/replace (nginx `sub_filter`). |
| `cache { … }` | once | Response caching for this site (see **cache**). |

### `location "match" { … }`

Matched in declaration order, first match wins. The matcher is a **prefix**
(`location "/api/"`) or a **regex** with a leading `~` (`location r"~\.php$"` —
use a KDL raw string `r"…"` for backslashes). Children: `upstream`,
`file-server`, `websocket`, `max-body`, `read-timeout-secs`, `deny` (many),
`cache`, `sub-filter` (many), `upstream-host`, `upstream-verify`.

---

## Upstreams

Two forms (don't mix them in one `upstream`):

```kdl
// Shorthand — plaintext backend; client Host preserved.
upstream "127.0.0.1:8080"
```
```kdl
// Shorthand — HTTPS backend: TLS + SNI + cert verification, Host rewritten to the host.
upstream "https://api.openai.com"
```
```kdl
// Block form — a load-balanced pool.
upstream {
    server "10.0.0.1:8080"
    server "10.0.0.2:8080" weight=2
    balance "ketama"
    health-check {
        path "/healthz"
        interval-secs 5
        timeout-secs 2
        healthy 2
        unhealthy 3
        expect-status 200
    }
}
```

**Balance policies:** `round-robin` (default), `random`, `ip-hash` (sticky, plain
`hash(ip)%N`, **weights ignored**), `ketama` (weighted **consistent** hashing —
use this when weights matter or the pool changes), `least-conn` (fewest in-flight,
weighted). `weight` is `1..=1000`. Connect-failure failover advances to the next
member.

**Health checks:** passive by default (skip a backend ~10 s after a failed
connect). An active `health-check` block probes each backend. For a **plaintext**
backend it does an HTTP `GET path`; for an **HTTPS** backend with a `path` it now
performs a **verified TLS handshake + HTTP status** check (a backend with a
broken/expired cert or a bad `path` status is taken out of rotation), reusing the
site's SNI and verify policy. `expect-status N` accepts exactly `N`; the default
accepts `200`–`399`. Omit `path` for a TCP-connect check.

---

## `file-server { … }`

| Directive | Type | Default | Meaning |
|-----------|------|---------|---------|
| `root` | string | (required) | Docroot. **Real path, no symlink components** (fd-pinned, `O_NOFOLLOW`). |
| `index` | string | `index.html` | Index file for directory requests (plain basename). |
| `cache-ttl-secs` | int ≥0 | `1` | Hot-file cache: serve a cached small file (≤64 KiB) up to this long before a secure re-open re-validates. `0` disables the content cache. |

```kdl
file-server {
    root "/var/www/example"
    index "index.html"
    cache-ttl-secs 5
}
```

Symlinks under the docroot are **refused** (never followed). `..`/dot segments
are **canonicalized before routing** (`/a/../secret` → `/secret`) and **cannot
escape** the fd-pinned docroot — so there is no traversal escape, though the
resulting canonical path may serve an in-docroot file, 404, or be denied by a
`deny`/WAF rule (it is not categorically a 403). Large files stream; small files
are cached in memory.

---

## `cache { … }` (response cache, per-site or per-location)

| Directive | Type | Default | Meaning |
|-----------|------|---------|---------|
| `ttl-secs` | int ≥0 | `60` | Cache successful responses this long. `0` = no caching. **A bare `cache {}` still caches for 60 s** — set `ttl-secs 0` if you don't want an implicit lifetime. |
| `max-object` | size | `8MiB` | Don't cache responses larger than this. |

```kdl
cache {
    ttl-secs 300
    max-object "16MiB"
}
```

Both fields have defaults: a `cache {}` with no children (or a partial one)
caches for **60 s** with an **8 MiB** object ceiling. Honors the origin's
`Cache-Control` (never caches `no-store`/`private`/`Set-Cookie`). Uses the
in-memory LRU unless a top-level `cache-store { }` selects the disk backend.

---

## WAF, redirects, rate limiting

```kdl
site "example.com" {
    // Block by regex on a request field.
    waf {
        block field="path" match=r"(?i)\.(env|git)" status=403
        block field="query" match=r"(?i)union\s+select" status=403
        block field="header:user-agent" match="(?i)sqlmap" status=403
    }

    // Regex → redirect. {uri} and {host} expand in target.
    redirect match=r"^/old/(.*)$" target="https://{host}/new" status=301

    // nginx `deny` — 403 for matching paths.
    deny r"^/wp-admin"

    // Token-bucket rate limit per client IP.
    rate-limit rps=20 burst=40

    // Cloudflare-only access (403 for non-CF peers).
    access cloudflare-only=true

    max-body "10MiB"
    upstream "127.0.0.1:8080"
}
```

`waf` `field` values: `path`, `query`, `method`, `user-agent` (shorthand), or
`header:<name>` (any header, name must be a valid HTTP token). The matcher runs a
linear-time Rust regex on the normalized value; use KDL raw strings `r"…"` for
backslashes.

---

## Recipes

**Recipes (a)–(d) are COMPLETE, standalone configs** — copy one into
`/etc/sluice/sluice.kdl` and it passes `sluice --check` (create any referenced
docroot/cert/cache dirs first).

**Recipes (e)–(m) are FRAGMENTS**, not standalone configs. Each shows just the
`site {}` (or `server {}`/`cache-store {}`) block being illustrated; a `site`
alone has no listener, and `site … { acme true }` additionally needs the
`acme {}` block plus the `:80` redirect and `:443 tls acme=true` listeners. To
use a fragment, drop it into the scaffold from recipe (a)/(b) — i.e. keep that
recipe's `acme {}` + two `listener` blocks and replace/extend its `site` with the
fragment's `site`. Always finish with `sluice --check` before deploying.

### (a) Static site over auto-HTTPS (ACME) with HTTP→HTTPS redirect

```kdl
acme {
    contact "admin@example.com"
}
listener "0.0.0.0:80" {
    redirect-to-https true
}
listener "0.0.0.0:443" {
    http2 true
    tls acme=true
}
site "example.com" {
    acme true
    hsts "max-age=31536000; includeSubDomains"
    file-server {
        root "/var/www/example"
    }
}
```

### (b) Reverse proxy to a backend, TLS via ACME

```kdl
acme {
    contact "admin@example.com"
}
listener "0.0.0.0:80" {
    redirect-to-https true
}
listener "0.0.0.0:443" {
    http2 true
    tls acme=true
}
site "app.example.com" {
    acme true
    upstream "127.0.0.1:8080"
    max-body "25MiB"
}
```

### (c) TLS via provided cert/key files

```kdl
listener "0.0.0.0:80" {
    redirect-to-https true
}
listener "0.0.0.0:443" {
    http2 true
    tls cert="/etc/sluice/tls/fullchain.pem" key="/etc/sluice/tls/privkey.pem"
}
site "example.com" {
    upstream "127.0.0.1:8080"
}
```

### (d) Multiple sites (SNI) with a cert-dir

`/etc/sluice/certs/` holds `a.example.com.crt` + `a.example.com.key`,
`b.example.com.crt` + `b.example.com.key`, … (hot-reloaded on SIGHUP).

```kdl
listener "0.0.0.0:80" {
    redirect-to-https true
}
listener "0.0.0.0:443" {
    http2 true
    tls cert-dir="/etc/sluice/certs"
}
site "a.example.com" {
    upstream "127.0.0.1:8001"
}
site "b.example.com" {
    file-server {
        root "/var/www/b"
    }
}
```

### (e) Load balancing + health checks

```kdl
site "api.example.com" {
    acme true
    upstream {
        server "10.0.0.1:8080" weight=2
        server "10.0.0.2:8080" weight=1
        balance "ketama"
        health-check {
            path "/healthz"
            interval-secs 5
            timeout-secs 2
            healthy 2
            unhealthy 3
            expect-status 200
        }
    }
}
```

HTTPS pool with verified health:
```kdl
site "gw.example.com" {
    acme true
    upstream {
        server "https://backend-1.internal"
        server "https://backend-2.internal"
        balance "least-conn"
        health-check {
            path "/health"
            expect-status 200
        }
    }
}
```

### (f) Response cache (memory, then disk)

```kdl
cache-store {
    dir "/var/cache/sluice"
    max-size "20GiB"
    min-free "2GiB"
}
site "cdn.example.com" {
    acme true
    upstream "127.0.0.1:8080"
    cache {
        ttl-secs 300
        max-object "16MiB"
    }
}
```

### (g) WAF + rate limiting + max-body

```kdl
site "example.com" {
    acme true
    max-body "8MiB"
    rate-limit rps=50 burst=100
    waf {
        block field="path" match=r"(?i)\.(env|git|htaccess)$" status=403
        block field="query" match=r"(?i)(union\s+select|<script)" status=403
    }
    deny r"^/wp-admin"
    upstream "127.0.0.1:8080"
}
```

### (h) sub-filter response rewrite

```kdl
site "example.com" {
    acme true
    sub-filter from="http://old.example.com" to="https://example.com"
    upstream "127.0.0.1:8080"
}
```

### (i) WebSockets

```kdl
site "ws.example.com" {
    acme true
    websocket true
    upstream "127.0.0.1:8080"
}
```

### (j) Security / DoS knobs — see the two presets under `server` above.

### (k) JSON access logging

```kdl
server {
    access-log-format "json"
}
```
Emits one JSON object per request (status, latency, bytes, client, host,
upstream, protocol, method, geo, bounded error), path only (no query/credentials).

### (l) Upstream DNS tuning (hostname backends)

```kdl
server {
    upstream-dns-timeout-secs 5
    upstream-dns-ttl-secs 30
    upstream-dns-stale-secs 300
    upstream-dns-max-concurrent 8
}
```

### (m) Static file-server cache TTL

```kdl
site "docs.example.com" {
    acme true
    file-server {
        root "/var/www/docs"
        index "index.html"
        cache-ttl-secs 5
    }
}
```
