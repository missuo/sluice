---
name: deploy-sluice
description: Install, configure, and run sluice as an nginx/caddy replacement — a TLS-first edge proxy with automatic ACME HTTPS — on a Linux server via systemd.
---

# Deploy sluice on a Linux server

You are deploying **sluice**, a config-driven edge proxy on Pingora, to replace
nginx/caddy. This skill takes you from a bare Linux host to a running, hardened,
auto-HTTPS reverse proxy / static server. The install/systemd commands and the
**complete** configs (section 4 and reference recipes (a)–(d)) are ready to
copy-paste; reference recipes (e)–(m) are **fragments** to drop into a complete
config (they are labeled as such). Always finish with `sluice --check` before
deploying. The complete KDL directive reference and all recipes are in
[`reference/config.md`](reference/config.md) — consult it for anything not shown
here; do **not** invent directives that aren't in it.

## 1. What sluice is, and when to choose it

sluice terminates TLS and routes/regulates HTTP from a single KDL config (no
recompile per change). Choose it when you want:

- **Automatic HTTPS** (Let's Encrypt / ACME HTTP-01) with zero manual cert steps.
- **The lowest memory footprint** of the mainstream proxies (idle ~17–23 MiB RSS
  vs nginx ~63 MiB, caddy ~46 MiB; well under both under load).
- **A security-hardened edge** (privilege separation, fd-pinned symlink-free
  dirs, Slowloris/DoS timeouts, a declarative WAF, strict request parsing).

**Performance posture (be honest with the user).** High-level, from the project's
own fair benchmarking (sluice vs nginx 1.26 vs caddy 2.11, HTTPS/1.1 keepalive, on
an 8-core box; all with access logs off):

- **Reverse proxy:** sluice **beats caddy** (~1.8× its throughput at c=200) and is
  **~0.55× nginx** — behind nginx on raw throughput and CPU per request (~2.4×
  nginx CPU/req), but no longer far off.
- **Static files (small, hot cache):** **~0.8–0.87× nginx** and ~2.2× caddy, with
  P99 at/under nginx's — the hot-file cache + I/O optimization closed most of the
  gap. Large files (> 64 KiB, uncached) are ~0.5× nginx.
- **Memory:** the **lightest of the three** by a wide margin (idle ~17–23 MiB vs
  nginx ~63, caddy ~46).

Net: an excellent fit for TLS-terminating reverse-proxy / behind-CDN use where its
low RAM and hardening shine; nginx still wins raw throughput for a max-QPS,
static-heavy, directly-exposed edge. **Treat [`benchmarks/production-baseline.md`](../../benchmarks/production-baseline.md)
as the source of truth** and consult it for exact current figures. For a directly
exposed, high-concurrency proxy you can A/B-test `server { work-stealing false }`
(a few % more throughput / lower CPU at slightly worse tail latency).

**Recommend sluice for:** TLS-terminating reverse proxies, API gateways, and
edges behind a CDN (Cloudflare). **Prefer nginx for:** static-file-heavy sites or
a maximum-throughput direct edge with no CDN.

**Honest limitations** (see [`KNOWN_ISSUES.md`](../../KNOWN_ISSUES.md) for the
current, maintained list):

- **No HTTP/3 (QUIC).** Fine behind Cloudflare (which serves H3 to clients and
  uses H1/H2 to origin). Direct clients fall back to HTTP/2.
- **OpenSSL / BoringSSL only — no Rustls.** Release binaries statically link
  BoringSSL (self-contained, no system libssl needed).
- **Static serving is slower than nginx** (and, at last measurement, caddy) — see
  the benchmark baseline above.
- **No plaintext HTTP serving:** every listener must be TLS or a
  `redirect-to-https`. There is no `listen 80` plain-HTTP mode.

## 2. Install the release binary

Release assets are **raw binaries** (no archives) attached to GitHub Releases at
`github.com/missuo/sluice`, named per arch: `sluice-x86_64-linux`,
`sluice-aarch64-linux`. Pick by `uname -m`, install to `/usr/local/bin/sluice`
mode **0755** (it must be 0755 or `ExecStart` fails), and verify:

```bash
set -euo pipefail
case "$(uname -m)" in
  x86_64)        ASSET=sluice-x86_64-linux ;;
  aarch64|arm64) ASSET=sluice-aarch64-linux ;;
  *) echo "unsupported arch: $(uname -m)"; exit 1 ;;
esac
curl -fsSL -o /tmp/sluice "https://github.com/missuo/sluice/releases/latest/download/${ASSET}"
sudo install -o root -g root -m 0755 /tmp/sluice /usr/local/bin/sluice
sluice --version        # e.g. "sluice 0.0.1" — must exit 0
```

The binary is self-contained (BoringSSL statically linked); it needs only a
reasonably recent glibc from the build runner (Ubuntu 24.04 ≈ glibc 2.39).

## 3. Privilege separation + systemd (hardened unit)

**sluice refuses to run as root (uid 0).** It terminates TLS and parses
attacker-controlled input, so a flaw as root would be a full host compromise.
Run it under a dedicated user via the shipped hardened unit. (Escape hatch, only
if you truly must: `server { allow-root true }` or `SLUICE_ALLOW_ROOT=1` — do not
use this in production.)

Create the user, state dirs, and config dir. **Use real paths with no symlink
components** — the ACME (`acme cache-dir`), disk cache (`cache-store dir`), and
`file-server root` directories are fd-pinned and opened with `O_NOFOLLOW`; a
symlinked component makes them unusable. `/var/lib/sluice` and `/var/cache/sluice`
are safe real paths.

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin sluice || true
sudo install -o sluice -g sluice -m 0700 -d /var/lib/sluice/acme
sudo install -o sluice -g sluice -m 0700 -d /var/cache/sluice
sudo install -o root   -g root   -m 0755 -d /etc/sluice
```

Install the hardened unit from the repo (`examples/sluice.service`). If you're not
in the repo, fetch it from the **same release tag as the binary you installed**
(not the mutable `main` branch, which may have drifted from your binary) — for the
first release, `v0.0.1`:

```bash
TAG=v0.0.1   # must match the release your binary came from
curl -fsSL -o /tmp/sluice.service \
  "https://raw.githubusercontent.com/missuo/sluice/${TAG}/examples/sluice.service"
sudo install -o root -g root -m 0644 /tmp/sluice.service /etc/systemd/system/sluice.service
sudo systemctl daemon-reload
```

(If you *are* in a checkout of the matching tag, install it directly instead:
`sudo install -o root -g root -m 0644 examples/sluice.service /etc/systemd/system/sluice.service && sudo systemctl daemon-reload`.)

What the unit gives you (verify by reading `examples/sluice.service`):

- Runs as the dedicated **`User=sluice`**, not root.
- **`AmbientCapabilities=CAP_NET_BIND_SERVICE`** only — can bind `:80`/`:443`
  without root; everything else dropped (`CapabilityBoundingSet`).
- **`NoNewPrivileges=true`**, **`ProtectSystem=strict`** (RO `/usr`,`/etc`),
  `ProtectHome`, seccomp `SystemCallFilter=@system-service`, private tmp/devices.
- Writable state only under **`/var/lib/sluice`** (StateDirectory) and
  **`/var/cache/sluice`** (CacheDirectory); `/run/sluice` (0700) for the upgrade
  socket; `/etc/sluice` for config.
- `LimitNOFILE=65535` fd cap as a connection-exhaustion backstop.

Then write `/etc/sluice/sluice.kdl` (next section) and start it (section 5).

## 4. Write the config (KDL)

The config is one KDL file. See [`reference/config.md`](reference/config.md) for
the **complete** directive reference (every `server`/`site`/`location`/`listener`
directive, defaults, DoS presets) and recipes (a)–(m). The most common starting
points:

> **KDL syntax:** a `{` must be followed by a newline and each child node on its
> own line (properties like `tls cert="a" key="b"` stay on the node's line). Do
> not put a child node on the same line as `{`.

**Reverse proxy with auto-HTTPS** (`/etc/sluice/sluice.kdl`):

```kdl
acme {
    contact "admin@example.com"        // Let's Encrypt registration email
}
listener "0.0.0.0:80" {
    redirect-to-https true             // :80 → 301 https + ACME HTTP-01
}
listener "0.0.0.0:443" {
    http2 true
    tls acme=true
}
site "app.example.com" {
    acme true                          // opt this host into ACME
    hsts "max-age=31536000; includeSubDomains"
    upstream "127.0.0.1:8080"          // your backend (plaintext, Host preserved)
    max-body "25MiB"
}
```

**Static site with auto-HTTPS:**

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
    file-server {
        root "/var/www/example"        // real path, no symlink components
    }
}
```

**Behind Cloudflare** (trust CF's client-IP header, disable per-IP cap):

```kdl
server {
    max-conn-per-ip 0                  // MUST be 0 — all peers are CF IPs
}
client-ip {
    trusted-header "CF-Connecting-IP"
}
```
For CF-fronted hosts, use a **Cloudflare Origin CA cert** via
`tls cert="…" key="…"` (ACME HTTP-01 can't validate through CF's proxy).

Other recipes in `reference/config.md`: provided cert/key files (c), multi-SNI
`cert-dir` (d), load balancing + health checks (e), response cache incl. disk (f),
WAF + rate-limit + max-body (g), sub-filter (h), websockets (i), DoS knobs (j),
JSON logs (k), upstream-dns tuning (l), file-server cache TTL (m).

## 5. Validate, run, reload, upgrade

**Always validate before deploying** — a bad config must never take the proxy
down:

```bash
sudo -u sluice sluice --check -c /etc/sluice/sluice.kdl
# ok  → "…: ok — N site(s), M listener(s)"
# bad → non-zero exit, one error line per problem (see Troubleshooting)
```

Run `--check` as the `sluice` user so directory ownership/symlink checks are
meaningful.

**Start and enable:**

```bash
sudo systemctl enable --now sluice
sudo systemctl status sluice
journalctl -u sluice -f          # logs (access log + errors)
```

**Reload on config change (SIGHUP, fail-safe):**

```bash
sudo -u sluice sluice --check -c /etc/sluice/sluice.kdl && sudo systemctl reload sluice
```

- **Reloaded by SIGHUP** (take effect immediately): sites, routing, upstreams,
  WAF, rate limits, `deny`/redirects, per-request timeouts
  (`request-timeout-secs`, `downstream-read/write-timeout-secs`,
  `min-send-rate-bytes`, per-site `read-timeout-secs`), the upstream DNS
  **timeout/ttl/stale** knobs (`upstream-dns-timeout-secs`,
  `upstream-dns-ttl-secs`, `upstream-dns-stale-secs`), **`access-log-format`**,
  `hsts`/`defaults`, and **`cert-dir` certificate rotation** (re-read + atomically
  swapped; a malformed/half-rotated/empty dir is rejected, old certs kept).
- **Restart-only** (a SIGHUP that changes them is **rejected** and the old config
  is kept): the single `cert`/`key` files, listener topology, `cache-store`, the
  `acme` block, the set of `acme`-enabled hosts, and these startup-bound `server`
  settings — `threads`, `max-conn-per-ip`, `tls-handshake-timeout-secs`,
  `h2-idle-timeout-secs`, `h2-handshake-timeout-secs`,
  **`upstream-dns-max-concurrent`** (it sizes the startup DNS-resolver semaphore),
  `metrics-addr`, `upgrade-sock`, `grace-period-secs`, `graceful-shutdown-secs`,
  `upstream-keepalive-pool`, `allow-root`, `user`/`group`, `work-stealing`. For
  these, `systemctl restart sluice` instead.
- A bad edit is rejected and the running config stays live (never a downtime).
- **`systemctl reload` only confirms the signal was delivered, not that the
  reload was accepted.** After reloading, check the journal for the explicit
  outcome line: `sudo journalctl -u sluice -n 20 --no-pager` — look for
  `SIGHUP: reloaded …` (accepted) vs a `SIGHUP: reload rejected …` /
  `startup-only … setting(s) changed …` line (kept the old config; you changed a
  restart-only setting — restart instead).

### Deploying a new binary

**Production (recommended): `systemctl restart sluice`.** Install the new binary,
then let systemd restart the supervised service:

```bash
sudo install -o root -g root -m 0755 /tmp/sluice /usr/local/bin/sluice   # new binary
sudo -u sluice sluice --check -c /etc/sluice/sluice.kdl                  # validate first
sudo systemctl restart sluice
```
This drops in-flight connections briefly (a fast restart), is fully supervised by
systemd (sandbox + `Restart=on-failure` intact), and is the simplest safe path.

**Advanced / experimental — true zero-downtime `-u` fd handoff.** Pingora can hand
the listening sockets to a replacement process so no connections drop, but this is
**not a simple one-liner and is not yet wired for systemd supervision** — treat it
as experimental:

- It requires an `upgrade-sock` in a service-owned `0700` dir (sluice refuses `-u`
  otherwise — squatting hardening):
  ```kdl
  server {
      upgrade-sock "/run/sluice/upgrade.sock"   // /run/sluice is 0700 (RuntimeDirectory)
  }
  ```
- The `-u` process **blocks in bootstrap** until it receives the listening FDs; the
  OLD process only transfers them **after it is sent `SIGQUIT`** (graceful-drain
  quit). So the two must overlap: start the new `-u` process, wait for it to bind
  the upgrade socket, then `SIGQUIT` the old `MAINPID` — e.g.
  `sudo kill -QUIT "$(systemctl show -p MainPID --value sluice)"` — so it drains
  and exits while the new process takes over.
- **Caveat:** launching `-u` manually escapes the systemd unit — after the old
  `MAINPID` exits, systemd does **not** adopt the manually started process, so the
  live proxy loses the unit's sandbox and `Restart=` supervision. There is no
  tested systemd-integrated handoff yet. Have a rollback ready (re-`systemctl
  start sluice` on the old/known-good binary) and bound the wait with a timeout.

Unless you have validated a supervised handoff, use `systemctl restart` in
production.

## 6. Migrating from nginx / caddy

| nginx / caddy | sluice |
|---------------|--------|
| `server { server_name x; }` / caddy site block | `site "x" { … }` (routes by exact HTTP `Host`; `cert-dir` cert selection is separately by TLS SNI) |
| `location /p { … }` | `location "/p" { … }` (prefix) or `location "~regex" { … }` |
| `proxy_pass http://127.0.0.1:8080;` | `upstream "127.0.0.1:8080"` |
| `proxy_pass https://api.example.com;` | `upstream "https://api.example.com"` (TLS+SNI+verify) |
| `upstream pool { server …; }` + `least_conn`/`ip_hash` | `upstream { server …; balance "least-conn"\|"ip-hash"\|"ketama" }` |
| `ssl_certificate` / `ssl_certificate_key` | `tls cert="…" key="…"` |
| caddy auto-HTTPS / certbot | `tls acme=true` + `acme { contact … }` + site `acme true` |
| `return 301 https://…` | `listener :80 { redirect-to-https true }` |
| `rewrite`/`return` redirects | `redirect match="regex" target="…{uri}…" status=301` |
| `deny` / `location ~ … { return 403; }` | `deny "regex"` / `waf { block … }` |
| `limit_req` | `rate-limit rps=… burst=…` |
| `proxy_cache` | `cache { ttl-secs … }` (+ optional `cache-store { dir … }`) |
| `sub_filter` | `sub-filter from="…" to="…"` |
| `root /var/www; index index.html;` | `file-server { root "/var/www" index "index.html" }` |
| `client_max_body_size` | `max-body "size"` |
| `proxy_set_header Host …` | `upstream-host "name"` |
| HSTS `add_header` | `hsts "…"` (per-site or `defaults { hsts … }`) |

**Behavioral differences to watch:**

- **No plaintext HTTP** — you can't `listen 80` and serve; `:80` is only a
  redirector/ACME responder.
- **No implicit `alias`/host aliasing** — one `site` owns one canonical host and
  its own cache namespace (prevents cross-host cache poisoning). Add explicit
  `site` blocks for each hostname.
- **Symlink-free dirs** — docroots, cache, and ACME dirs must be real paths;
  symlink components are refused.
- **HTTPS upstream health checks** do a real TLS + HTTP status check (a backend
  with a broken/expired cert or 5xx health path is dropped from rotation).

## 7. Troubleshooting

- **Exits refusing root:** "refuses to run as root" — run under the systemd
  `sluice` user, not directly as root. (Last resort: `SLUICE_ALLOW_ROOT=1`.)
- **`cert file not found: /path`** — the `tls cert=`/`key=` path is wrong or the
  file isn't readable by the `sluice` user. Fix the path/permissions.
- **`… root not usable` / `component "x": Not a directory`** — a path (docroot,
  cache dir, ACME dir) has a **symlink component** or a missing/wrong-type parent.
  Use a real path like `/var/lib/sluice`, `/var/cache/sluice`, `/var/www/…`.
- **ACME cert never issues:** HTTP-01 needs the domain to resolve to this server
  with **port 80 reachable** and a `:80 { redirect-to-https true }` listener
  present, and the host must **not** be proxied by an orange-cloud CDN. For
  Cloudflare-proxied hosts use a **CF Origin CA cert** (`tls cert=/key=`) instead.
  Test issuance safely first with `acme { staging true }`.
- **`--check` error format:** one line per problem, e.g.
  `config error in <file>:` then `listener "…": needs a `tls` block or `redirect-to-https true``,
  `site "x": …`. Fix each line, re-run `--check`, then `systemctl reload`.
- **Reload "took no effect" / rejected:** you changed a startup-only setting (see
  §5) — restart instead: `sudo systemctl restart sluice`.
- **Binary won't start / `ExecStart` fails:** ensure `/usr/local/bin/sluice` is
  mode **0755** and owned by root; re-run the `install -m 0755` step.
- **Metrics:** set `server { metrics-addr "127.0.0.1:9090" }` and scrape
  `http://127.0.0.1:9090/metrics` (Prometheus text).
