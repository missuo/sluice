# AGENTS.md

Guidance for AI coding agents working on **Sluice** — a config-driven edge proxy
built on [Pingora](https://github.com/cloudflare/pingora). Behaviour is declared
in a KDL config (`sluice.kdl`); there is no recompile per routing change. Read
`README.md` for the feature list and `DESIGN.md` for the rationale and milestones.

## Build, check, run

```bash
cargo build                      # dev build (OpenSSL, the default)
cargo build --release            # release (LTO, one codegen unit)
cargo build --release --no-default-features --features boringssl   # optional BoringSSL
cargo clippy --all-targets       # lint before committing
cargo bench                      # CPU hot-path micro-benchmarks (benches/hot.rs)
./target/release/sluice --check -c examples/sluice.kdl   # validate a config, exit
./target/release/sluice -c /etc/sluice/sluice.kdl        # run
./target/release/sluice -c cfg.kdl -u                    # zero-downtime upgrade (see below)
```

The crate is a **lib + thin bin** (see `lib.rs`): tests and benches link
`sluice::…`.

- **`cargo test`** runs the unit suite (declarative-schema + value-range
  rejection, `parse_size`, path normalization, query decode, Accept-Encoding
  cache-key isolation, active-health key scoping + no-CRLF probe, combined-PEM
  certs, ACME legacy migration + atomic secret write, `SecureDir` openat/symlink
  safety, disk-cache roundtrip/torn-entry + reaper file-boundary, cache-epoch
  tracking, static index validation, sub-filter carry-over, Ketama). It is NOT
  end-to-end — also validate with `--check` and manual testing against a local
  backend + a self-signed cert. Never test against a production/live host unless
  that is explicitly the task.
- **CI** (`.github/workflows/ci.yml`, all actions on Node 24): fmt,
  `clippy -D warnings`, build, test; a strict `--check` on the self-contained
  `examples/smoke.kdl` (must exit 0); an EXACT-error assertion on the full
  `examples/sluice.kdl` (every non-header line must be a known filesystem error —
  any new error/panic/schema line fails); a **BoringSSL** build+test job; and
  `cargo audit` (one documented ignore: RUSTSEC-2024-0437, see KNOWN_ISSUES.md).
- The **BoringSSL** feature (`boring-sys`) needs extra tools beyond a C toolchain
  on a fresh Debian: `git golang-go nasm ninja-build`.

## TLS backends (important)

Default is **OpenSSL** and it is the recommended backend (empirically fine behind
Cloudflare). **BoringSSL** is an optional static-link alternative. **Rustls is
NOT usable** — Pingora's rustls backend has no TLS certificate callback, so
dynamic SNI certs (`cert-dir`) and ACME can't select a cert. Don't "fix" the
rustls feature; it's a Pingora 0.8 limitation, not ours. HTTP/3 is likewise
blocked upstream (Pingora has no QUIC transport).

## Architecture / module map (`src/`)

- **`main.rs`** — arg parsing (`-c`, `--check`, `-u`), builds `ServerConf` from
  the config, wires listeners (static cert / `cert-dir` SNI callback / ACME /
  `:80` redirect), Prometheus service, and the SIGHUP reload thread.
- **`config.rs`** — the KDL parser and *all* validation. `Config::parse` does
  syntax + semantic checks and is the single gate for both `--check` and hot
  reload. Validation is a **declarative recursive schema** (`Spec` tree +
  `walk`): every node's positional args (count+type), properties (names+types,
  duplicates), and children (names+multiplicity, block-allowed) are checked at
  every level. Adding a directive means adding it to the `Spec` tree AND
  consuming it in the parse functions.
- **`proxy.rs`** — the `ProxyHttp` implementation (the request path) plus the
  `:80` `RedirectProxy`. Load-balancer selection, rate limiting, WAF, caching
  hooks, health state, and the access log all live here.
- **`certs.rs`** — dynamic SNI cert store served via Pingora's `TlsAccept`
  callback (used by `cert-dir` and ACME); hot-swappable via `ArcSwap`.
- **`acme.rs`** — ACME/Let's Encrypt HTTP-01 auto-TLS (background thread,
  `instant-acme` 0.8). Account is created once and persisted per environment.
  Each cert is ONE combined key+chain PEM installed by a single atomic rename;
  legacy `.crt`/`.key` pairs are served and migrated on startup. The cache dir
  is verified (real dir, owned, 0700) before any secret is written.
- **`diskcache.rs`** — a disk-backed `pingora_cache::Storage` implementation
  (Pingora only ships an in-memory `MemCache`). ONE sharded `.ent` file per
  entry (meta prefix + body), `O_EXCL` temp + single atomic rename, background
  reaper that only ever touches cache-owned filenames (`<32hex>.ent`, `.tmp.*`,
  legacy `.meta`/`.body`) — never a user's stray file.
- **`dirs.rs`** — `SecureDir`: a private directory PINNED by fd. `provision`
  (startup) creates 0700 / verifies owner / `fchmod`s the fd; `validate` is the
  read-only `--check` counterpart. All IO goes through its `openat`/`renameat`/
  `unlinkat` methods (single component, `O_NOFOLLOW`), so a swapped parent can't
  reroute a write. Used by both the ACME store and the disk cache.
- **`metrics.rs`** — Prometheus metric definitions.
- **`lib.rs` + `main.rs`** — the crate is a lib (`sluice::…`, all the modules
  above) plus a thin bin that wires listeners. The split exists so unit tests
  and `benches/hot.rs` (criterion micro-benchmarks of the CPU hot path) can link
  the internals. `cargo bench` runs the micro-benchmarks; `scripts/loadtest.sh`
  (needs `oha`) is the end-to-end P50/P99 harness.

### Config hot-reload model (do not break this)

The config lives in an `Arc<ArcSwap<Config>>`. Each request snapshots it **once**
in `Ctx.cfg` at `new_ctx()`, and every hook reads `ctx.cfg` (never `self.cfg`) so
a mid-flight SIGHUP reload can't change a request's view. Indices like `ctx.site`
/ `ctx.location` are only ever used against that same snapshot — keep it that way
(clone the `Arc` locally if you need to mutate `ctx` while reading config).

### Request flow (`proxy.rs`)

`request_filter` (client-IP → host routing → geo → cloudflare-only → rate-limit →
**normalize path** → WAF → site deny → redirects → location match → per-location
deny → static file OR pick LB backend → body-limit) → `request_cache_filter` /
`cache_key_callback` / `response_cache_filter` (caching) → `upstream_peer` (LB
select + health skip) → `fail_to_connect` (failover + mark down) →
`upstream_request_filter` (strip forwarding headers, set XFF/Host, drop
Accept-Encoding for sub-filter) → `response_filter` (HSTS, enable rewrite) →
`response_body_filter` (sub-filter) → `logging` (metrics + access log).

## KDL config gotchas

The parser uses **KDL v1 grammar** (`KdlDocument::parse_v1`):

- Bare `true`/`false` (not `#true`).
- Block children must be **newline-separated** — inline `{ a; b }` with `;`
  separators does **not** parse. Write multi-line blocks.
- A KDL string escapes `\`, so **regexes with a backslash need a raw string**:
  `match=r"\.php$"` — a plain `"\.php$"` is an invalid escape and fails to parse.
- Unknown top-level directives are rejected (add new ones to `TOP_LEVEL`).

## Security invariants (must not regress)

These were fixed after review; a change that reverts any of them is a bug:

- **Path normalization** (`normalize_path`) runs before WAF / `deny` / location
  matching, so `%2e`/`//`/`..` can't bypass them. Match on the normalized path.
- **Cache never crosses auth boundaries**: a request with `Authorization` or a
  `Cookie` is only cacheable if the origin says `Cache-Control: public`; responses
  with `Set-Cookie` or a non-`Accept-Encoding` `Vary` are never cached.
- **Client-IP is anti-spoofed**: the trusted header (e.g. `CF-Connecting-IP`) is
  honored only when the TCP peer is in `trusted_proxies`; no leftmost-XFF fallback.
- **Forwarding headers are stripped** upstream (`X-Forwarded-Host`, `X-Original-URL`,
  …) so a client can't poison origin URL generation / the cache.
- **Metric label cardinality** is bounded: unmatched Host → `-`, country is
  validated, only `country` is allowed as a geo metric label.
- Disk-cache `lookup` treats any IO/parse error as a miss — never fail a request.
- **Cache entries and ACME certs are single-file + one atomic rename** — never
  split state across two files whose renames can be separated by a crash.
- **Private dirs (ACME, disk cache) are fd-pinned** via `dirs::SecureDir`: the
  validated directory is held by fd and ALL IO is `*at`-relative + `O_NOFOLLOW`,
  so a swapped parent/shard symlink can't reroute a write or a delete. Never go
  back to path-based `open`/`rename`/`create_dir_all` for these — that reopens
  the cross-UID symlink exploit. Provisioning mutates (startup only); `--check`
  uses read-only `dirs::validate`.
- **Static files are served race-free**: descend from the docroot with
  `openat`/`O_NOFOLLOW` per component (rejecting `.`/`..`/separators); never
  `canonicalize`→`open` (TOCTOU), and take `Content-Length` from `fstat` on the
  streamed fd. Symlinks under the root are not followed. The `file-server index`
  is validated to be a single basename at config load.
- **Cache entries and ACME certs are single-file + one atomic rename** — never
  split state across two files whose renames can be separated by a crash. The
  cache key is namespaced by a per-site config epoch (a reload can't serve a
  retired upstream's entries); the reaper only touches cache-owned filenames.
- **The config schema is strict at every level** (`Spec` tree + `walk` in
  `config.rs`): args (count/type/int-range), props (names/types/dups), children
  (names/multiplicity/block-allowed). Never add a directive without its full
  Spec — a lenient node re-opens silent-typo config bugs. Header-bound config
  values (hsts, upstream-host, health path, redirect target, site host) reject
  control characters, and site hosts are lowercased + charset-checked.

## Conventions

- **Commits are authored `Vincent Yang <missuo@pm.me>`**, no `Co-Authored-By`
  trailer. Conventional-commit style (`feat:`, `fix:`, `docs:`, `security:`).
- **All repo docs and comments are in English.**
- Keep `README.md` (feature list + the nginx/Caddy comparison table), the example
  `examples/sluice.kdl`, and `DESIGN.md` in sync when adding a feature — the
  comparison table and roadmap have drifted before.
- When adding a config directive: parse + validate it in `config.rs`, consume it
  in `proxy.rs`/`main.rs`, document it in `examples/sluice.kdl` and `README.md`.

## Pingora specifics worth knowing

- `pingora::cache` is feature-gated in the facade — import cache types from the
  `pingora_cache` crate directly (that's why it's a direct dependency).
- Some Pingora `ProxyHttp` cache/body hooks are **sync** `fn` (e.g.
  `response_body_filter`, `cache_key_callback`) while others are `async`. Match
  the trait signature exactly (check `proxy_trait.rs`).
- The cache API is upstream-marked "experimental / volatile" — pin the pingora
  and pingora-cache versions together and re-verify after any bump.
- **Zero-downtime upgrade**: `-u` makes bootstrap acquire the listening sockets
  from the running process over `upgrade-sock`; then `SIGQUIT` the old process to
  drain and exit. Needs `upgrade-sock` configured.
