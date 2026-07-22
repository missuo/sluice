# Vendored `pingora-core` (patched)

This is an **exact copy of `pingora-core` 0.8.1** from crates.io (the latest
published release — there is no newer version to bump to) with a small set of
**minimal, documented** functional changes, applied via `[patch.crates-io]` in
the workspace `Cargo.toml`.

The upstream `examples/` directory and its `[[example]]` manifest targets were
removed (this crate is vendored only as a library dependency). The only other
manifest change is the **`prometheus` dependency bump `0.13` → `0.14`** (see
below); nothing else in the manifest changed. Every source change is delimited by
`// ---- sluice vendored patch ... ----` markers.

## Manifest change — `prometheus` 0.13 → 0.14 (RUSTSEC-2024-0437)

`[dependencies.prometheus]` was bumped from `0.13` to `0.14` to match the
workspace's direct dependency. Prometheus 0.14 pulls `protobuf 3.7.x` instead of
`protobuf 2.28`, which removes [RUSTSEC-2024-0437](https://rustsec.org/advisories/RUSTSEC-2024-0437.html)
(uncontrolled recursion in `protobuf` 2.x) from the dependency graph. This crate
only uses the small, stable Prometheus API (`prometheus::gather()` and
`Encoder`/`TextEncoder` in `src/apps/prometheus_http_app.rs`), which is unchanged
across the bump, so **no source patch was required** — the change is manifest-only
and the `/metrics` app compiles and serves valid Prometheus text as before.

## Patch 1 — `HEAD` + interim `1xx` ends the response early

`src/protocols/http/v1/client.rs`, `HttpSession::init_body_reader`.

Upstream applied the **HEAD → zero-length body** rule *before* checking whether
the response status was **informational (1xx)**. As a result, a `HEAD` request
whose origin sent an interim `1xx` (e.g. `103 Early Hints`) before the final
response had its body reader initialized to `Content-Length: 0` on the **1xx**,
which marked that interim task as end-of-stream. `pingora-proxy`'s upstream loop
then set `response_done = true` and finished the request **without ever reading
the final response**. The fix reorders the checks so informational-status
handling runs **first** (a `1xx` other than `101` returns without initializing
the body reader, regardless of method), so the HEAD rule applies only to the
genuinely final response. Regression test: `tests/head_early_hints.rs`.

## Patch 2 — strict `Transfer-Encoding` validation (request smuggling)

`src/protocols/http/v1/common.rs` (new `validate_request_transfer_encoding` /
`validate_response_transfer_encoding` / `te_tokens`),
`src/protocols/http/v1/server.rs` (`validate_request`),
`src/protocols/http/v1/client.rs` (`validate_response`).

Upstream only checked that the **last token of the last** `Transfer-Encoding`
field was `chunked`, accepting the smuggling vector `Transfer-Encoding: chunked,
chunked` (and repeated `Transfer-Encoding` fields). A downstream that dechunks
once while an upstream honours both advertised codings then disagree on the
message boundary, bypassing routing/WAF/deny. The patch validates **every token
of every** TE field: a REQUEST must carry exactly one `chunked` coding (a proxy
that does not decode arbitrary transfer codings must not accept anything else); a
RESPONSE may carry `chunked` at most once and only as the final coding. Empty
tokens are rejected. Regression tests: `tests/te_smuggling.rs`.

## Patch 3 — H1 header buffer cap + non-resettable header deadline (Slowloris)

`src/protocols/http/v1/common.rs` (`MAX_HEADER_SIZE`),
`src/protocols/http/v1/server.rs` (`read_request`).

Upstream capped the first-header buffer at ~1 MiB and wrapped each individual read
in a resettable timeout, letting a client hold ~1 MiB per socket indefinitely by
dripping one byte per interval. A new `MAX_REQUEST_HEADER_SIZE` = **16 KiB** caps
the client-controlled REQUEST header in `read_request` (the original
`MAX_HEADER_SIZE` = ~1 MiB is kept for the origin-controlled RESPONSE parser, so
large legit origin headers still work). The cap is enforced against the **parsed
header-section length**, not the socket read amount: on a complete parse the
returned header length `s` is rejected when it exceeds the cap, and on a partial
parse the still-incomplete buffer is rejected as soon as it exceeds the cap. (The
earlier form checked the running `already_read` count *before* each read and never
re-checked on a complete parse, so a single read that produced a complete header
of up to ~2× the cap — or a small header coalesced with a large preread body —
slipped through; the parsed-length check makes the boundary exact and excludes
legitimate preread body bytes.) The request read loop also arms a
**non-resettable** completion deadline (`HEADER_READ_TIMEOUT`, 15 s) once the
first byte arrives — the idle wait for the first byte still uses the
keepalive/read timeout, but from the first byte the whole header must complete
within the deadline. Regression test: `tests/h1_header_limit.rs` (exact 16 KiB
boundary, the 16–32 KiB rejected interval, and a small-header-with-large-preread-body
case).

## Patch 4 — H2 request-body read timeout (idle DATA)

`src/protocols/http/v2/server.rs` (`HttpSession::read_timeout` field +
`read_body_bytes` + `set_read_timeout`/`get_read_timeout`),
`src/protocols/http/server.rs` (dispatcher `set_read_timeout`/`get_read_timeout`
route to H2 instead of being no-ops).

Upstream's H2 body reader had `// TODO: timeout` and awaited the next DATA frame
forever, and the dispatcher's `set_read_timeout` was a no-op for H2, so a single
connection could open the max concurrent streams and pin them indefinitely. The
patch enforces the read timeout **around the DATA-read future**; on expiry it
resets the stream with `CANCEL` and returns a read timeout. Sluice sets this via
the existing `set_read_timeout` (now honored for H2) and pairs it with the
absolute deadline it already checks per body callback and a per-write timeout for
the H2 slow-reader path. (The dispatcher change in `http/server.rs` opens its patch
marker inside the `set_read_timeout` doc comment and is closed after
`get_read_timeout`, so all patch markers are balanced.)

## Patch 5 — relax the upstream read timeout only after a confirmed `101`

`src/protocols/http/v1/client.rs`, `HttpSession::read_response`.

Sluice arms a **finite** upstream read timeout (`peer.options.read_timeout`) for
**every** request, including a WebSocket handshake, so the origin's response
header and any non-101 fallback body are bounded — a request-intent exemption
would leave a handshake whose origin returns a non-101 (or stalls) with no
response timeout at all. But once the upgrade is established the connection
becomes a long-lived, sparsely-read tunnel, and the same finite timeout would
kill a legitimately idle tunnel. `read_response` already computes
`self.upgraded` the moment it parses the response header; the patch clears
`self.read_timeout` **there**, at the `101` transition and nowhere else, so the
handshake/fallback stay bounded while the established tunnel does not. This is
the "minimal vendored hook" the timeout relaxation needs — `pingora-proxy` runs
the tunnel body reads through this same session's `read_timeout`, and Sluice has
no hook to change the upstream session timeout at that transition itself.

## Patch 6 — downstream H2 handshake timeout, idle timeout, bounded close, panic-safe accounting, and two-phase graceful drain

`src/apps/mod.rs` (`HttpServerOptions::h2_idle_timeout` +
`h2_graceful_shutdown_timeout` + `h2_handshake_timeout` fields; the
`h2_idle_expired`, `wait_for_idle`, and `dispatch_h2_stream` helpers; the
`StreamActiveGuard` RAII type; and the h2 accept loop in
`impl<T: HttpServerApp> ServerApp for T`). `src/protocols/http/v2/server.rs`
(`graceful_shutdown_bounded` helper).

Stock Pingora's h2 accept loop awaited the next stream **forever** — the source
carried a literal `// TODO: add a timeout?`. After the TLS/H2 handshake a client
that opened no stream (or went idle between streams) pinned the socket, TLS/H2
state, memory, and file descriptor for the connection's whole life; Sluice's
per-read downstream timeout only covers request-body DATA and its absolute
deadline only covers an in-flight request, so neither fired for a silent
post-handshake connection. With `max-conn-per-ip` disabled by default, one
unauthenticated source could hold connections until the process FD limit was
exhausted (DoS).

**Handshake timeout (preface).** Before any of the below, `process_new` awaited
`server::handshake` — the 24-byte H2 connection preface — with **no deadline**, and
the idle timeout only arms *after* it returns. A client that negotiated ALPN `h2`
over TLS and then sent no (or a dripped partial) preface therefore pinned the
socket / TLS+H2 allocations / conn-limit guard / task **indefinitely**, before the
idle accounting could ever start. The handshake is now wrapped in a
`tokio::select!` of a **finite** `tokio::time::timeout` (`h2_handshake_timeout`,
`None` → `H2_HANDSHAKE_TIMEOUT_DEFAULT` = 10 s — kept finite even when the idle
timeout is disabled) and `shutdown.changed()` (so a draining server never hangs
awaiting a preface); on either the future is dropped and the connection closed.

**Idle timeout (active-stream-aware).** A new optional
`HttpServerOptions::h2_idle_timeout` adds a finite idle-connection timeout. The
accept loop closes a connection that stays idle — **no active streams** — for that
duration, using **active-stream accounting** rather than a blind timer around
`from_h2_conn`: each accepted stream increments a shared counter (synchronously,
before it is spawned) and `h2_idle_expired` only arms the timer while the counter
is zero. A newly accepted stream resolves `from_h2_conn` and cancels the idle
future, so while that future lives the counter can only *decrease* — a full idle
period genuinely reflects a quiet connection and a long-running **active** stream
is never torn down. `None` preserves the stock unbounded behavior.

**Bounded close (does not trust the peer).** The idle-expiry path previously sent
GOAWAY and then awaited `poll_closed` with **no bound**, so a client that IGNORES
GOAWAY kept the socket/FD/`ConnGuard`/task forever — the DoS was not actually
closed. It now calls `graceful_shutdown_bounded` (v2/server.rs): best-effort
GOAWAY flush, a **bounded** `poll_closed` wait (1 s — the counter proves no active
streams), then it returns so the connection is dropped and the FD released
unconditionally.

**Panic-safe accounting.** The counter's decrement used to run only *after*
`process_new_http().await` returned normally, so a panic in the isolated stream
task leaked a permanent count and wedged the idle timer. Each stream task now
moves a `StreamActiveGuard` whose `Drop` does the decrement + notify, so a normal
return, an unwind from a panic, **and** task cancellation each release exactly one
slot.

**Two-phase graceful drain.** On a shutdown signal the loop previously called
`graceful_shutdown()` (whose first GOAWAY advertises `last-stream-id = 2^31-1`),
stopped calling `from_h2_conn`, and waited only on `poll_closed`. Streams already
sent but not yet `accept()`ed were dropped — even though that GOAWAY tells the
client they may have been processed, breaking safe retry — and an uncooperative
peer hung the wait. The loop now keeps calling `from_h2_conn` after
`graceful_shutdown()` so every eligible in-flight stream is dispatched (h2 then
emits the final GOAWAY carrying the true last-stream-id), waits (via
`wait_for_idle`) for the accepted tasks, and force-closes at
`h2_graceful_shutdown_timeout` (Sluice wires its global `graceful-shutdown-secs`;
`None` falls back to 30 s) so the drain always terminates.

Sluice sets `h2_idle_timeout` from `h2-idle-timeout-secs` (default **60 s**,
mirroring the H1 keepalive idle default; `0` disables), `h2_graceful_shutdown_timeout`
from `graceful-shutdown-secs`, and `h2_handshake_timeout` from
`h2-handshake-timeout-secs` (default **10 s**, minimum **1 s**), via the proxy
service's `server_options`. Regression tests: `tests/h2_idle_timeout.rs` — silent
idle connection closed at the timeout; active stream preserved past it; a **raw
GOAWAY-ignoring** client dropped at a finite bound with no peer close; a
**panicking** handler still lets the connection go idle and close; and a **graceful
drain** that dispatches every queued stream and returns finitely.
`tests/h2_handshake_timeout.rs` — a client that ALPN-negotiates `h2` and then sends
no preface, and one that byte-drips a partial preface, are both dropped at the
single non-resettable handshake deadline, while a prompt valid preface still
succeeds. The existing per-stream body/read/write deadlines (Patch 4 and Sluice's
own timeouts) are unchanged.

## Patch 7 — configurable downstream (TLS) handshake timeout

`src/services/listening.rs` (`Service::handshake_timeout` field +
`set_handshake_timeout` setter; the `run_endpoint` accept loop).

Upstream **hardcoded 60 s** for the downstream handshake in the accept loop
(`timeout(Duration::from_secs(60), io.handshake())`), which runs BEFORE any app
code. On a directly-reachable listener a silent or byte-dripped partial ClientHello
could therefore retain a socket + spawned task for a full minute (a pre-HTTP
Slowloris), and the value was not adjustable by a `Service` consumer. The patch adds
a private `handshake_timeout: Duration` field (defaulting to `DEFAULT_HANDSHAKE_TIMEOUT`
= the former 60 s, so an unconfigured `Service` is unchanged), a public
`set_handshake_timeout` setter, threads the value from `start_service` into
`run_endpoint`, and replaces the literal `60`. Sluice sets this on BOTH its proxy and
`:80` redirect services from the strictly-validated `tls-handshake-timeout-secs`
server directive (finite, min 1 s, default 10 s), and derives its per-IP
`ConnLimiter` pending-slot TTL from that value — the handshake timeout PLUS a fixed
30 s scheduling grace (`ConnLimiter::for_handshake_timeout`), NOT the bare timeout —
because a pending slot is timestamped at ACCEPT while the spawned handshake task only
starts its own `timeout(handshake_timeout, …)` once scheduled, so a bare-timeout TTL
could expire before the handshake it covers is still live. Regression tests: `tests/tls_handshake_timeout.rs`
— a silent ClientHello and a byte-dripped partial ClientHello are both dropped at the
single finite deadline, while a prompt valid handshake still succeeds.

## Updated upstream tests

Two upstream tests asserted the now-fixed lax framing and were updated in place
(marked with the same patch markers) to assert the new strict behavior:
`test_request_multiple_transfer_encoding_headers` (a `gzip, chunked` request is
now rejected) and `test_response_multiple_te_headers_chunked_not_last` (a
non-final `chunked` response is now rejected). Equivalent coverage that runs in
Sluice's own `cargo test` is in `tests/te_smuggling.rs` (both request and
response paths).

## Upstreaming

These are straightforward correctness / hardening fixes that belong upstream; if
a future `pingora-core` release incorporates them (or is bumped to a version that
does), drop this vendored copy and the `[patch.crates-io]` entry.
