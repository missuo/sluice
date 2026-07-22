// Copyright 2026 Cloudflare, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! The abstraction and implementation interface for service application logic

pub mod http_app;
pub mod prometheus_http_app;

use crate::server::ShutdownWatch;
use async_trait::async_trait;
use log::{debug, error};
// ---- sluice vendored patch: the H2 idle/shutdown close paths no longer poll the
// connection inline (see the bounded-close helper + two-phase drain), so the
// `poll_fn` import is replaced by `Instant` for the drain deadline. ----
use std::time::Instant;
// ---- end sluice vendored patch ----
use std::sync::Arc;

use crate::protocols::http::v2::server;
use crate::protocols::http::ServerSession;
use crate::protocols::Digest;
use crate::protocols::Stream;
use crate::protocols::ALPN;

// https://datatracker.ietf.org/doc/html/rfc9113#section-3.4
const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

// ---- sluice vendored patch (see vendor/pingora-core/PATCH.md) ----
/// Completes only once a downstream H2 connection has been continuously IDLE
/// (no active streams) for `timeout`. Used as one arm of the h2 accept
/// `select!`: a newly accepted stream resolves `from_h2_conn` and cancels this
/// future, and while this future is alive `active_streams` can only DECREASE (a
/// new stream would have cancelled us), so a full idle period genuinely means the
/// connection is quiet and can be closed. While any stream is active we park on
/// `stream_done` and re-evaluate each time one finishes, so an active/long-running
/// stream is never torn down. `None` never completes, preserving stock behavior.
async fn h2_idle_expired(
    timeout: Option<std::time::Duration>,
    active_streams: &std::sync::atomic::AtomicUsize,
    stream_done: &tokio::sync::Notify,
) {
    use std::sync::atomic::Ordering;
    let Some(timeout) = timeout else {
        // No idle timeout configured: this arm must never fire.
        std::future::pending::<()>().await;
        return;
    };
    loop {
        if active_streams.load(Ordering::SeqCst) == 0 {
            // Idle. A stream cannot start while this future lives (that path
            // resolves `from_h2_conn` in the outer select and cancels us), so a
            // full `timeout` with no cancellation means the connection is quiet.
            tokio::time::sleep(timeout).await;
            return;
        }
        // Busy: wait for an active stream to finish, then re-evaluate.
        stream_done.notified().await;
    }
}

/// Bounded drain for an IDLE-timeout close: no active streams exist, so this only
/// gives a compliant client a brief window to observe GOAWAY and close cleanly
/// before the connection is dropped (which releases the socket/FD regardless).
const H2_IDLE_CLOSE_DRAIN: std::time::Duration = std::time::Duration::from_secs(1);

/// Fallback bound for the graceful-shutdown H2 drain when the app configures no
/// deadline. Sluice wires its global graceful-shutdown deadline instead.
const H2_GRACEFUL_DRAIN_DEFAULT: std::time::Duration = std::time::Duration::from_secs(30);

/// Fallback bound for the H2 connection-preface handshake when the app configures
/// none. Kept FINITE even when the post-handshake idle timeout is disabled, so a
/// client that negotiates ALPN `h2` and then sends no/partial preface cannot pin
/// the connection before the idle accounting can start.
const H2_HANDSHAKE_TIMEOUT_DEFAULT: std::time::Duration = std::time::Duration::from_secs(10);

/// Releases exactly one active-stream slot on drop. Because `Drop` runs on a
/// normal return, a panic (unwind), AND task cancellation, a stream task that
/// panics or is cancelled can no longer leave the per-connection active-stream
/// counter permanently non-zero (which would stop `h2_idle_expired` from ever
/// arming again). Pingora deliberately isolates these stream tasks, so an
/// otherwise-contained panic must not corrupt connection-lifetime accounting.
struct StreamActiveGuard {
    active: Arc<std::sync::atomic::AtomicUsize>,
    done: Arc<tokio::sync::Notify>,
}

impl Drop for StreamActiveGuard {
    fn drop(&mut self) {
        self.active.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
        self.done.notify_one();
    }
}

/// Completes once `active_streams` reaches zero, waking on each `stream_done`
/// notification. Used to wait (bounded by the caller) for accepted streams to
/// finish during graceful shutdown.
async fn wait_for_idle(
    active_streams: &std::sync::atomic::AtomicUsize,
    stream_done: &tokio::sync::Notify,
) {
    use std::sync::atomic::Ordering;
    while active_streams.load(Ordering::SeqCst) != 0 {
        stream_done.notified().await;
    }
}

/// Count an accepted H2 stream as active (BEFORE spawning, so the idle timer
/// already sees it) and spawn its isolated handler task. A [`StreamActiveGuard`]
/// moved into the task releases the slot on any exit — normal, panic, or cancel.
fn dispatch_h2_stream<T>(
    app: Arc<T>,
    h2_stream: server::HttpSession,
    shutdown: ShutdownWatch,
    active_streams: &Arc<std::sync::atomic::AtomicUsize>,
    stream_done: &Arc<tokio::sync::Notify>,
) where
    T: HttpServerApp + Send + Sync + 'static,
{
    active_streams.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let guard = StreamActiveGuard {
        active: active_streams.clone(),
        done: stream_done.clone(),
    };
    pingora_runtime::current_handle().spawn(async move {
        // `_guard` decrements the counter and notifies on drop (normal return,
        // unwind from a panic in the handler, or task cancellation).
        let _guard = guard;
        // Note, `PersistentSettings` not currently relevant for h2
        app.process_new_http(ServerSession::new_http2(h2_stream), &shutdown)
            .await;
    });
}
// ---- end sluice vendored patch ----

#[async_trait]
/// This trait defines the interface of a transport layer (TCP or TLS) application.
pub trait ServerApp {
    /// Whenever a new connection is established, this function will be called with the established
    /// [`Stream`] object provided.
    ///
    /// The application can do whatever it wants with the `session`.
    ///
    /// After processing the `session`, if the `session`'s connection is reusable, This function
    /// can return it to the service by returning `Some(session)`. The returned `session` will be
    /// fed to another [`Self::process_new()`] for another round of processing.
    /// If not reusable, `None` should be returned.
    ///
    /// The `shutdown` argument will change from `false` to `true` when the server receives a
    /// signal to shutdown. This argument allows the application to react accordingly.
    async fn process_new(
        self: &Arc<Self>,
        mut session: Stream,
        // TODO: make this ShutdownWatch so that all task can await on this event
        shutdown: &ShutdownWatch,
    ) -> Option<Stream>;

    /// This callback will be called once after the service stops listening to its endpoints.
    async fn cleanup(&self) {}
}
#[non_exhaustive]
#[derive(Default)]
/// HTTP Server options that control how the server handles some transport types.
pub struct HttpServerOptions {
    /// Allow HTTP/2 for plaintext.
    pub h2c: bool,

    /// Allow proxying CONNECT requests when handling HTTP traffic.
    ///
    /// When disabled, CONNECT requests are rejected with 405 by proxy services.
    pub allow_connect_method_proxying: bool,

    #[doc(hidden)]
    pub force_custom: bool,

    /// Maximum number of requests that this connection will handle. This is
    /// equivalent to [Nginx's keepalive requests](https://nginx.org/en/docs/http/ngx_http_upstream_module.html#keepalive_requests)
    /// which says:
    ///
    /// > Closing connections periodically is necessary to free per-connection
    /// > memory allocations. Therefore, using too high maximum number of
    /// > requests could result in excessive memory usage and not recommended.
    ///
    /// Unlike nginx, the default behavior here is _no limit_.
    pub keepalive_request_limit: Option<u32>,

    // ---- sluice vendored patch (see vendor/pingora-core/PATCH.md) ----
    /// Idle-connection timeout for a downstream HTTP/2 connection that has NO
    /// active streams. Stock Pingora waits on the next stream forever (see the
    /// `TODO: add a timeout?` in the h2 accept loop below), so a client that
    /// completes the H2 handshake and then opens no stream pins the socket / TLS /
    /// H2 state / file descriptor for the connection's whole life. When set, the
    /// accept loop closes a connection that stays idle (no active streams) for
    /// this duration; a long-running ACTIVE stream keeps it open. `None` = the
    /// stock unbounded behavior.
    pub h2_idle_timeout: Option<std::time::Duration>,

    /// Bound on the graceful-shutdown H2 drain. On a shutdown signal the accept
    /// loop keeps dispatching the streams the client already sent (so queued
    /// requests are not silently lost and the final GOAWAY advertises the true
    /// last-stream-id for safe retry), then waits for the accepted tasks — all
    /// bounded by this deadline, after which the connection is dropped so an
    /// uncooperative peer cannot hang the drain. `None` falls back to
    /// `H2_GRACEFUL_DRAIN_DEFAULT`. Sluice wires its global graceful-shutdown
    /// deadline here.
    pub h2_graceful_shutdown_timeout: Option<std::time::Duration>,

    /// Absolute timeout on the H2 connection-preface handshake. Stock Pingora
    /// awaited the client's 24-byte preface with NO deadline, and the
    /// post-handshake idle timeout only arms AFTER the handshake completes — so a
    /// client that negotiated ALPN `h2` over TLS and then sent no (or a dripped
    /// partial) preface pinned the socket / TLS+H2 allocations / conn-limit guard /
    /// task indefinitely. When set, the accept loop bounds `server::handshake` with
    /// this deadline; `None` falls back to `H2_HANDSHAKE_TIMEOUT_DEFAULT` (kept
    /// FINITE even when `h2_idle_timeout` is disabled). Sluice wires its
    /// `h2-handshake-timeout-secs`.
    pub h2_handshake_timeout: Option<std::time::Duration>,
    // ---- end sluice vendored patch ----
}

#[derive(Debug, Clone)]
pub struct HttpPersistentSettings {
    keepalive_timeout: Option<u64>,
    keepalive_reuses_remaining: Option<u32>,
}

impl HttpPersistentSettings {
    pub fn for_session(session: &ServerSession) -> Self {
        HttpPersistentSettings {
            keepalive_timeout: session.get_keepalive(),
            keepalive_reuses_remaining: session.get_keepalive_reuses_remaining(),
        }
    }

    pub fn apply_to_session(self, session: &mut ServerSession) {
        let Self {
            keepalive_timeout,
            mut keepalive_reuses_remaining,
        } = self;

        // Reduce the number of times the connection for this session can be
        // reused by one. A session with reuse count of zero won't be reused
        if let Some(reuses) = keepalive_reuses_remaining.as_mut() {
            *reuses = reuses.saturating_sub(1);
        }

        session.set_keepalive(keepalive_timeout);
        session.set_keepalive_reuses_remaining(keepalive_reuses_remaining);
    }
}

#[derive(Debug)]
pub struct ReusedHttpStream {
    stream: Stream,
    persistent_settings: Option<HttpPersistentSettings>,
}

impl ReusedHttpStream {
    pub fn new(stream: Stream, persistent_settings: Option<HttpPersistentSettings>) -> Self {
        ReusedHttpStream {
            stream,
            persistent_settings,
        }
    }

    pub fn consume(self) -> (Stream, Option<HttpPersistentSettings>) {
        (self.stream, self.persistent_settings)
    }
}

/// This trait defines the interface of an HTTP application.
#[async_trait]
pub trait HttpServerApp {
    /// Similar to the [`ServerApp`], this function is called whenever a new HTTP session is established.
    ///
    /// After successful processing, [`ServerSession::finish()`] can be called to return an optionally reusable
    /// connection back to the service. The caller needs to make sure that the connection is in a reusable state
    /// i.e., no error or incomplete read or write headers or bodies. Otherwise a `None` should be returned.
    async fn process_new_http(
        self: &Arc<Self>,
        mut session: ServerSession,
        // TODO: make this ShutdownWatch so that all task can await on this event
        shutdown: &ShutdownWatch,
    ) -> Option<ReusedHttpStream>;

    /// Provide options on how HTTP/2 connection should be established. This function will be called
    /// every time a new HTTP/2 **connection** needs to be established.
    ///
    /// A `None` means to use the built-in default options. See [`server::H2Options`] for more details.
    fn h2_options(&self) -> Option<server::H2Options> {
        None
    }

    /// Provide HTTP server options used to override default behavior. This function will be called
    /// every time a new connection is processed.
    ///
    /// A `None` means no server options will be applied.
    fn server_options(&self) -> Option<&HttpServerOptions> {
        None
    }

    async fn http_cleanup(&self) {}

    #[doc(hidden)]
    async fn process_custom_session(
        self: Arc<Self>,
        _stream: Stream,
        _shutdown: &ShutdownWatch,
    ) -> Option<Stream> {
        None
    }
}

#[async_trait]
impl<T> ServerApp for T
where
    T: HttpServerApp + Send + Sync + 'static,
{
    async fn process_new(
        self: &Arc<Self>,
        mut stream: Stream,
        shutdown: &ShutdownWatch,
    ) -> Option<Stream> {
        let mut h2c = self.server_options().as_ref().map_or(false, |o| o.h2c);
        let custom = self
            .server_options()
            .as_ref()
            .map_or(false, |o| o.force_custom);

        // try to read h2 preface
        if h2c && !custom {
            let mut buf = [0u8; H2_PREFACE.len()];
            let peeked = stream
                .try_peek(&mut buf)
                .await
                .map_err(|e| {
                    // this error is normal when h1 reuse and close the connection
                    debug!("Read error while peeking h2c preface {e}");
                    e
                })
                .ok()?;
            // not all streams support peeking
            if peeked {
                // turn off h2c (use h1) if h2 preface doesn't exist
                h2c = buf == H2_PREFACE;
            }
        }
        if h2c || matches!(stream.selected_alpn_proto(), Some(ALPN::H2)) {
            // create a shared connection digest
            let digest = Arc::new(Digest {
                ssl_digest: stream.get_ssl_digest(),
                // TODO: log h2 handshake time
                timing_digest: stream.get_timing_digest(),
                proxy_digest: stream.get_proxy_digest(),
                socket_digest: stream.get_socket_digest(),
            });

            let h2_options = self.h2_options();
            // ---- sluice vendored patch (see vendor/pingora-core/PATCH.md) ----
            // Absolute timeout on the H2 connection-preface handshake. Upstream
            // awaited the client's 24-byte preface with NO deadline, and the
            // post-handshake idle timeout only arms AFTER `handshake` returns — so a
            // client that negotiated ALPN `h2` over TLS and then sent no/partial
            // preface pinned the socket / TLS+H2 allocations / conn-limit guard /
            // task indefinitely (FD-exhaustion DoS). Bound it with a FINITE deadline
            // (kept finite even when `h2_idle_timeout` is disabled), and also react
            // to shutdown so a draining server doesn't hang awaiting a preface.
            let h2_handshake_timeout = self
                .server_options()
                .and_then(|o| o.h2_handshake_timeout)
                .unwrap_or(H2_HANDSHAKE_TIMEOUT_DEFAULT);
            let mut hs_shutdown = shutdown.clone();
            let h2_conn = tokio::select! {
                _ = hs_shutdown.changed() => {
                    debug!("shutdown while awaiting H2 handshake");
                    return None;
                }
                res = tokio::time::timeout(
                    h2_handshake_timeout,
                    server::handshake(stream, h2_options),
                ) => match res {
                    Err(_) => {
                        debug!("H2 handshake preface timeout after {h2_handshake_timeout:?}");
                        return None;
                    }
                    Ok(conn) => conn,
                },
            };
            // ---- end sluice vendored patch ----
            let mut h2_conn = match h2_conn {
                Err(e) => {
                    error!("H2 handshake error {e}");
                    return None;
                }
                Ok(c) => c,
            };

            let mut shutdown = shutdown.clone();
            // ---- sluice vendored patch (see vendor/pingora-core/PATCH.md) ----
            // Downstream H2 idle-connection timeout. Upstream waited on the next
            // stream forever (the `TODO: add a timeout?` below), so a client that
            // completed the H2 handshake and then sent no stream pinned the socket /
            // TLS / H2 state / file descriptor for the connection's whole life. We
            // close the connection when it has been idle (NO active streams) for
            // `h2_idle_timeout`. This uses ACTIVE-STREAM ACCOUNTING rather than a
            // blind timer around `from_h2_conn`: a newly accepted stream resolves
            // `from_h2_conn` (cancelling the idle future), and each spawned stream
            // increments a shared counter that it decrements on completion, so a
            // long-running ACTIVE stream is never torn down by the timeout. `None`
            // preserves the stock unbounded behavior.
            let h2_idle_timeout = self.server_options().and_then(|o| o.h2_idle_timeout);
            let h2_graceful_timeout = self
                .server_options()
                .and_then(|o| o.h2_graceful_shutdown_timeout)
                .unwrap_or(H2_GRACEFUL_DRAIN_DEFAULT);
            let active_streams = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let stream_done = Arc::new(tokio::sync::Notify::new());
            // ---- end sluice vendored patch ----
            loop {
                // this loop ends when the client decides to close the h2 conn
                let h2_stream = tokio::select! {
                    _ = shutdown.changed() => {
                        // ---- sluice vendored patch (see vendor/pingora-core/PATCH.md) ----
                        // Two-phase graceful H2 drain (zero-downtime upgrade / SIGQUIT).
                        // Upstream called `graceful_shutdown()` then waited only on
                        // `poll_closed`, which (a) STOPPED accepting streams the client
                        // had ALREADY sent — losing them even though the initial GOAWAY's
                        // last-stream-id = 2^31-1 tells the client they may have been
                        // processed, breaking safe retry — and (b) hung on an
                        // uncooperative peer. Instead: send the initial GOAWAY, keep
                        // accepting the in-flight streams so they are dispatched (h2 then
                        // emits the final GOAWAY with the true last-stream-id), then wait
                        // for the accepted tasks — all bounded by the global graceful
                        // deadline, after which we drop the connection to release the
                        // socket/FD unconditionally.
                        h2_conn.graceful_shutdown();
                        let drain_deadline = Instant::now() + h2_graceful_timeout;
                        loop {
                            let remaining =
                                drain_deadline.saturating_duration_since(Instant::now());
                            if remaining.is_zero() {
                                break;
                            }
                            match tokio::time::timeout(
                                remaining,
                                server::HttpSession::from_h2_conn(&mut h2_conn, digest.clone()),
                            )
                            .await
                            {
                                Err(_) => break, // drain deadline reached
                                Ok(Err(e)) => {
                                    debug!("H2 error draining streams on shutdown {e}");
                                    break;
                                }
                                Ok(Ok(None)) => break, // graceful shutdown complete
                                Ok(Ok(Some(h2_stream))) => {
                                    dispatch_h2_stream(
                                        self.clone(),
                                        h2_stream,
                                        shutdown.clone(),
                                        &active_streams,
                                        &stream_done,
                                    );
                                }
                            }
                        }
                        // Wait (bounded) for accepted streams to finish, then drop.
                        let remaining =
                            drain_deadline.saturating_duration_since(Instant::now());
                        let _ = tokio::time::timeout(
                            remaining,
                            wait_for_idle(&active_streams, &stream_done),
                        )
                        .await;
                        return None;
                        // ---- end sluice vendored patch ----
                    }
                    // ---- sluice vendored patch ----
                    // Fires only while the connection is idle (no active streams);
                    // see `h2_idle_expired`. On expiry, best-effort GOAWAY then a
                    // BOUNDED wait, and drop the connection to release the socket/FD
                    // even if the peer ignores GOAWAY (the counter proves no active
                    // streams, so nothing in-flight is disrupted).
                    _ = h2_idle_expired(h2_idle_timeout, &active_streams, &stream_done) => {
                        debug!("H2 connection idle for {h2_idle_timeout:?}, closing");
                        server::graceful_shutdown_bounded(&mut h2_conn, H2_IDLE_CLOSE_DRAIN).await;
                        return None;
                    }
                    // ---- end sluice vendored patch ----
                    h2_stream = server::HttpSession::from_h2_conn(&mut h2_conn, digest.clone()) => h2_stream
                };
                let h2_stream = match h2_stream {
                    Err(e) => {
                        // It is common for the client to just disconnect TCP without properly
                        // closing H2. So we don't log the errors here
                        debug!("H2 error when accepting new stream {e}");
                        return None;
                    }
                    Ok(s) => s?, // None means the connection is ready to be closed
                };
                // ---- sluice vendored patch ----
                // Count + spawn the isolated stream task. `dispatch_h2_stream`
                // increments the active-stream counter BEFORE spawning (so the idle
                // timer already sees it) and moves an RAII guard into the task that
                // releases the slot on normal return, panic, or cancellation.
                dispatch_h2_stream(
                    self.clone(),
                    h2_stream,
                    shutdown.clone(),
                    &active_streams,
                    &stream_done,
                );
                // ---- end sluice vendored patch ----
            }
        } else if custom || matches!(stream.selected_alpn_proto(), Some(ALPN::Custom(_))) {
            return self.clone().process_custom_session(stream, shutdown).await;
        } else {
            // No ALPN or ALPN::H1 and h2c was not configured, fallback to HTTP/1.1
            let mut session = ServerSession::new_http1(stream);
            if *shutdown.borrow() {
                // stop downstream from reusing if this service is shutting down soon
                session.set_keepalive(None);
            } else {
                // default 60s
                session.set_keepalive(Some(60));
            }
            session.set_keepalive_reuses_remaining(
                self.server_options()
                    .and_then(|opts| opts.keepalive_request_limit),
            );

            let mut result = self.process_new_http(session, shutdown).await;
            while let Some((stream, persistent_settings)) = result.map(|r| r.consume()) {
                let mut session = ServerSession::new_http1(stream);
                if let Some(persistent_settings) = persistent_settings {
                    persistent_settings.apply_to_session(&mut session);
                }

                result = self.process_new_http(session, shutdown).await;
            }
        }
        None
    }

    async fn cleanup(&self) {
        self.http_cleanup().await;
    }
}
