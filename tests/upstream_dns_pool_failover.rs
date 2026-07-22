//! Regression test for round-22 finding 3: a DNS failure for one configured pool
//! member must fail over to the next healthy member, not return a non-retryable 502.
//!
//! Before the fix, a resolution failure happened inside `upstream_peer`, which
//! returned `Err` BEFORE any `HttpPeer` existed — so Pingora returned it directly
//! without ever calling `fail_to_connect`, and a two-server pool whose FIRST member
//! couldn't be resolved returned 502 even though the SECOND was healthy (the
//! reviewer verified `tries: 1, retry: false`, origin never hit). The fix does
//! bounded backend selection + resolution in an internal loop inside `upstream_peer`.
//!
//! Here the first pool member's name is seeded as a DNS FAILURE and the second is a
//! healthy IPv4 origin; round-robin picks index 0 first, so the request must fail
//! over to index 1 and return 200.

use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use pingora::apps::{HttpServerOptions, ServerApp};
use pingora::protocols::Stream;
use pingora::proxy::http_proxy;
use pingora::server::configuration::ServerConf;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use sluice::config::Config;
use sluice::proxy::SluiceProxy;

async fn spawn_origin() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut tmp = [0u8; 8192];
                loop {
                    match tokio::time::timeout(Duration::from_secs(5), sock.read(&mut tmp)).await {
                        Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
                        Ok(Ok(_)) => {}
                    }
                    if sock
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                        .await
                        .is_err()
                    {
                        break;
                    }
                    let _ = sock.flush().await;
                }
            });
        }
    });
    port
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dns_failure_on_first_backend_fails_over_to_healthy_second() {
    let origin_port = spawn_origin().await;

    // A 2-member round-robin pool: member 0 is a hostname whose DNS is seeded to
    // FAIL; member 1 is the healthy IPv4 origin. Round-robin picks index 0 first.
    let cfg_text = format!(
        "listener \"127.0.0.1:8443\" {{\n redirect-to-https true\n}}\n\
         site \"pool.local\" {{\n \
           upstream {{\n balance \"round-robin\"\n \
             server \"badhost:{origin_port}\"\n \
             server \"127.0.0.1:{origin_port}\"\n \
           }}\n\
         }}\n"
    );
    let config = Config::parse(&cfg_text).expect("config parses");
    let cfg = Arc::new(ArcSwap::from_pointee(config));

    let conf = Arc::new(ServerConf {
        upstream_keepalive_pool_size: 128,
        ..Default::default()
    });

    let sluice = SluiceProxy::new(cfg, None);
    // Member 0 ("badhost") never resolves; the request must fail over to member 1.
    sluice.seed_dns_failure("badhost", origin_port);

    let mut app = http_proxy(&conf, sluice);
    let mut opts = HttpServerOptions::default();
    opts.h2c = true;
    app.server_options = Some(opts);
    let app = Arc::new(app);

    let (client_io, server_io) = tokio::io::duplex(1024 * 1024);
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let server_stream: Stream = Box::new(server_io);
    let proxy = tokio::spawn(async move { app.process_new(server_stream, &shutdown_rx).await });

    let client = tokio::spawn(async move {
        let (mut send_req, connection) = h2::client::handshake(client_io).await.unwrap();
        let conn_task = tokio::spawn(async move {
            let _ = connection.await;
        });
        let mut ready = send_req.ready().await.unwrap();
        let req = http::Request::builder()
            .method("GET")
            .uri("http://pool.local/")
            .body(())
            .unwrap();
        let (resp, _body) = ready.send_request(req, true).unwrap();
        send_req = ready;
        let _ = &mut send_req;
        let status = tokio::time::timeout(Duration::from_secs(8), resp)
            .await
            .expect("request did not complete — pool failover on DNS failure stalled")
            .unwrap()
            .status();
        conn_task.abort();
        status.as_u16()
    });

    let status = tokio::time::timeout(Duration::from_secs(15), client)
        .await
        .expect("client did not finish")
        .expect("client task panicked");

    assert_eq!(
        status, 200,
        "a DNS failure on the first pool member must fail over to the healthy second (200)"
    );
    proxy.abort();
}
