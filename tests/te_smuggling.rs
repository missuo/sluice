//! Regression tests for the vendored `pingora-core` strict Transfer-Encoding
//! validation (`vendor/pingora-core/PATCH.md`, finding 1): the stock 0.8.1 parser
//! only checked that the LAST token of the last `Transfer-Encoding` field was
//! `chunked`, accepting the request-smuggling vector `chunked, chunked` (and
//! repeated fields). Sluice would dechunk once and forward the double-coding, so
//! an upstream honoring both codings could split a pipelined request past
//! routing/WAF/deny.
//!
//! These drive the patched H1 server `read_request` (which calls `validate_request`)
//! through a `tokio_test` mock stream, so they run in the normal `cargo test` suite.

use pingora::http::RequestHeader;
use pingora::protocols::http::v1::client::HttpSession as ClientSession;
use pingora::protocols::http::v1::server::HttpSession;
use tokio_test::io::Builder;

/// Feed a raw request head to `read_request` and report whether it was accepted.
async fn read_head_ok(head: &[u8]) -> bool {
    let mock = Builder::new().read(head).build();
    let mut session = HttpSession::new(Box::new(mock));
    session.read_request().await.is_ok()
}

/// Send a GET and feed a raw RESPONSE head to the H1 client's `read_response`
/// (which calls `validate_response`); report whether it was accepted.
async fn read_resp_head_ok(resp_head: &[u8]) -> bool {
    let mock = Builder::new()
        .write(b"GET / HTTP/1.1\r\n\r\n")
        .read(resp_head)
        .build();
    let mut session = ClientSession::new(Box::new(mock));
    let req = RequestHeader::build("GET", b"/", None).unwrap();
    session.write_request_header(Box::new(req)).await.unwrap();
    session.read_response().await.is_ok()
}

#[tokio::test]
async fn single_chunked_request_is_accepted() {
    assert!(
        read_head_ok(b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n").await,
        "a single valid `chunked` request coding must be accepted"
    );
    // Case-insensitive.
    assert!(
        read_head_ok(b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: Chunked\r\n\r\n").await
    );
    // No Transfer-Encoding at all is fine.
    assert!(read_head_ok(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").await);
}

#[tokio::test]
async fn double_chunked_and_repeated_te_are_rejected() {
    // The core smuggling vector: `chunked, chunked` in one field.
    assert!(
        !read_head_ok(b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked, chunked\r\n\r\n")
            .await,
        "duplicate `chunked` in a comma list must be rejected"
    );
    // Two Transfer-Encoding fields, each `chunked` — the repeated-field form.
    assert!(
        !read_head_ok(
            b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n"
        )
        .await,
        "duplicate `chunked` across repeated fields must be rejected"
    );
}

#[tokio::test]
async fn non_chunked_and_multi_coding_requests_are_rejected() {
    // We do not decode arbitrary transfer codings, so a coding before `chunked`
    // is rejected for requests (the safe policy).
    assert!(
        !read_head_ok(b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: gzip, chunked\r\n\r\n")
            .await
    );
    // `chunked` not final is always illegal.
    assert!(
        !read_head_ok(
            b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked, identity\r\n\r\n"
        )
        .await
    );
    // A non-chunked coding alone (the body framing would be unknown).
    assert!(!read_head_ok(b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: gzip\r\n\r\n").await);
}

#[tokio::test]
async fn empty_te_tokens_are_rejected() {
    assert!(
        !read_head_ok(b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked,\r\n\r\n").await
    );
    assert!(
        !read_head_ok(b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: , chunked\r\n\r\n").await
    );
    assert!(
        !read_head_ok(
            b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked, , chunked\r\n\r\n"
        )
        .await
    );
}

#[tokio::test]
async fn content_length_plus_te_is_handled_not_double_framed() {
    // With both CL and a single valid `chunked`, RFC 9112 §6.1 says TE wins and CL
    // is dropped (keepalive disabled). Pingora does this, so the header is accepted
    // — but crucially only a SINGLE chunked coding got here, never `chunked,
    // chunked` alongside a Content-Length.
    assert!(
        read_head_ok(
            b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n"
        )
        .await
    );
    // CL + the illegal double coding is still rejected on the TE.
    assert!(
        !read_head_ok(
            b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nTransfer-Encoding: chunked, chunked\r\n\r\n"
        )
        .await
    );
}

#[tokio::test]
async fn response_te_validation_matches_rfc_9112() {
    // A single `chunked`, or a coding then final `chunked`, is legal for responses.
    assert!(read_resp_head_ok(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n").await);
    assert!(
        read_resp_head_ok(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n").await
    );
    assert!(read_resp_head_ok(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n").await);
    // Duplicate `chunked` (single field or repeated fields) is rejected.
    assert!(
        !read_resp_head_ok(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, chunked\r\n\r\n").await
    );
    assert!(
        !read_resp_head_ok(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n"
        )
        .await
    );
    // `chunked` not final (ambiguous framing) is rejected.
    assert!(
        !read_resp_head_ok(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, identity\r\n\r\n")
            .await
    );
    // Empty token is rejected.
    assert!(!read_resp_head_ok(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, \r\n\r\n").await);
}
