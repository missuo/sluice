//! Regression test for the vendored `pingora-core` H1 request header-size cap
//! (`vendor/pingora-core/PATCH.md`, finding 3). The stock 0.8.1 cap was ~1 MiB
//! per connection; it is now 16 KiB.
//!
//! An earlier version of the patch checked the SOCKET read amount before each
//! read and never re-checked on a complete parse, so a single read that produced
//! a complete header of up to ~2× the cap slipped through — the advertised 16 KiB
//! limit actually accepted complete heads up to ~32 KiB. The cap is now enforced
//! against the PARSED header-section length, so the boundary is exact, and
//! legitimately preread body bytes (which follow the header in the same read) are
//! not counted against it.
//!
//! Uses an in-memory `tokio::io::duplex` pipe (which the vendored crate implements
//! the `IO` trait for) so read_request can reject mid-stream without a mock's
//! strict "all bytes consumed" assertion.

use pingora::protocols::http::v1::server::HttpSession;
use tokio::io::AsyncWriteExt;

/// Write `head` (and any trailing bytes) into an in-memory pipe and run
/// `read_request` on the other end; report whether it was accepted.
async fn read_head_ok(head: Vec<u8>) -> bool {
    // A generous buffer so the whole payload is buffered without the writer blocking.
    let (mut client, server) = tokio::io::duplex(head.len() + 4096);
    let writer = tokio::spawn(async move {
        let _ = client.write_all(&head).await;
        let _ = client.flush().await;
        // Keep the write half open; read_request rejects an oversized header (or
        // returns on a complete one) before EOF, so we don't need to close it.
        client
    });
    let mut session = HttpSession::new(Box::new(server));
    let res = session.read_request().await;
    let _ = writer.await;
    res.is_ok()
}

/// Build a complete request head whose total header-section length (including the
/// terminating `\r\n\r\n`) is exactly `total` bytes, by padding a single field.
fn head_of_len(total: usize) -> Vec<u8> {
    // Fixed overhead: "GET / HTTP/1.1\r\n" (16) + "X-Pad: " (7) + "\r\n\r\n" (4) = 27.
    const OVERHEAD: usize = 27;
    assert!(total >= OVERHEAD, "total too small: {total}");
    let pad = "A".repeat(total - OVERHEAD);
    let head = format!("GET / HTTP/1.1\r\nX-Pad: {pad}\r\n\r\n").into_bytes();
    assert_eq!(head.len(), total, "constructed head length mismatch");
    head
}

#[tokio::test]
async fn header_exactly_16kib_is_accepted() {
    // 16384 == MAX_REQUEST_HEADER_SIZE. The check is `s > MAX`, so the boundary
    // value itself is accepted.
    assert!(
        read_head_ok(head_of_len(16384)).await,
        "a header section of exactly 16 KiB must be accepted"
    );
}

#[tokio::test]
async fn headers_over_16kib_are_all_rejected() {
    // Every complete head above the cap must be rejected — including the 16 KiB–32 KiB
    // interval that the earlier check silently accepted.
    for total in [16385usize, 20000, 32768, 32769, 64 * 1024] {
        assert!(
            !read_head_ok(head_of_len(total)).await,
            "a complete header of {total} bytes (> 16 KiB cap) must be rejected"
        );
    }
}

#[tokio::test]
async fn small_header_with_large_preread_body_is_accepted() {
    // A small header immediately followed by a large body in the SAME stream. The
    // body bytes are preread after the header terminator; they must NOT count
    // toward the header cap. `already_read` here far exceeds 16 KiB, but the parsed
    // header section is tiny, so the request is accepted.
    let body_len = 40_000usize;
    let mut head =
        format!("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: {body_len}\r\n\r\n").into_bytes();
    head.extend(std::iter::repeat_n(b'b', body_len));
    assert!(
        read_head_ok(head).await,
        "a small header with a large preread body must be accepted (body is not header)"
    );
}

#[tokio::test]
async fn ordinary_header_is_accepted() {
    // A realistic header (incl. a moderate ~2 KiB cookie) is well under the cap.
    let cookie = "session=".to_string() + &"b".repeat(2000);
    let head =
        format!("GET /path HTTP/1.1\r\nHost: example.com\r\nCookie: {cookie}\r\n\r\n").into_bytes();
    assert!(read_head_ok(head).await);
}
