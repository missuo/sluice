//! Regression test for the vendored `pingora-core` patch
//! (`vendor/pingora-core/PATCH.md`): a `HEAD` request that receives an interim
//! `1xx` (e.g. `103 Early Hints`) before the final response must NOT have that
//! `1xx` marked end-of-stream. The stock 0.8.1 code applied the HEAD-zero-body
//! rule before the informational check, so `read_response_task` returned the
//! interim header with `is_end() == true`, and `pingora-proxy` finished the
//! request without ever reading the final response (a persistent client hangs;
//! a close-mode client sees only the 103).
//!
//! This drives the patched H1 client directly through its public API against a
//! `tokio_test` mock stream, so it runs in the normal `cargo test` suite. Before
//! the patch, the first assertion (`!task.is_end()`) fails.

use pingora::http::RequestHeader;
use pingora::protocols::http::v1::client::HttpSession;
use pingora::protocols::http::HttpTask;
use tokio_test::io::Builder;

/// Extract the status code from an `HttpTask::Header`, or panic with the variant.
fn header_status(task: &HttpTask) -> u16 {
    match task {
        HttpTask::Header(h, _) => h.status.as_u16(),
        other => panic!("expected a response header task, got {}", other.type_str()),
    }
}

#[tokio::test]
async fn head_request_with_interim_1xx_still_reads_final_response() {
    // The HEAD request `write_request_header` will serialize, followed by the
    // origin's interim 103 (as its own read chunk, mirroring a delayed/fragmented
    // Early Hints) and then the final 200.
    let request_wire = b"HEAD / HTTP/1.1\r\n\r\n";
    let interim_103 = b"HTTP/1.1 103 Early Hints\r\nLink: </s.css>; rel=preload\r\n\r\n";
    let final_200 = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\n";

    let mock = Builder::new()
        .write(&request_wire[..])
        .read(&interim_103[..])
        .read(&final_200[..])
        .build();
    let mut session = HttpSession::new(Box::new(mock));

    let req = RequestHeader::build("HEAD", b"/", None).unwrap();
    session.write_request_header(Box::new(req)).await.unwrap();

    // First task: the 103. It MUST NOT be flagged end-of-stream — otherwise the
    // proxy would stop here and never deliver the final response.
    let t1 = session.read_response_task().await.unwrap();
    assert_eq!(header_status(&t1), 103, "first task is the interim 103");
    assert!(
        !t1.is_end(),
        "the 103 to a HEAD request must NOT end the response (the patched behavior)"
    );

    // Second task: the final 200 is delivered.
    let t2 = session.read_response_task().await.unwrap();
    assert_eq!(
        header_status(&t2),
        200,
        "final response reached after the 103"
    );
    // A HEAD response carries no body — this final header task is the end.
    assert!(
        t2.is_end(),
        "HEAD 200 has no body → end-of-stream on its header"
    );
}

/// A GET receiving the same interim 103 must behave the same (baseline: this
/// already worked upstream, and the patch must not regress it).
#[tokio::test]
async fn get_request_with_interim_1xx_reads_final_response() {
    let request_wire = b"GET / HTTP/1.1\r\n\r\n";
    let interim_103 = b"HTTP/1.1 103 Early Hints\r\nLink: </s.css>; rel=preload\r\n\r\n";
    let final_200 = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n";
    let body = b"hello";

    let mock = Builder::new()
        .write(&request_wire[..])
        .read(&interim_103[..])
        .read(&final_200[..])
        .read(&body[..])
        .build();
    let mut session = HttpSession::new(Box::new(mock));

    let req = RequestHeader::build("GET", b"/", None).unwrap();
    session.write_request_header(Box::new(req)).await.unwrap();

    let t1 = session.read_response_task().await.unwrap();
    assert_eq!(header_status(&t1), 103);
    assert!(!t1.is_end());

    let t2 = session.read_response_task().await.unwrap();
    assert_eq!(header_status(&t2), 200);
    assert!(
        !t2.is_end(),
        "GET 200 with a body → header task is not the end"
    );

    // Drain the body task so the mock's scripted reads are fully consumed.
    let t3 = session.read_response_task().await.unwrap();
    match t3 {
        HttpTask::Body(Some(b), end) => {
            assert_eq!(&b[..], body);
            assert!(end, "the 5-byte body completes the response");
        }
        other => panic!("expected the response body, got {}", other.type_str()),
    }
}
