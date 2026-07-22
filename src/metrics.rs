//! Prometheus metrics, registered in the default registry that Pingora's
//! `prometheus_http_service` scrapes. Country is the only geo field allowed as a
//! label (low cardinality); ASN/city stay in logs.

use std::sync::LazyLock;

use prometheus::{HistogramVec, IntCounterVec, IntGauge};

pub static REQUESTS: LazyLock<IntCounterVec> = LazyLock::new(|| {
    prometheus::register_int_counter_vec!(
        "sluice_requests_total",
        "requests by host and status class",
        &["host", "status"]
    )
    .unwrap()
});
pub static RESPONSES: LazyLock<IntCounterVec> = LazyLock::new(|| {
    prometheus::register_int_counter_vec!(
        "sluice_responses_total",
        "responses by host and exact status code",
        &["host", "code"]
    )
    .unwrap()
});
pub static LATENCY: LazyLock<HistogramVec> = LazyLock::new(|| {
    prometheus::register_histogram_vec!(
        "sluice_request_duration_seconds",
        "end-to-end request duration by host",
        &["host"],
        vec![0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0]
    )
    .unwrap()
});
pub static INFLIGHT: LazyLock<IntGauge> = LazyLock::new(|| {
    prometheus::register_int_gauge!("sluice_inflight_requests", "in-flight requests").unwrap()
});
pub static RESP_BYTES: LazyLock<IntCounterVec> = LazyLock::new(|| {
    prometheus::register_int_counter_vec!(
        "sluice_response_bytes_total",
        "response body bytes sent to clients by host",
        &["host"]
    )
    .unwrap()
});
pub static REQ_BYTES: LazyLock<IntCounterVec> = LazyLock::new(|| {
    prometheus::register_int_counter_vec!(
        "sluice_request_bytes_total",
        "request body bytes read from clients by host",
        &["host"]
    )
    .unwrap()
});
pub static UPSTREAM_ERRORS: LazyLock<IntCounterVec> = LazyLock::new(|| {
    prometheus::register_int_counter_vec!(
        "sluice_upstream_errors_total",
        "upstream or proxy errors by host",
        &["host"]
    )
    .unwrap()
});
pub static REQUESTS_BY_COUNTRY: LazyLock<IntCounterVec> = LazyLock::new(|| {
    prometheus::register_int_counter_vec!(
        "sluice_requests_by_country_total",
        "requests by client country (from the geoip country header)",
        &["country"]
    )
    .unwrap()
});

#[cfg(test)]
mod tests {
    use super::*;
    use prometheus::{Encoder, TextEncoder};

    /// The `gather()` + `TextEncoder` path Pingora's `prometheus_http_service`
    /// uses must produce valid, non-empty Prometheus exposition text. This also
    /// guards the metrics API across the prometheus 0.13 -> 0.14 bump (protobuf 3
    /// / RUSTSEC-2024-0437 fix): a registered+incremented counter must appear in
    /// the scraped text with its `# HELP` / `# TYPE` lines.
    #[test]
    fn gathered_metrics_encode_to_valid_prometheus_text() {
        REQUESTS.with_label_values(&["metrics.test", "2xx"]).inc();
        INFLIGHT.set(1);

        let mut buf = Vec::new();
        let encoder = TextEncoder::new();
        encoder.encode(&prometheus::gather(), &mut buf).unwrap();
        let text = String::from_utf8(buf).unwrap();

        assert!(
            text.contains("# TYPE sluice_requests_total counter"),
            "expected the counter's TYPE line in:\n{text}"
        );
        assert!(
            text.contains("sluice_requests_total{host=\"metrics.test\",status=\"2xx\"} 1"),
            "expected the incremented sample in:\n{text}"
        );
        assert!(
            text.contains("sluice_inflight_requests 1"),
            "expected the gauge sample in:\n{text}"
        );
    }
}
