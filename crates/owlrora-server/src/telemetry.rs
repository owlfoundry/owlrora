//! Process-local OpenTelemetry providers. No global subscriber/provider mutation.
//! SDK workers own batching and metric aggregation; request tasks never export.
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};

use opentelemetry::{
    Context, KeyValue,
    metrics::{Counter, Histogram, MeterProvider as _, UpDownCounter},
    trace::{SpanKind, TraceContextExt as _, Tracer as _, TracerProvider as _},
};
use opentelemetry_otlp::{WithExportConfig as _, WithHttpConfig as _};
use opentelemetry_sdk::{
    Resource,
    error::OTelSdkResult,
    metrics::{
        PeriodicReader, SdkMeterProvider, Temporality, data::ResourceMetrics,
        exporter::PushMetricExporter,
    },
    trace::{
        BatchConfigBuilder, BatchSpanProcessor, Sampler, SdkTracer, SdkTracerProvider, Span,
        SpanData, SpanExporter, SpanProcessor,
    },
};
use serde::Serialize;

const QUEUE_CAPACITY: usize = 512;
const BATCH_SIZE: usize = 128;
const EXPORT_TIMEOUT: Duration = Duration::from_millis(500);

#[derive(Debug, Default)]
struct ExportState {
    outstanding_spans: AtomicUsize,
    queue_dropped_spans: AtomicU64,
    export_failed_spans: AtomicU64,
    exported_spans: AtomicU64,
    metric_export_failures: AtomicU64,
    metric_exports: AtomicU64,
    shutdown_failures: AtomicU64,
    closed: AtomicBool,
}

#[derive(Debug, Serialize)]
pub(crate) struct TelemetryStatus {
    enabled: bool,
    outstanding_spans: usize,
    queue_dropped_spans: u64,
    export_failed_spans: u64,
    exported_spans: u64,
    metric_export_failures: u64,
    metric_exports: u64,
    shutdown_failures: u64,
}

/// Admission accounting wraps (not replaces) the SDK batch processor. The SDK
/// does not expose its private queue-drop counter. Bounding queued + in-flight
/// spans below its queue capacity makes SDK queue overflow unreachable and lets
/// diagnostics report exact drop-newest counts without parsing SDK log strings.
#[derive(Debug)]
struct CountedProcessor {
    inner: BatchSpanProcessor,
    state: Arc<ExportState>,
}
impl SpanProcessor for CountedProcessor {
    fn on_start(&self, span: &mut Span, cx: &Context) {
        self.inner.on_start(span, cx);
    }
    fn on_end(&self, span: SpanData) {
        if !span.span_context.is_sampled() {
            return;
        }
        if self.state.closed.load(Ordering::Acquire)
            || self
                .state
                .outstanding_spans
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                    (n < QUEUE_CAPACITY).then_some(n + 1)
                })
                .is_err()
        {
            self.state
                .queue_dropped_spans
                .fetch_add(1, Ordering::Relaxed);
            return;
        }
        self.inner.on_end(span);
    }
    fn force_flush(&self) -> OTelSdkResult {
        self.inner.force_flush()
    }
    fn shutdown_with_timeout(&self, timeout: Duration) -> OTelSdkResult {
        self.state.closed.store(true, Ordering::Release);
        self.inner.shutdown_with_timeout(timeout)
    }
    fn set_resource(&mut self, resource: &Resource) {
        self.inner.set_resource(resource);
    }
}

#[derive(Debug)]
struct CountedSpanExporter {
    inner: opentelemetry_otlp::SpanExporter,
    state: Arc<ExportState>,
}
impl SpanExporter for CountedSpanExporter {
    async fn export(&self, batch: Vec<SpanData>) -> OTelSdkResult {
        let count = batch.len();
        let result = self.inner.export(batch).await;
        if result.is_ok() {
            &self.state.exported_spans
        } else {
            &self.state.export_failed_spans
        }
        .fetch_add(count as u64, Ordering::Relaxed);
        self.state
            .outstanding_spans
            .fetch_sub(count, Ordering::AcqRel);
        result
    }
    fn shutdown_with_timeout(&self, timeout: Duration) -> OTelSdkResult {
        self.inner.shutdown_with_timeout(timeout)
    }
    fn set_resource(&mut self, resource: &Resource) {
        self.inner.set_resource(resource);
    }
}

#[derive(Debug)]
struct CountedMetricExporter {
    inner: opentelemetry_otlp::MetricExporter,
    state: Arc<ExportState>,
}
impl PushMetricExporter for CountedMetricExporter {
    async fn export(&self, metrics: &ResourceMetrics) -> OTelSdkResult {
        let result = self.inner.export(metrics).await;
        if result.is_ok() {
            &self.state.metric_exports
        } else {
            &self.state.metric_export_failures
        }
        .fetch_add(1, Ordering::Relaxed);
        result
    }
    fn force_flush(&self) -> OTelSdkResult {
        self.inner.force_flush()
    }
    fn shutdown_with_timeout(&self, timeout: Duration) -> OTelSdkResult {
        self.inner.shutdown_with_timeout(timeout)
    }
    fn temporality(&self) -> Temporality {
        Temporality::Cumulative
    }
}

#[derive(Debug)]
pub(crate) struct Telemetry {
    traces: SdkTracerProvider,
    metrics: SdkMeterProvider,
    tracer: SdkTracer,
    state: Arc<ExportState>,
    facts: Counter<u64>,
    duration: Histogram<f64>,
    units: Counter<f64>,
    cost: Counter<f64>,
    unknown_cost: Counter<u64>,
    active: UpDownCounter<i64>,
    http_requests: Counter<u64>,
    http_headers: Histogram<f64>,
    http_bytes: Counter<u64>,
}

impl Telemetry {
    pub(crate) async fn build(
        endpoint: String,
        sample_ratio: f64,
    ) -> Result<Arc<Self>, &'static str> {
        // reqwest's blocking client and SDK workers must be composed outside a
        // Tokio worker. They never borrow the application's runtime for IO.
        tokio::task::spawn_blocking(move || Self::build_blocking(&endpoint, sample_ratio))
            .await
            .map_err(|_| "telemetry initialization worker failed")?
    }

    fn build_blocking(endpoint: &str, sample_ratio: f64) -> Result<Arc<Self>, &'static str> {
        let state = Arc::new(ExportState::default());
        let client = reqwest::blocking::Client::builder()
            .timeout(EXPORT_TIMEOUT)
            .connect_timeout(EXPORT_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()
            .map_err(|_| "telemetry HTTP client initialization failed")?;
        let resource = Resource::builder_empty()
            .with_attributes([
                KeyValue::new("service.name", "owlrora-server"),
                KeyValue::new("service.version", env!("CARGO_PKG_VERSION")),
            ])
            .build();
        let retry = opentelemetry_otlp::RetryPolicy::recommended()
            .with_max_retries(1)
            .with_initial_delay(Duration::from_millis(25))
            .with_max_delay(Duration::from_millis(25))
            .with_max_jitter(Duration::from_millis(10));
        let span_exporter = opentelemetry_otlp::SpanExporter::builder()
            .with_http()
            .with_endpoint(format!("{}/v1/traces", endpoint.trim_end_matches('/')))
            .with_protocol(opentelemetry_otlp::Protocol::HttpBinary)
            .with_timeout(EXPORT_TIMEOUT)
            .with_retry_policy(retry.clone())
            .with_http_client(client.clone())
            .build()
            .map_err(|_| "telemetry trace exporter initialization failed")?;
        let metric_exporter = opentelemetry_otlp::MetricExporter::builder()
            .with_http()
            .with_endpoint(format!("{}/v1/metrics", endpoint.trim_end_matches('/')))
            .with_protocol(opentelemetry_otlp::Protocol::HttpBinary)
            .with_timeout(EXPORT_TIMEOUT)
            .with_retry_policy(retry)
            .with_http_client(client)
            .build()
            .map_err(|_| "telemetry metric exporter initialization failed")?;
        let processor = BatchSpanProcessor::builder(CountedSpanExporter {
            inner: span_exporter,
            state: state.clone(),
        })
        .with_batch_config(
            BatchConfigBuilder::default()
                .with_max_queue_size(QUEUE_CAPACITY)
                .with_max_export_batch_size(BATCH_SIZE)
                .with_scheduled_delay(Duration::from_secs(1))
                .build(),
        )
        .build();
        let traces = SdkTracerProvider::builder()
            .with_resource(resource.clone())
            .with_sampler(Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(
                sample_ratio,
            ))))
            .with_max_attributes_per_span(16)
            .with_max_events_per_span(8)
            .with_span_processor(CountedProcessor {
                inner: processor,
                state: state.clone(),
            })
            .build();
        let metrics = SdkMeterProvider::builder()
            .with_resource(resource)
            .with_reader(
                PeriodicReader::builder(CountedMetricExporter {
                    inner: metric_exporter,
                    state: state.clone(),
                })
                .with_interval(Duration::from_secs(10))
                .build(),
            )
            .build();
        let meter = metrics.meter("owlrora.gateway");
        let observed = state.clone();
        meter
            .u64_observable_gauge("owlrora.telemetry.outstanding_spans")
            .with_callback(move |observer| {
                observer.observe(
                    observed.outstanding_spans.load(Ordering::Relaxed) as u64,
                    &[],
                );
            })
            .build();
        let observed = state.clone();
        meter
            .u64_observable_counter("owlrora.telemetry.dropped_spans")
            .with_callback(move |observer| {
                observer.observe(
                    observed.queue_dropped_spans.load(Ordering::Relaxed),
                    &[KeyValue::new("reason", "queue_full_or_closed")],
                );
                observer.observe(
                    observed.export_failed_spans.load(Ordering::Relaxed),
                    &[KeyValue::new("reason", "export_failed")],
                );
            })
            .build();
        let observed = state.clone();
        meter
            .u64_observable_counter("owlrora.telemetry.metric_export_failures")
            .with_callback(move |observer| {
                observer.observe(observed.metric_export_failures.load(Ordering::Relaxed), &[]);
            })
            .build();
        Ok(Arc::new(Self {
            tracer: traces.tracer("owlrora.gateway"),
            traces,
            metrics,
            state,
            facts: meter.u64_counter("owlrora.gateway.facts").build(),
            duration: meter
                .f64_histogram("owlrora.gateway.duration")
                .with_unit("s")
                .build(),
            units: meter
                .f64_counter("owlrora.gateway.units")
                .with_unit("{token}")
                .build(),
            cost: meter
                .f64_counter("owlrora.gateway.cost")
                .with_unit("{USD_nano}")
                .build(),
            unknown_cost: meter.u64_counter("owlrora.gateway.unknown_cost").build(),
            active: meter.i64_up_down_counter("owlrora.gateway.active").build(),
            http_requests: meter.u64_counter("owlrora.gateway.http_responses").build(),
            http_headers: meter
                .f64_histogram("owlrora.gateway.http_response_headers")
                .with_unit("s")
                .build(),
            http_bytes: meter
                .u64_counter("owlrora.gateway.http_bytes")
                .with_unit("By")
                .build(),
        }))
    }

    pub(crate) fn observe_process(&self, application: &Arc<crate::application::Application>) {
        let meter = self.metrics.meter("owlrora.process");
        let runtime = Arc::downgrade(application.runtime());
        meter
            .i64_observable_gauge("owlrora.runtime.revision")
            .with_callback(move |observer| {
                if let Some(runtime) = runtime.upgrade() {
                    observer.observe(runtime.status().applied_revision, &[]);
                }
            })
            .build();
        let runtime = Arc::downgrade(application.runtime());
        meter
            .i64_observable_gauge("owlrora.runtime.confirmation_age")
            .with_unit("ms")
            .with_callback(move |observer| {
                if let Some(runtime) = runtime.upgrade() {
                    observer.observe(
                        (chrono::Utc::now() - runtime.status().confirmed_at)
                            .num_milliseconds()
                            .max(0),
                        &[],
                    );
                }
            })
            .build();
        let app = Arc::downgrade(application);
        meter
            .u64_observable_gauge("owlrora.usage.pending_batches")
            .with_callback(move |observer| {
                if let Some(app) = app.upgrade() {
                    observer.observe(app.usage_status().pending_batches as u64, &[]);
                }
            })
            .build();
        let app = Arc::downgrade(application);
        meter
            .u64_observable_counter("owlrora.usage.lost_facts")
            .with_callback(move |observer| {
                if let Some(app) = app.upgrade() {
                    let status = app.usage_status();
                    observer.observe(
                        status.lost_logical_facts,
                        &[KeyValue::new("owlrora.fact", "logical")],
                    );
                    observer.observe(
                        status.lost_attempt_facts,
                        &[KeyValue::new("owlrora.fact", "attempt")],
                    );
                }
            })
            .build();
    }

    pub(crate) fn status(&self) -> TelemetryStatus {
        TelemetryStatus {
            enabled: true,
            outstanding_spans: self.state.outstanding_spans.load(Ordering::Acquire),
            queue_dropped_spans: self.state.queue_dropped_spans.load(Ordering::Relaxed),
            export_failed_spans: self.state.export_failed_spans.load(Ordering::Relaxed),
            exported_spans: self.state.exported_spans.load(Ordering::Relaxed),
            metric_export_failures: self.state.metric_export_failures.load(Ordering::Relaxed),
            metric_exports: self.state.metric_exports.load(Ordering::Relaxed),
            shutdown_failures: self.state.shutdown_failures.load(Ordering::Relaxed),
        }
    }

    pub(crate) fn span(
        &self,
        family: &'static str,
        protocol: &'static str,
        parent: &Context,
    ) -> TraceSpan {
        let span = self
            .tracer
            .span_builder(family)
            .with_kind(if family == "logical" {
                SpanKind::Server
            } else {
                SpanKind::Client
            })
            .with_attributes([KeyValue::new("owlrora.protocol", protocol)])
            .start_with_context(&self.tracer, parent);
        let labels = [
            KeyValue::new("owlrora.fact", family),
            KeyValue::new("owlrora.protocol", protocol),
        ];
        self.active.add(1, &labels);
        TraceSpan {
            context: parent.with_span(span),
            active: self.active.clone(),
            labels,
            ended: AtomicBool::new(false),
        }
    }

    #[allow(clippy::cast_precision_loss)]
    pub(crate) fn record(
        &self,
        family: &'static str,
        protocol: &'static str,
        outcome: &'static str,
        duration: Duration,
        input: u128,
        output: u128,
        cost: Option<u128>,
    ) {
        let attributes = [
            KeyValue::new("owlrora.fact", family),
            KeyValue::new("owlrora.protocol", protocol),
            KeyValue::new("owlrora.outcome", outcome),
        ];
        self.facts.add(1, &attributes);
        self.duration.record(duration.as_secs_f64(), &attributes);
        for (direction, count) in [("input", input), ("output", output)] {
            let mut labels = attributes.to_vec();
            labels.push(KeyValue::new("owlrora.direction", direction));
            self.units.add(count as f64, &labels);
        }
        if let Some(cost) = cost {
            self.cost.add(cost as f64, &attributes);
        } else {
            self.unknown_cost.add(1, &attributes);
        }
    }

    pub(crate) async fn shutdown(self: &Arc<Self>) {
        let this = self.clone();
        // Each SDK shutdown has a five-second wait. With 512 outstanding spans,
        // 128 per batch and a 500ms transport timeout, collector stalls stay
        // inside this bound. No unbounded spawn_blocking task is abandoned.
        if tokio::task::spawn_blocking(move || {
            if this
                .traces
                .shutdown_with_timeout(Duration::from_secs(5))
                .is_err()
            {
                this.state.shutdown_failures.fetch_add(1, Ordering::Relaxed);
            }
            if this
                .metrics
                .shutdown_with_timeout(Duration::from_secs(5))
                .is_err()
            {
                this.state.shutdown_failures.fetch_add(1, Ordering::Relaxed);
            }
        })
        .await
        .is_err()
        {
            self.state.shutdown_failures.fetch_add(1, Ordering::Relaxed);
        }
        let status = self.status();
        tracing::info!(
            event = "telemetry_shutdown",
            outstanding_spans = status.outstanding_spans,
            dropped_spans = status.queue_dropped_spans,
            failed_spans = status.export_failed_spans,
            metric_export_failures = status.metric_export_failures,
            shutdown_failures = status.shutdown_failures
        );
    }
}

pub(crate) struct TraceSpan {
    context: Context,
    active: UpDownCounter<i64>,
    labels: [KeyValue; 2],
    ended: AtomicBool,
}
impl TraceSpan {
    pub(crate) fn context(&self) -> Context {
        self.context.clone()
    }
    pub(crate) fn finish(&self, outcome: &'static str) {
        if !self.ended.swap(true, Ordering::AcqRel) {
            self.context
                .span()
                .set_attribute(KeyValue::new("owlrora.outcome", outcome));
            self.context.span().end();
            self.active.add(-1, &self.labels);
        }
    }
}
impl Drop for TraceSpan {
    fn drop(&mut self) {
        self.finish("cancelled");
    }
}

/// Transport evidence includes failures before typed Gateway admission. The
/// response-header histogram is deliberately not called total request duration.
pub(crate) async fn http_observation(
    axum::extract::State(application): axum::extract::State<Arc<crate::application::Application>>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use http_body_util::BodyExt as _;
    let Some(telemetry) = application.usage.telemetry.get() else {
        return next.run(request).await;
    };
    let started = std::time::Instant::now();
    let (parts, body) = request.into_parts();
    let bytes = telemetry.http_bytes.clone();
    let body = body.map_frame(move |frame| {
        if let Some(data) = frame.data_ref() {
            bytes.add(data.len() as u64, &[KeyValue::new("direction", "request")]);
        }
        frame
    });
    let response = next
        .run(axum::extract::Request::from_parts(
            parts,
            axum::body::Body::new(body),
        ))
        .await;
    let outcome = match response.status().as_u16() {
        100..=299 => "success",
        300..=399 => "redirect",
        401 => "unauthenticated",
        403 => "forbidden",
        429 => "limited",
        400..=499 => "client_error",
        _ => "server_error",
    };
    let labels = [KeyValue::new("owlrora.outcome", outcome)];
    telemetry.http_requests.add(1, &labels);
    telemetry
        .http_headers
        .record(started.elapsed().as_secs_f64(), &labels);
    let (parts, body) = response.into_parts();
    let bytes = telemetry.http_bytes.clone();
    let body = body.map_frame(move |frame| {
        if let Some(data) = frame.data_ref() {
            bytes.add(data.len() as u64, &[KeyValue::new("direction", "response")]);
        }
        frame
    });
    axum::response::Response::from_parts(parts, axum::body::Body::new(body))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use axum::{
        Router,
        body::Bytes,
        extract::State,
        http::{StatusCode, Uri},
        routing::post,
    };
    use opentelemetry_proto::tonic::collector::{
        metrics::v1::ExportMetricsServiceRequest, trace::v1::ExportTraceServiceRequest,
    };
    use prost::Message as _;
    use std::sync::Mutex;
    use tokio::net::TcpListener;

    #[derive(Clone, Default)]
    pub(crate) struct Collector {
        pub(crate) requests: Arc<Mutex<Vec<(String, Bytes)>>>,
        delay: Duration,
        fail: bool,
    }
    async fn receive(State(collector): State<Collector>, uri: Uri, body: Bytes) -> StatusCode {
        collector
            .requests
            .lock()
            .unwrap()
            .push((uri.path().to_owned(), body));
        tokio::time::sleep(collector.delay).await;
        if collector.fail {
            StatusCode::SERVICE_UNAVAILABLE
        } else {
            StatusCode::OK
        }
    }
    pub(crate) async fn collector_server(
        collector: Collector,
    ) -> (String, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let router = Router::new()
            .route("/v1/traces", post(receive))
            .route("/v1/metrics", post(receive))
            .with_state(collector);
        let task = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        (endpoint, task)
    }

    #[tokio::test]
    async fn standard_otlp_protobuf_exports_parented_spans_and_unsampled_metrics() {
        let collector = Collector::default();
        let (endpoint, task) = collector_server(collector.clone()).await;
        let telemetry = Telemetry::build(endpoint.clone(), 1.0).await.unwrap();
        let logical = telemetry.span("logical", "openai_responses", &Context::new());
        let attempt = telemetry.span("attempt", "openai_responses", &logical.context());
        attempt.finish("actual");
        logical.finish("success");
        telemetry.record(
            "attempt",
            "openai_responses",
            "actual",
            Duration::from_millis(12),
            3,
            5,
            Some(13),
        );
        telemetry.shutdown().await;
        assert_eq!(telemetry.status().exported_spans, 2);
        assert_eq!(telemetry.status().outstanding_spans, 0);
        assert_eq!(telemetry.status().shutdown_failures, 0);
        let requests = collector.requests.lock().unwrap().clone();
        let spans = requests
            .iter()
            .filter(|(path, _)| path == "/v1/traces")
            .flat_map(|(_, body)| {
                ExportTraceServiceRequest::decode(body.clone())
                    .unwrap()
                    .resource_spans
            })
            .flat_map(|resource| resource.scope_spans)
            .flat_map(|scope| scope.spans)
            .collect::<Vec<_>>();
        let root = spans.iter().find(|span| span.name == "logical").unwrap();
        let child = spans.iter().find(|span| span.name == "attempt").unwrap();
        assert_eq!(child.trace_id, root.trace_id);
        assert_eq!(child.parent_span_id, root.span_id);
        for span in &spans {
            assert!(span.attributes.iter().all(|attribute| matches!(
                attribute.key.as_str(),
                "owlrora.protocol" | "owlrora.outcome"
            )));
        }
        let metrics = requests
            .iter()
            .filter(|(path, _)| path == "/v1/metrics")
            .flat_map(|(_, body)| {
                ExportMetricsServiceRequest::decode(body.clone())
                    .unwrap()
                    .resource_metrics
            })
            .flat_map(|resource| resource.scope_metrics)
            .flat_map(|scope| scope.metrics)
            .collect::<Vec<_>>();
        assert!(
            metrics
                .iter()
                .any(|metric| metric.name == "owlrora.gateway.cost")
        );
        assert!(
            metrics
                .iter()
                .any(|metric| metric.name == "owlrora.telemetry.dropped_spans")
        );

        // Sampling never affects compact usage/metric facts; zero sampling
        // produces no spans but still sends metrics through the actual network.
        collector.requests.lock().unwrap().clear();
        let telemetry = Telemetry::build(endpoint, 0.0).await.unwrap();
        telemetry
            .span("logical", "openai_responses", &Context::new())
            .finish("success");
        telemetry.record(
            "logical",
            "openai_responses",
            "success",
            Duration::from_millis(1),
            0,
            0,
            Some(0),
        );
        telemetry.shutdown().await;
        assert_eq!(telemetry.status().exported_spans, 0);
        assert!(telemetry.status().metric_exports > 0);
        assert!(
            collector
                .requests
                .lock()
                .unwrap()
                .iter()
                .all(|(path, _)| path == "/v1/metrics")
        );
        task.abort();
        let _ = task.await;
    }

    #[tokio::test]
    async fn stalled_collector_bounds_memory_request_work_and_shutdown_with_exact_loss() {
        let collector = Collector {
            delay: Duration::from_secs(2),
            ..Collector::default()
        };
        let (endpoint, task) = collector_server(collector).await;
        let telemetry = Telemetry::build(endpoint, 1.0).await.unwrap();
        let started = std::time::Instant::now();
        for _ in 0..4096 {
            telemetry
                .span("logical", "openai_responses", &Context::new())
                .finish("success");
        }
        // This is local span work, not 4096 collector round trips.
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(telemetry.status().outstanding_spans <= QUEUE_CAPACITY);
        assert!(telemetry.status().queue_dropped_spans > 0);
        telemetry.record(
            "logical",
            "openai_responses",
            "success",
            Duration::from_millis(1),
            0,
            0,
            None,
        );
        tokio::time::timeout(Duration::from_secs(8), telemetry.shutdown())
            .await
            .unwrap();
        let status = telemetry.status();
        assert_eq!(status.outstanding_spans, 0);
        assert_eq!(
            status.queue_dropped_spans + status.export_failed_spans + status.exported_spans,
            4096
        );
        assert!(status.export_failed_spans > 0);
        assert!(status.metric_export_failures > 0);
        task.abort();
        let _ = task.await;
    }

    #[tokio::test]
    async fn failing_collector_is_best_effort_and_does_not_log_raw_errors() {
        let (endpoint, task) = collector_server(Collector {
            fail: true,
            ..Collector::default()
        })
        .await;
        let telemetry = Telemetry::build(endpoint, 1.0).await.unwrap();
        telemetry
            .span("logical", "anthropic_messages", &Context::new())
            .finish("success");
        telemetry.shutdown().await;
        assert_eq!(telemetry.status().export_failed_spans, 1);
        assert_eq!(telemetry.status().outstanding_spans, 0);
        let status = serde_json::to_string(&telemetry.status()).unwrap();
        assert!(!status.contains("http") && !status.contains("authorization"));
        task.abort();
        let _ = task.await;
    }
}
