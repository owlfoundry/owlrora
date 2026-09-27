//! Process-local drain authority. Cancellation drops request owners before final flush.
use std::{future::Future, sync::Mutex, time::Duration};

use tokio::{sync::watch, task::JoinHandle, time::Instant};
use tokio_util::task::TaskTracker;

#[derive(Debug)]
pub(crate) struct Lifecycle {
    draining: watch::Sender<Option<Instant>>,
    pub upgrades: TaskTracker,
    pub response_pumps: TaskTracker,
    controllers: Mutex<Vec<JoinHandle<()>>>,
}

impl Default for Lifecycle {
    fn default() -> Self {
        Self {
            draining: watch::channel(None).0,
            upgrades: TaskTracker::new(),
            response_pumps: TaskTracker::new(),
            controllers: Mutex::new(Vec::new()),
        }
    }
}

impl Lifecycle {
    pub fn accepting(&self) -> bool {
        self.draining.borrow().is_none()
    }

    pub fn begin_drain(&self) {
        self.draining.send_if_modified(|started| {
            if started.is_some() {
                return false;
            }
            *started = Some(Instant::now());
            true
        });
    }

    pub async fn cancelled_after(&self, grace: Duration) {
        let mut receiver = self.draining.subscribe();
        loop {
            let started = *receiver.borrow_and_update();
            if let Some(started) = started {
                tokio::time::sleep_until(started + grace).await;
                return;
            }
            if receiver.changed().await.is_err() {
                return;
            }
        }
    }

    pub fn spawn_controller(&self, future: impl Future<Output = ()> + Send + 'static) {
        let mut tasks = self.controllers.lock().expect("controller registry");
        if !self.accepting() {
            return;
        }
        tasks.retain(|task| !task.is_finished());
        tasks.push(tokio::spawn(future));
    }

    pub async fn stop_controllers(&self) {
        let tasks = std::mem::take(&mut *self.controllers.lock().expect("controller registry"));
        for task in &tasks {
            task.abort();
        }
        for task in tasks {
            let _ = task.await;
        }
    }
}

#[derive(Clone)]
pub(crate) struct DrainPolicy {
    pub lifecycle: std::sync::Arc<Lifecycle>,
    pub request_grace: Duration,
    pub stream_grace: Duration,
}

pub(crate) async fn request_drain(
    axum::extract::State(policy): axum::extract::State<DrainPolicy>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::response::IntoResponse as _;
    use http_body_util::BodyExt as _;
    if !policy.lifecycle.accepting() {
        if matches!(request.uri().path(), "/health" | "/ready") {
            return next.run(request).await;
        }
        return axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    let connection_drain = request.extensions().get::<ConnectionDrain>().cloned();
    if let Some(drain) = &connection_drain {
        drain.0.send_replace(policy.request_grace);
    }
    let response = tokio::select! {
        response = next.run(request) => response,
        () = policy.lifecycle.cancelled_after(policy.request_grace) => {
            return axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };
    let streaming = response
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .is_some_and(|value| value.as_bytes().starts_with(b"text/event-stream"));
    let grace = if streaming {
        policy.stream_grace
    } else {
        policy.request_grace
    };
    if let Some(drain) = connection_drain {
        drain.0.send_replace(grace);
    }
    let (parts, mut body) = response.into_parts();
    let frames = async_stream::stream! {
        loop {
            let frame = tokio::select! {
                frame = body.frame() => frame,
                () = policy.lifecycle.cancelled_after(grace) => {
                    yield Err(axum::Error::new(std::io::Error::new(std::io::ErrorKind::Interrupted, "server draining")));
                    break;
                }
            };
            match frame { Some(frame) => yield frame, None => break }
        }
    };
    axum::response::Response::from_parts(
        parts,
        axum::body::Body::new(http_body_util::StreamBody::new(frames)),
    )
}

#[derive(Clone)]
struct ConnectionDrain(watch::Sender<Duration>);

async fn connection_deadline(lifecycle: &Lifecycle, mut grace: watch::Receiver<Duration>) {
    loop {
        let current = *grace.borrow_and_update();
        tokio::select! {
            () = lifecycle.cancelled_after(current) => return,
            changed = grace.changed() => if changed.is_err() { return; },
        }
    }
}

/// Own connection tasks, including idle keep-alive sockets. Axum's public serve
/// future alone cannot abort and join its internally spawned connections.
pub(crate) async fn serve<F>(
    listener: tokio::net::TcpListener,
    router: axum::Router,
    lifecycle: std::sync::Arc<Lifecycle>,
    request_grace: Duration,
    stream_grace: Duration,
    shutdown: F,
) -> std::io::Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    use hyper::server::conn::http1::Builder;
    use hyper_util::{rt::TokioIo, service::TowerToHyperService};
    let (stop, _) = watch::channel(false);
    let mut connections = tokio::task::JoinSet::new();
    tokio::pin!(shutdown);
    let result: std::io::Result<()> = 'accept: loop {
        tokio::select! {
            () = &mut shutdown => break Ok(()),
            Some(_) = connections.join_next(), if !connections.is_empty() => {},
            accepted = listener.accept() => {
                let (socket, address) = match accepted {
                    Ok(value) => value,
                    Err(error) => {
                        if matches!(error.kind(), std::io::ErrorKind::ConnectionAborted | std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionRefused) { continue; }
                        tracing::warn!(event_name="server.accept_retry", kind=?error.kind(), "listener accept failed; retrying after bounded backoff");
                        tokio::select! {
                            () = &mut shutdown => break 'accept Ok(()),
                            () = tokio::time::sleep(Duration::from_secs(1)) => continue,
                        }
                    }
                };
                let (drain, grace) = watch::channel(request_grace);
                let service = TowerToHyperService::new(router.clone()
                    .layer(axum::Extension(axum::extract::ConnectInfo(address)))
                    .layer(axum::Extension(ConnectionDrain(drain))));
                let mut stop = stop.subscribe();
                let lifecycle = lifecycle.clone();
                connections.spawn(async move {
                    // Preserve the existing HTTP/1 backend protocol. TLS/HTTP/2
                    // termination belongs to the configured reverse proxy.
                    let connection = Builder::new().serve_connection(TokioIo::new(socket), service).with_upgrades();
                    tokio::pin!(connection);
                    tokio::select! {
                        _ = &mut connection => {},
                        _ = stop.changed() => {
                            connection.as_mut().graceful_shutdown();
                            tokio::select! {
                                _ = connection => {},
                                () = connection_deadline(&lifecycle, grace) => {},
                            }
                        }
                    }
                });
            }
        }
    };
    lifecycle.begin_drain();
    drop(listener);
    stop.send_replace(true);
    let deadline = Instant::now() + request_grace.max(stream_grace);
    if tokio::time::timeout_at(deadline, async {
        while connections.join_next().await.is_some() {}
    })
    .await
    .is_err()
    {
        connections.abort_all();
        while connections.join_next().await.is_some() {}
    }
    lifecycle.upgrades.close();
    lifecycle.upgrades.wait().await;
    lifecycle.response_pumps.close();
    lifecycle.response_pumps.wait().await;
    result
}

/// Timeouts alone detach a `JoinHandle`. Always abort and join on expiry.
pub(crate) async fn join_bounded(mut task: JoinHandle<()>, grace: Duration) -> bool {
    if tokio::time::timeout(grace, &mut task).await.is_ok() {
        return true;
    }
    task.abort();
    let _ = task.await;
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Router,
        body::{Body, Bytes},
        response::IntoResponse,
        routing::get,
    };
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    use tokio::sync::{Notify, oneshot};

    struct Dropped(Arc<AtomicBool>);
    impl Drop for Dropped {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn bounded_join_aborts_and_joins_instead_of_detaching() {
        let dropped = Arc::new(AtomicBool::new(false));
        let guard = Dropped(dropped.clone());
        let task = tokio::spawn(async move {
            let _guard = guard;
            std::future::pending::<()>().await;
        });
        assert!(!join_bounded(task, Duration::from_millis(10)).await);
        assert!(dropped.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn shutdown_cancels_http_and_stream_owners_under_separate_bounds() {
        let lifecycle = Arc::new(Lifecycle::default());
        let request_dropped = Arc::new(AtomicBool::new(false));
        let stream_dropped = Arc::new(AtomicBool::new(false));
        let large_dropped = Arc::new(AtomicBool::new(false));
        let large_flag = large_dropped.clone();
        let entered = Arc::new(Notify::new());
        let request_flag = request_dropped.clone();
        let stream_flag = stream_dropped.clone();
        let notify = entered.clone();
        let request_grace = Duration::from_millis(30);
        let stream_grace = Duration::from_millis(160);
        let router = Router::new()
            .route(
                "/large",
                get(move || {
                    let guard = Dropped(large_flag.clone());
                    async move {
                        Body::from_stream(async_stream::stream! {
                            let _guard = guard;
                            loop { yield Ok::<_, std::io::Error>(Bytes::from(vec![0_u8; 65536])); }
                        })
                    }
                }),
            )
            .route(
                "/blocked",
                get(move || {
                    let guard = Dropped(request_flag.clone());
                    let notify = notify.clone();
                    async move {
                        let _guard = guard;
                        notify.notify_one();
                        std::future::pending::<()>().await;
                        "unreachable"
                    }
                }),
            )
            .route(
                "/stream",
                get(move || {
                    let guard = Dropped(stream_flag.clone());
                    async move {
                        let stream = async_stream::stream! {
                            let _guard = guard;
                            yield Ok::<_, std::io::Error>(Bytes::from_static(b"data: ready\n\n"));
                            std::future::pending::<()>().await;
                        };
                        (
                            [("content-type", "text/event-stream")],
                            Body::from_stream(stream),
                        )
                            .into_response()
                    }
                }),
            )
            .layer(axum::middleware::from_fn_with_state(
                DrainPolicy {
                    lifecycle: lifecycle.clone(),
                    request_grace,
                    stream_grace,
                },
                request_drain,
            ));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (stop, stopped) = oneshot::channel();
        let server = tokio::spawn(serve(
            listener,
            router,
            lifecycle.clone(),
            request_grace,
            stream_grace,
            async {
                let _ = stopped.await;
            },
        ));
        let idle = tokio::net::TcpStream::connect(address).await.unwrap();
        let blocked =
            tokio::spawn(async move { reqwest::get(format!("http://{address}/blocked")).await });
        entered.notified().await;
        let mut stream = reqwest::get(format!("http://{address}/stream"))
            .await
            .unwrap();
        assert!(stream.chunk().await.unwrap().is_some());
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let mut stalled = tokio::net::TcpStream::connect(address).await.unwrap();
        stalled
            .write_all(b"GET /large HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut first = [0_u8; 1024];
        assert!(stalled.read(&mut first).await.unwrap() > 0);
        // Stop reading: Hyper can now be blocked on socket writes, not poll_frame.
        stop.send(()).unwrap();
        let response = tokio::time::timeout(Duration::from_millis(100), blocked)
            .await
            .unwrap()
            .unwrap();
        if let Ok(response) = response {
            assert_eq!(response.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
        }
        tokio::time::timeout(Duration::from_millis(70), async {
            while !large_dropped.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(request_dropped.load(Ordering::SeqCst));
        assert!(!stream_dropped.load(Ordering::SeqCst));
        assert!(!lifecycle.accepting());
        tokio::time::timeout(Duration::from_secs(1), server)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(stream_dropped.load(Ordering::SeqCst));
        assert!(lifecycle.response_pumps.is_empty());
        drop(idle);
    }

    #[tokio::test]
    async fn draining_is_sticky_and_controllers_cannot_restart() {
        let lifecycle = Lifecycle::default();
        lifecycle.begin_drain();
        let guard = Dropped(Arc::new(AtomicBool::new(false)));
        let dropped = guard.0.clone();
        lifecycle.spawn_controller(async move {
            let _guard = guard;
            std::future::pending::<()>().await;
        });
        assert!(dropped.load(Ordering::SeqCst));
        assert!(!lifecycle.accepting());
        lifecycle.cancelled_after(Duration::ZERO).await;
        lifecycle.stop_controllers().await;
    }
}
