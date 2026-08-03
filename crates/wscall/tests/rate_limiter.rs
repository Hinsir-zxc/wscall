#![cfg(all(feature = "client", feature = "server"))]

use std::sync::Arc;
use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde_json::json;
use tokio::net::TcpStream;
use tokio::time::{sleep, timeout};
use tokio_tungstenite::MaybeTlsStream;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;
use wscall::{
    EncryptionKind, FrameCodec, PacketBody, PacketEnvelope, RateLimitConfig, RateLimiter,
    WscallServer,
};

static NEXT_PORT: AtomicU16 = AtomicU16::new(29300);

fn next_address() -> (String, String) {
    let port = NEXT_PORT.fetch_add(1, Ordering::Relaxed);
    (
        format!("127.0.0.1:{port}"),
        format!("ws://127.0.0.1:{port}/socket"),
    )
}

/// Read frames until the next API response arrives, skipping server-pushed events.
async fn next_api_response(
    ws: &mut WebSocketStream<MaybeTlsStream<TcpStream>>,
    codec: &FrameCodec,
) -> PacketBody {
    loop {
        let message = timeout(Duration::from_secs(10), ws.next())
            .await
            .expect("timed out waiting for a frame")
            .expect("connection closed unexpectedly")
            .expect("websocket error");

        let Message::Binary(bytes) = message else {
            continue;
        };

        let packet = codec.decode(bytes).expect("frame should decode");
        if matches!(packet.body, PacketBody::ApiResponse { .. }) {
            return packet.body;
        }
    }
}

/// Read frames until the next EventAck arrives.
async fn next_event_ack(
    ws: &mut WebSocketStream<MaybeTlsStream<TcpStream>>,
    codec: &FrameCodec,
) -> PacketBody {
    loop {
        let message = timeout(Duration::from_secs(10), ws.next())
            .await
            .expect("timed out waiting for a frame")
            .expect("connection closed unexpectedly")
            .expect("websocket error");

        let Message::Binary(bytes) = message else {
            continue;
        };

        let packet = codec.decode(bytes).expect("frame should decode");
        if matches!(packet.body, PacketBody::EventAck { .. }) {
            return packet.body;
        }
    }
}

fn make_request(request_id: u64, route: &str) -> PacketEnvelope {
    PacketEnvelope::with_encryption(
        PacketBody::ApiRequest {
            request_id,
            route: route.to_string(),
            params: json!({}),
            attachments: Vec::new(),
            metadata: json!({}),
        },
        EncryptionKind::None,
    )
}

fn make_event(event_id: u64, name: &str) -> PacketEnvelope {
    PacketEnvelope::with_encryption(
        PacketBody::EventEmit {
            event_id,
            name: name.to_string(),
            data: json!({}).as_object().unwrap().clone(),
            attachments: Vec::new(),
            metadata: json!({}),
            expect_ack: true,
        },
        EncryptionKind::None,
    )
}

/// Connection-level frequency limit: after exceeding max_messages, route
/// requests receive 503 service_busy.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connection_rate_limit_returns_503() {
    let (address, url) = next_address();

    let limiter = RateLimiter::new()
        .connection(RateLimitConfig::new(Duration::from_secs(60)).max_messages(3));

    let mut server = WscallServer::new().with_rate_limiter(limiter);
    server.route("ping", |_ctx| async { Ok(json!("pong")) });

    let server_task = tokio::spawn(async move { server.listen(&address).await });
    sleep(Duration::from_millis(100)).await;

    let (mut ws, _) = connect_async(&url).await.expect("connect");
    let codec = FrameCodec::plaintext();

    // First 3 requests should succeed.
    for i in 1..=3 {
        ws.send(Message::Binary(
            codec.encode(&make_request(i, "ping")).unwrap().into(),
        ))
        .await
        .unwrap();

        let body = next_api_response(&mut ws, &codec).await;
        match body {
            PacketBody::ApiResponse {
                request_id,
                ok,
                status,
                ..
            } => {
                assert_eq!(request_id, i);
                assert!(ok, "request {i} should succeed");
                assert_eq!(status, 200);
            }
            other => panic!("expected ApiResponse, got: {other:?}"),
        }
    }

    // 4th and 5th requests should be rate-limited (503).
    for i in 4..=5 {
        ws.send(Message::Binary(
            codec.encode(&make_request(i, "ping")).unwrap().into(),
        ))
        .await
        .unwrap();

        let body = next_api_response(&mut ws, &codec).await;
        match body {
            PacketBody::ApiResponse {
                request_id,
                ok,
                status,
                ref error,
                ..
            } => {
                assert_eq!(request_id, i);
                assert!(!ok, "request {i} should be rate-limited");
                assert_eq!(status, 503);
                let payload = error.as_ref().expect("503 carries error payload");
                assert_eq!(payload.code, "service_busy");
            }
            other => panic!("expected ApiResponse, got: {other:?}"),
        }
    }

    let _ = ws.close(None).await;
    server_task.abort();
}

/// Rate-limited events are silently discarded: the client receives an ok:true
/// ack but the handler is never invoked.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rate_limited_event_silently_discarded() {
    let (address, url) = next_address();

    let handler_calls = Arc::new(AtomicU64::new(0));
    let handler_calls_clone = Arc::clone(&handler_calls);

    let limiter = RateLimiter::new()
        .connection(RateLimitConfig::new(Duration::from_secs(60)).max_messages(2));

    let mut server = WscallServer::new().with_rate_limiter(limiter);
    server.event_handler("test.event", move |_ctx| {
        let calls = Arc::clone(&handler_calls_clone);
        async move {
            calls.fetch_add(1, Ordering::Relaxed);
            Ok(json!({ "received": true }))
        }
    });

    let server_task = tokio::spawn(async move { server.listen(&address).await });
    sleep(Duration::from_millis(100)).await;

    let (mut ws, _) = connect_async(&url).await.expect("connect");
    let codec = FrameCodec::plaintext();

    // First 2 events should be processed normally.
    for i in 1..=2 {
        ws.send(Message::Binary(
            codec.encode(&make_event(i, "test.event")).unwrap().into(),
        ))
        .await
        .unwrap();

        let body = next_event_ack(&mut ws, &codec).await;
        match body {
            PacketBody::EventAck { event_id, ok, .. } => {
                assert_eq!(event_id, i);
                assert!(ok);
            }
            other => panic!("expected EventAck, got: {other:?}"),
        }
    }

    assert_eq!(handler_calls.load(Ordering::Relaxed), 2);

    // 3rd event should be silently discarded (ok:true ack, handler NOT called).
    ws.send(Message::Binary(
        codec.encode(&make_event(3, "test.event")).unwrap().into(),
    ))
    .await
    .unwrap();

    let body = next_event_ack(&mut ws, &codec).await;
    match body {
        PacketBody::EventAck {
            event_id,
            ok,
            ref receipt,
            ref error,
        } => {
            assert_eq!(event_id, 3);
            assert!(ok, "silent discard still sends ok:true");
            assert_eq!(receipt, &json!({}));
            assert!(error.is_none());
        }
        other => panic!("expected EventAck, got: {other:?}"),
    }

    // Handler was NOT called for the 3rd event.
    assert_eq!(
        handler_calls.load(Ordering::Relaxed),
        2,
        "handler must not be invoked for rate-limited events"
    );

    let _ = ws.close(None).await;
    server_task.abort();
}

/// When ban_duration is configured with IP-level limits, triggering the
/// limit bans the IP; new connections from the same IP are rejected.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ban_rejects_new_connections() {
    let (address, url) = next_address();

    let limiter = RateLimiter::new()
        .ip(RateLimitConfig::new(Duration::from_secs(60)).max_messages(2))
        .ban_duration(Duration::from_secs(30));

    let mut server = WscallServer::new().with_rate_limiter(limiter);
    server.route("ping", |_ctx| async { Ok(json!("pong")) });

    let server_task = tokio::spawn(async move { server.listen(&address).await });
    sleep(Duration::from_millis(100)).await;

    let (mut ws, _) = connect_async(&url).await.expect("connect");
    let codec = FrameCodec::plaintext();

    // Exhaust the limit (2 messages allowed).
    for i in 1..=2 {
        ws.send(Message::Binary(
            codec.encode(&make_request(i, "ping")).unwrap().into(),
        ))
        .await
        .unwrap();
        let _ = next_api_response(&mut ws, &codec).await;
    }

    // 3rd message triggers the ban.
    ws.send(Message::Binary(
        codec.encode(&make_request(3, "ping")).unwrap().into(),
    ))
    .await
    .unwrap();
    let body = next_api_response(&mut ws, &codec).await;
    match body {
        PacketBody::ApiResponse { status, ok, .. } => {
            assert!(!ok);
            assert_eq!(status, 503);
        }
        other => panic!("expected 503, got: {other:?}"),
    }

    let _ = ws.close(None).await;
    sleep(Duration::from_millis(50)).await;

    // A new connection from the same IP (127.0.0.1) should be rejected.
    // The TCP connect may succeed but the WebSocket upgrade will fail because
    // the server drops the stream before upgrading.
    let result = timeout(Duration::from_secs(3), connect_async(&url)).await;
    match result {
        Ok(Err(_)) => { /* connection rejected as expected */ }
        Ok(Ok((mut ws, _))) => {
            // If the upgrade somehow succeeded, the connection should close
            // immediately.
            let next = timeout(Duration::from_secs(2), ws.next()).await;
            match next {
                Ok(None) | Ok(Some(Err(_))) => { /* closed */ }
                _ => panic!("banned IP connection should not stay open"),
            }
        }
        Err(_) => panic!("timed out trying to connect (expected fast rejection)"),
    }

    server_task.abort();
}

/// IP-level byte volume limit: exceeding max_bytes triggers rate limiting
/// across all connections from that IP.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ip_byte_volume_limit() {
    let (address, url) = next_address();

    // Very small byte budget: 512 bytes per 60s window.
    let limiter =
        RateLimiter::new().ip(RateLimitConfig::new(Duration::from_secs(60)).max_bytes(512));

    let mut server = WscallServer::new().with_rate_limiter(limiter);
    server.route("ping", |_ctx| async { Ok(json!("pong")) });

    let server_task = tokio::spawn(async move { server.listen(&address).await });
    sleep(Duration::from_millis(100)).await;

    let (mut ws, _) = connect_async(&url).await.expect("connect");
    let codec = FrameCodec::plaintext();

    // Send requests with large params to quickly exhaust the byte budget.
    let large_params = json!({ "payload": "x".repeat(200) });
    let mut rate_limited = false;

    for i in 1..=10 {
        let request = PacketEnvelope::with_encryption(
            PacketBody::ApiRequest {
                request_id: i,
                route: "ping".to_string(),
                params: large_params.clone(),
                attachments: Vec::new(),
                metadata: json!({}),
            },
            EncryptionKind::None,
        );
        ws.send(Message::Binary(codec.encode(&request).unwrap().into()))
            .await
            .unwrap();

        let body = next_api_response(&mut ws, &codec).await;
        match body {
            PacketBody::ApiResponse { status, ok, .. } => {
                if !ok && status == 503 {
                    rate_limited = true;
                    break;
                }
                assert!(ok);
            }
            other => panic!("expected ApiResponse, got: {other:?}"),
        }
    }

    assert!(
        rate_limited,
        "should have been rate-limited by IP byte volume"
    );

    let _ = ws.close(None).await;
    server_task.abort();
}
