#![cfg(all(feature = "client", feature = "server"))]

use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde_json::json;
use tokio::net::TcpStream;
use tokio::time::{sleep, timeout};
use tokio_tungstenite::MaybeTlsStream;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;
use wscall::{EncryptionKind, FrameCodec, PacketBody, PacketEnvelope, WscallServer};

static NEXT_PORT: AtomicU16 = AtomicU16::new(29200);

fn next_address() -> (String, String) {
    let port = NEXT_PORT.fetch_add(1, Ordering::Relaxed);
    (
        format!("127.0.0.1:{port}"),
        format!("ws://127.0.0.1:{port}/socket"),
    )
}

/// Read frames until the next API response arrives, skipping server-pushed
/// events (e.g. the `system.notice` connection notification).
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

        let packet = codec.decode(&bytes).expect("frame should decode");
        if matches!(packet.body, PacketBody::ApiResponse { .. }) {
            return packet.body;
        }
    }
}

/// An oversized uplink frame must be answered with a 413 error response while
/// the connection stays open: a subsequent well-formed request still succeeds.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oversized_frame_returns_413_and_keeps_connection_open() {
    let (address, url) = next_address();

    // Small limit so a modest probe frame already exceeds it.
    let max_frame_bytes = 200usize;
    let mut server = WscallServer::new().with_max_frame_bytes(max_frame_bytes);
    server.route("system.echo", |ctx| async move {
        Ok(json!({ "message": ctx.param("message") }))
    });

    let server_task = tokio::spawn(async move { server.listen(&address).await });
    sleep(Duration::from_millis(100)).await;

    // Raw WebSocket client bypasses the SDK's encode-side size check.
    let (mut ws, _) = connect_async(&url)
        .await
        .expect("ws connect should succeed");
    let codec = FrameCodec::plaintext();

    // 1) Send an oversized binary frame (larger than max_frame_bytes, well
    //    within the WebSocket-level headroom) and expect a 413 error response.
    let oversized = vec![0u8; max_frame_bytes + 100];
    ws.send(Message::Binary(oversized.into()))
        .await
        .expect("send oversized");

    let error_body = next_api_response(&mut ws, &codec).await;
    match error_body {
        PacketBody::ApiResponse {
            request_id,
            ok,
            status,
            ref error,
            ..
        } => {
            assert_eq!(request_id, 0, "protocol-level error uses request_id 0");
            assert!(!ok);
            assert_eq!(status, 413);
            let payload = error
                .as_ref()
                .expect("413 response carries an error payload");
            assert_eq!(payload.code, "frame_too_large");
        }
        other => panic!("expected ApiResponse, got: {other:?}"),
    }

    // 2) The connection must still be open: a normal request round-trips.
    let request = PacketEnvelope::with_encryption(
        PacketBody::ApiRequest {
            request_id: 1,
            route: "system.echo".to_string(),
            params: json!({ "message": "still alive" }),
            attachments: Vec::new(),
            metadata: json!({}),
        },
        EncryptionKind::None,
    );
    ws.send(Message::Binary(
        codec.encode(&request).expect("encode request").into(),
    ))
    .await
    .expect("send normal request after 413");

    let ok_body = next_api_response(&mut ws, &codec).await;
    match ok_body {
        PacketBody::ApiResponse {
            request_id,
            ok,
            status,
            ref data,
            ..
        } => {
            assert_eq!(request_id, 1);
            assert!(ok);
            assert_eq!(status, 200);
            assert_eq!(data["message"], "still alive");
        }
        other => panic!("expected ApiResponse, got: {other:?}"),
    }

    let _ = ws.close(None).await;
    server_task.abort();
}
