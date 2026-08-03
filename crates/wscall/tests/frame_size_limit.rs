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

        let packet = codec.decode(bytes).expect("frame should decode");
        if matches!(packet.body, PacketBody::ApiResponse { .. }) {
            return packet.body;
        }
    }
}

/// A frame whose declared header length mismatches the actual payload is
/// rejected with a 413 error response while the connection stays open.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mismatched_frame_header_returns_413_and_keeps_connection_open() {
    let (address, url) = next_address();

    let mut server = WscallServer::new();
    server.route("system.echo", |ctx| async move {
        Ok(json!({ "message": ctx.param("message") }))
    });

    let server_task = tokio::spawn(async move { server.listen(&address).await });
    sleep(Duration::from_millis(100)).await;

    let (mut ws, _) = connect_async(&url)
        .await
        .expect("ws connect should succeed");
    let codec = FrameCodec::plaintext();

    // 1) Craft a frame with a bogus declared length (first 4 bytes) that does
    //    NOT match the actual payload size. The frame is small enough to pass
    //    the WebSocket-level limit but fails the WSCALL header check.
    let mut bogus_frame = Vec::new();
    bogus_frame.extend_from_slice(&9999u32.to_be_bytes()); // declared = 9999
    bogus_frame.push(0x00); // message_type = Api
    bogus_frame.extend_from_slice(b"some payload");
    ws.send(Message::Binary(bogus_frame.into()))
        .await
        .expect("send bogus frame");

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

/// A frame exceeding `max_frame_bytes` is rejected at the WebSocket protocol
/// layer (tungstenite closes the connection) — no 413 is sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oversized_frame_closes_connection() {
    let (address, url) = next_address();

    let max_frame_bytes = 200usize;
    let mut server = WscallServer::new().with_max_frame_bytes(max_frame_bytes);
    server.route("system.echo", |ctx| async move {
        Ok(json!({ "message": ctx.param("message") }))
    });

    let server_task = tokio::spawn(async move { server.listen(&address).await });
    sleep(Duration::from_millis(100)).await;

    let (mut ws, _) = connect_async(&url)
        .await
        .expect("ws connect should succeed");

    // Drain the initial system.notice event so it doesn't interfere.
    let _ = timeout(Duration::from_secs(5), ws.next()).await;

    // Send a frame larger than max_frame_bytes; tungstenite will reject it at
    // the WebSocket level and close the connection.
    let oversized = vec![0u8; max_frame_bytes + 100];
    let _ = ws.send(Message::Binary(oversized.into())).await;

    // The connection should be closed by the server. We may need to skip
    // a ping frame or two before seeing the close.
    let mut closed = false;
    for _ in 0..5 {
        match timeout(Duration::from_secs(5), ws.next()).await {
            Ok(Some(Err(_))) | Ok(None) => {
                closed = true;
                break;
            }
            Ok(Some(Ok(Message::Close(_)))) => {
                closed = true;
                break;
            }
            Ok(Some(Ok(_))) => continue, // skip pings/other frames
            Err(_) => break,
        }
    }
    assert!(
        closed,
        "connection should have been closed after oversized frame"
    );

    server_task.abort();
}
