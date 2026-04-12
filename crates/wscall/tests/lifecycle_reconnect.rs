#![cfg(all(feature = "client", feature = "server"))]

use std::error::Error;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde_json::json;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::time::{sleep, timeout};
use tokio_tungstenite::{accept_async, tungstenite::Message};
use wscall::{EncryptionKind, FrameCodec, PacketBody, PacketEnvelope, WscallClient, WscallServer};

static NEXT_PORT: AtomicU16 = AtomicU16::new(29100);

fn next_address() -> (String, String) {
    let port = NEXT_PORT.fetch_add(1, Ordering::Relaxed);
    (
        format!("127.0.0.1:{port}"),
        format!("ws://127.0.0.1:{port}/socket"),
    )
}

async fn recv_event<T>(rx: &mut mpsc::UnboundedReceiver<T>) -> T {
    timeout(Duration::from_secs(10), rx.recv())
        .await
        .expect("timed out waiting for event")
        .expect("event channel closed unexpectedly")
}

async fn run_test_protocol_server(
    address: String,
    label: &'static str,
    close_after_response: bool,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let listener = TcpListener::bind(&address).await?;
    let (stream, _) = listener.accept().await?;
    let websocket = accept_async(stream).await?;
    let (mut sink, mut stream) = websocket.split();
    let codec = FrameCodec::plaintext();

    while let Some(message) = stream.next().await {
        match message? {
            Message::Binary(bytes) => {
                let packet = codec.decode(&bytes)?;
                if let PacketBody::ApiRequest {
                    request_id,
                    route,
                    params,
                    ..
                } = packet.body
                {
                    let response = PacketEnvelope::with_encryption(
                        PacketBody::ApiResponse {
                            request_id,
                            ok: true,
                            status: 200,
                            data: json!({
                                "route": route,
                                "params": params,
                                "server": label,
                            }),
                            error: None,
                            metadata: json!({}),
                        },
                        EncryptionKind::None,
                    );

                    sink.send(Message::Binary(codec.encode(&response)?)).await?;

                    if close_after_response {
                        let _ = sink.send(Message::Close(None)).await;
                        break;
                    }
                }
            }
            Message::Close(_) => break,
            Message::Ping(payload) => {
                sink.send(Message::Pong(payload)).await?;
            }
            Message::Pong(_) | Message::Text(_) | Message::Frame(_) => {}
        }
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lifecycle_callbacks_fire_for_client_and_server() {
    let (address, url) = next_address();
    let (server_conn_tx, mut server_conn_rx) = mpsc::unbounded_channel();
    let (server_disc_tx, mut server_disc_rx) = mpsc::unbounded_channel();

    let mut server = WscallServer::new();
    server.on_connected(move |ctx| {
        let server_conn_tx = server_conn_tx.clone();
        async move {
            let _ = server_conn_tx.send(ctx.connection_id().to_string());
        }
    });
    server.on_disconnected(move |ctx| {
        let server_disc_tx = server_disc_tx.clone();
        async move {
            let _ = server_disc_tx.send((ctx.connection_id().to_string(), ctx.reason().to_string()));
        }
    });
    server.route("system.echo", |ctx| async move {
        Ok(json!({
            "route": ctx.route(),
            "message": ctx.param("message").and_then(|value| value.as_str()),
        }))
    });

    let server_task = tokio::spawn(async move { server.listen(&address).await });
    sleep(Duration::from_millis(100)).await;

    let client = WscallClient::connect(&url).await.expect("client should connect");
    let (client_conn_tx, mut client_conn_rx) = mpsc::unbounded_channel();
    let (client_disc_tx, mut client_disc_rx) = mpsc::unbounded_channel();

    client
        .on_connected(move |event| {
            let client_conn_tx = client_conn_tx.clone();
            async move {
                let _ = client_conn_tx.send(event.url);
            }
        })
        .await;
    client
        .on_disconnected(move |event| {
            let client_disc_tx = client_disc_tx.clone();
            async move {
                let _ = client_disc_tx.send((event.reason, event.will_reconnect, event.retry_after));
            }
        })
        .await;

    let server_connection_id = recv_event(&mut server_conn_rx).await;
    let client_connected_url = recv_event(&mut client_conn_rx).await;
    assert_eq!(client_connected_url, url);
    assert!(!server_connection_id.is_empty());

    let response = client
        .call("system.echo", json!({ "message": "hello" }), Vec::new())
        .await
        .expect("call should succeed");
    assert_eq!(response["route"], "system.echo");
    assert_eq!(response["message"], "hello");

    client.close().await.expect("close should succeed");

    let client_disconnect = recv_event(&mut client_disc_rx).await;
    assert_eq!(client_disconnect.0, "disconnected");
    assert!(!client_disconnect.1);
    assert_eq!(client_disconnect.2, None);

    let server_disconnect = recv_event(&mut server_disc_rx).await;
    assert_eq!(server_disconnect.0, server_connection_id);
    assert!(!server_disconnect.1.is_empty());

    server_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_reconnects_after_unexpected_disconnect() {
    let (address, url) = next_address();

    let first_server = tokio::spawn(run_test_protocol_server(address.clone(), "first", true));
    sleep(Duration::from_millis(100)).await;

    let client = WscallClient::connect(&url).await.expect("client should connect");
    let (connected_tx, mut connected_rx) = mpsc::unbounded_channel();
    let (disconnected_tx, mut disconnected_rx) = mpsc::unbounded_channel();

    client
        .on_connected(move |event| {
            let connected_tx = connected_tx.clone();
            async move {
                let _ = connected_tx.send(event.url);
            }
        })
        .await;
    client
        .on_disconnected(move |event| {
            let disconnected_tx = disconnected_tx.clone();
            async move {
                let _ = disconnected_tx.send((event.reason, event.will_reconnect, event.retry_after));
            }
        })
        .await;

    let first_connected_url = recv_event(&mut connected_rx).await;
    assert_eq!(first_connected_url, url);

    let first_response = client
        .call("system.echo", json!({ "round": 1 }), Vec::new())
        .await
        .expect("initial call should succeed");
    assert_eq!(first_response["server"], "first");

    first_server
        .await
        .expect("first server task should join")
        .expect("first server should exit cleanly");

    let disconnect_event = recv_event(&mut disconnected_rx).await;
    assert!(!disconnect_event.0.trim().is_empty());
    assert!(disconnect_event.1);
    assert_eq!(disconnect_event.2, Some(Duration::from_secs(3)));

    let second_server = tokio::spawn(run_test_protocol_server(address.clone(), "second", false));

    let second_connected_url = recv_event(&mut connected_rx).await;
    assert_eq!(second_connected_url, url);

    let response = timeout(Duration::from_secs(10), async {
        loop {
            match client
                .call("system.echo", json!({ "round": 2 }), Vec::new())
                .await
            {
                Ok(response) => break response,
                Err(_) => sleep(Duration::from_millis(200)).await,
            }
        }
    })
    .await
    .expect("client did not recover in time");

    assert_eq!(response["server"], "second");

    client.close().await.expect("close should succeed");

    second_server.abort();
}