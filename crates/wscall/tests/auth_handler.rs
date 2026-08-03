#![cfg(all(feature = "client", feature = "server"))]

use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;

use serde_json::{Map, Value, json};
use tokio::sync::mpsc;
use tokio::time::{sleep, timeout};
use wscall::{ApiError, AuthOutput, ClientError, WscallClient, WscallClientConfig, WscallServer};

static NEXT_PORT: AtomicU16 = AtomicU16::new(29200);

fn next_address() -> (String, String) {
    let port = NEXT_PORT.fetch_add(1, Ordering::Relaxed);
    (
        format!("127.0.0.1:{port}"),
        format!("ws://127.0.0.1:{port}/socket"),
    )
}

async fn recv_event<T>(rx: &mut mpsc::UnboundedReceiver<T>, secs: u64) -> T {
    timeout(Duration::from_secs(secs), rx.recv())
        .await
        .expect("timed out waiting for event")
        .expect("event channel closed unexpectedly")
}

fn client_config_with_credential(credential: Option<&str>) -> WscallClientConfig {
    let config = WscallClientConfig::plaintext().with_auto_reconnect(false);
    match credential {
        Some(credential) => config.with_credential(credential),
        None => config,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn auth_success_allows_connection() {
    let (address, url) = next_address();

    let mut server = WscallServer::new();
    server.auth_handler(|ctx| async move {
        if ctx.credential() == "secret-token" {
            Ok(AuthOutput::new())
        } else {
            Err(ApiError::unauthorized("bad token"))
        }
    });
    server.route("system.echo", |ctx| async move {
        Ok(json!({ "message": ctx.param("message").and_then(|v| v.as_str()) }))
    });

    let server_task = tokio::spawn(async move { server.listen(&address).await });
    sleep(Duration::from_millis(100)).await;

    let client = WscallClient::connect(&url, client_config_with_credential(Some("secret-token")))
        .await
        .expect("client should connect after successful auth");

    let response = client
        .call("system.echo", json!({ "message": "hello" }), Vec::new())
        .await
        .expect("call should succeed after auth");
    assert_eq!(response["message"], "hello");

    client.close().await.expect("close should succeed");
    server_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn auth_failure_rejects_connection() {
    let (address, url) = next_address();

    let mut server = WscallServer::new();
    server.auth_handler(|_ctx| async move { Err(ApiError::unauthorized("invalid credential")) });
    server.route("system.echo", |_ctx| async move { Ok(json!({})) });

    let server_task = tokio::spawn(async move { server.listen(&address).await });
    sleep(Duration::from_millis(100)).await;

    let result =
        WscallClient::connect(&url, client_config_with_credential(Some("wrong-token"))).await;

    match result {
        Err(ClientError::AuthFailed(payload)) => {
            assert_eq!(payload.code, "unauthorized");
            assert_eq!(payload.status, 401);
        }
        Err(other) => panic!("expected ClientError::AuthFailed, got: {other:?}"),
        Ok(_) => panic!("expected connect to fail with AuthFailed"),
    }

    server_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_auth_handler_skips_auth() {
    let (address, url) = next_address();

    let mut server = WscallServer::new();
    server.route("system.echo", |ctx| async move {
        Ok(json!({ "message": ctx.param("message").and_then(|v| v.as_str()) }))
    });

    let server_task = tokio::spawn(async move { server.listen(&address).await });
    sleep(Duration::from_millis(100)).await;

    // No auth_handler on the server, no credential on the client: the
    // connection proceeds without any auth phase (full backward compat).
    let client = WscallClient::connect(&url, client_config_with_credential(None))
        .await
        .expect("client should connect without auth");

    let response = client
        .call("system.echo", json!({ "message": "legacy" }), Vec::new())
        .await
        .expect("call should succeed without auth");
    assert_eq!(response["message"], "legacy");

    client.close().await.expect("close should succeed");
    server_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn auth_session_timeout_applied() {
    let (address, url) = next_address();

    let mut server = WscallServer::new();
    server.auth_handler(|_ctx| async move {
        // Very short per-connection idle timeout: the server closes the
        // connection ~1s after the last inbound frame.
        Ok(AuthOutput::new().with_session_timeout(Duration::from_secs(1)))
    });
    server.route("system.echo", |_ctx| async move { Ok(json!({})) });

    let server_task = tokio::spawn(async move { server.listen(&address).await });
    sleep(Duration::from_millis(100)).await;

    let client = WscallClient::connect(&url, client_config_with_credential(Some("token")))
        .await
        .expect("client should connect");

    let (disc_tx, mut disc_rx) = mpsc::unbounded_channel();
    client
        .on_disconnected(move |event| {
            let disc_tx = disc_tx.clone();
            async move {
                let _ = disc_tx.send((event.reason, event.will_reconnect));
            }
        })
        .await;

    // First call works while the connection is alive.
    client
        .call("system.echo", json!({}), Vec::new())
        .await
        .expect("call should succeed before session timeout");

    // The client sends no frames for >1s (heartbeats are every 15s), so the
    // server's per-connection idle timeout kicks in and closes the socket.
    let disconnect = recv_event(&mut disc_rx, 10).await;
    assert!(!disconnect.0.trim().is_empty());
    assert!(!disconnect.1, "auto_reconnect is disabled");

    server_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn auth_timeout_when_client_sends_no_credential() {
    let (address, url) = next_address();

    let mut server = WscallServer::new();
    server.auth_handler(|_ctx| async move { Ok(AuthOutput::new()) });
    server.route("system.echo", |_ctx| async move { Ok(json!({})) });

    let server_task = tokio::spawn(async move { server.listen(&address).await });
    sleep(Duration::from_millis(100)).await;

    // The server expects an auth frame but the client never sends one; after
    // SERVER_AUTH_TIMEOUT (10s) the server closes the connection.
    let client = WscallClient::connect(&url, client_config_with_credential(None))
        .await
        .expect("ws-level connect should succeed");

    let (disc_tx, mut disc_rx) = mpsc::unbounded_channel();
    client
        .on_disconnected(move |event| {
            let disc_tx = disc_tx.clone();
            async move {
                let _ = disc_tx.send(event.reason);
            }
        })
        .await;

    let reason = recv_event(&mut disc_rx, 15).await;
    assert!(!reason.trim().is_empty());

    server_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn auth_context_accessible_in_handlers() {
    let (address, url) = next_address();

    let mut server = WscallServer::new();
    server.auth_handler(|_ctx| async move {
        let mut context = Map::new();
        context.insert("user_id".to_string(), json!("u-123"));
        context.insert("roles".to_string(), json!(["admin", "editor"]));
        Ok(AuthOutput::new().with_context(context))
    });
    server.route("whoami", |ctx| async move {
        match ctx.auth_context() {
            Some(auth) => Ok(Value::Object(auth.clone())),
            None => Err(ApiError::unauthorized("missing auth context")),
        }
    });
    server.event_handler("identify", |ctx| async move {
        let user_id = ctx
            .auth_context()
            .and_then(|auth| auth.get("user_id"))
            .and_then(|value| value.as_str())
            .unwrap_or("anonymous");
        Ok(json!({ "identified_as": user_id }))
    });

    let server_task = tokio::spawn(async move { server.listen(&address).await });
    sleep(Duration::from_millis(100)).await;

    let client = WscallClient::connect(&url, client_config_with_credential(Some("token")))
        .await
        .expect("client should connect");

    // Route handler sees the auth context.
    let whoami = client
        .call("whoami", json!({}), Vec::new())
        .await
        .expect("whoami should succeed");
    assert_eq!(whoami["user_id"], "u-123");
    assert_eq!(whoami["roles"], json!(["admin", "editor"]));

    // Event handler sees the same auth context.
    let receipt = client
        .send_event("identify", Map::new(), Vec::new())
        .await
        .expect("event should be acknowledged");
    assert_eq!(receipt["identified_as"], "u-123");

    client.close().await.expect("close should succeed");
    server_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_auth_handler_context_is_none() {
    let (address, url) = next_address();

    let mut server = WscallServer::new();
    server.route("has_auth", |ctx| async move {
        Ok(json!({ "has_auth": ctx.auth_context().is_some() }))
    });

    let server_task = tokio::spawn(async move { server.listen(&address).await });
    sleep(Duration::from_millis(100)).await;

    let client = WscallClient::connect(&url, client_config_with_credential(None))
        .await
        .expect("client should connect");

    let response = client
        .call("has_auth", json!({}), Vec::new())
        .await
        .expect("call should succeed");
    assert_eq!(response["has_auth"], false);

    client.close().await.expect("close should succeed");
    server_task.abort();
}
