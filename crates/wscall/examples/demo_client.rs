use serde_json::json;
use wscall::{FileAttachment, WscallClient};

const DEMO_CHACHA20_KEY: [u8; 32] = [0x42; 32];

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();

    // --ecdh: use ECDH dynamic key agreement (no pre-shared key needed).
    let use_ecdh = std::env::args().any(|a| a == "--ecdh");
    let client = if use_ecdh {
        println!("connecting in ECDH mode (dynamic key agreement)");
        WscallClient::connect_with_ecdh("ws://127.0.0.1:9001/socket").await?
    } else {
        println!("connecting in PSK mode (ChaCha20)");
        WscallClient::connect_with_chacha20("ws://127.0.0.1:9001/socket", DEMO_CHACHA20_KEY).await?
    };

    client
        .on_connected(|event| async move {
            println!("connected: {}", event.url);
        })
        .await;

    client
        .on_disconnected(|event| async move {
            println!(
                "disconnected: reason={}, retry_after={:?}",
                event.reason, event.retry_after
            );
        })
        .await;

    client
        .on_event("system.notice", |event| async move {
            println!("notice: {}", serde_json::Value::Object(event.data.clone()));
            json!({ "received": true })
        })
        .await;

    client
        .on_event("chat.message", |event| async move {
            println!(
                "chat event: {}",
                serde_json::Value::Object(event.data.clone())
            );
            json!({ "seen": true, "event_id": event.event_id })
        })
        .await;

    let echo = client
        .call(
            "system.echo",
            json!({
                "message": "hello from Rust client",
                "sample_file": FileAttachment::param_ref("note-1"),
            }),
            vec![FileAttachment::inline_text(
                "note-1",
                "hello.txt",
                "text/plain",
                "sample attachment from client",
            )],
        )
        .await?;
    println!("echo response: {echo}");

    let inspect = client
        .call(
            "files.inspect",
            json!({ "avatar": FileAttachment::param_ref("avatar-1") }),
            vec![FileAttachment::inline_bytes(
                "avatar-1",
                "avatar.bin",
                "application/octet-stream",
                vec![1_u8, 2, 3, 4],
            )],
        )
        .await?;
    println!("file response: {inspect}");

    let ack = client
        .send_event(
            "chat.message",
            json!({ "message": "hello room" })
                .as_object()
                .unwrap()
                .clone(),
            Vec::new(),
        )
        .await?;
    println!("event ack: {ack}");

    let history = client.call("chat.history", json!({}), Vec::new()).await?;
    println!("history: {history}");

    client.close().await?;
    Ok(())
}
