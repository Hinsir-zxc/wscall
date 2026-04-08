use serde_json::json;
use tokio::time::{Duration, sleep};
use wscall::{WscallClient, WscallServer};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let address = "127.0.0.1:9010";
    let url = "ws://127.0.0.1:9010/socket";

    let server_task = tokio::spawn(async move {
        let mut server = WscallServer::new();
        server.route("system.echo", |ctx| async move {
            Ok(json!({
                "route": ctx.route(),
                "params": ctx.params(),
            }))
        });

        server.listen(address).await
    });

    sleep(Duration::from_millis(100)).await;

    let client = WscallClient::connect(url).await?;
    let response = client
        .call("system.echo", json!({ "message": "hello" }), Vec::new())
        .await?;

    println!("response: {response}");
    client.close().await?;

    server_task.abort();
    Ok(())
}
