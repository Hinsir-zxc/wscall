use std::sync::Arc;

use serde::Deserialize;
use serde_json::json;
use tokio::sync::Mutex;
use wscall::server::validation::{Validate, non_negative_i32, not_blank, positive_i32};
use wscall::{ApiError, ExceptionContext, FileAttachment, ValidateParams, WscallServer};

const DEMO_CHACHA20_KEY: [u8; 32] = [0x42; 32];

wscall_server::wscall_regex_validator!(
    validate_username,
    r"^[a-zA-Z][a-zA-Z0-9_]{2,15}$",
    "invalid_username"
);

#[derive(Debug, Deserialize)]
struct EchoParams {
    message: String,
    #[serde(default)]
    sample_file: Option<serde_json::Value>,
}

impl ValidateParams for EchoParams {
    fn validate(&self) -> Result<(), ApiError> {
        if self.message.trim().is_empty() {
            return Err(ApiError::bad_request("message cannot be empty"));
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize, Validate)]
struct TypedEchoParams {
    #[validate(custom(function = "not_blank"))]
    message: String,
    #[serde(default)]
    sample_file: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, Validate)]
struct RegisterUserParams {
    #[validate(custom(function = "not_blank"))]
    display_name: String,
    #[validate(custom(function = "validate_username"))]
    username: String,
    #[validate(email)]
    email: String,
    #[validate(custom(function = "positive_i32"))]
    age: i32,
    #[validate(custom(function = "non_negative_i32"))]
    login_count: i32,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();

    let history = Arc::new(Mutex::new(Vec::<serde_json::Value>::new()));
    // --ecdh: use ECDH dynamic key agreement (no pre-shared key needed).
    let use_ecdh = std::env::args().any(|a| a == "--ecdh");
    let mut server = if use_ecdh {
        println!("starting server in ECDH mode (dynamic key agreement)");
        WscallServer::new().with_ecdh()
    } else {
        println!("starting server in PSK mode (ChaCha20)");
        WscallServer::new().with_chacha20_key(DEMO_CHACHA20_KEY)
    };

    server.on_connected(|ctx| async move {
        println!(
            "client connected: connection_id={}, peer_ip={:?}",
            ctx.connection_id(),
            ctx.peer_ip()
        );
    });

    server.on_disconnected(|ctx| async move {
        println!(
            "client disconnected: connection_id={}, reason={}",
            ctx.connection_id(),
            ctx.reason()
        );
    });

    server.filter(|ctx| async move {
        if ctx.route().trim().is_empty() {
            return Err(ApiError::bad_request("route cannot be empty"));
        }
        Ok(ctx)
    });

    server.exception_handler(|exception: ExceptionContext| async move {
        let details = json!({
            "target": exception.target,
            "request_id": exception.request_id,
            "connection_id": exception.connection_id,
        });

        match exception.error.code.as_str() {
            "not_found" => exception.error.with_details(details).into_payload(),
            _ => ApiError::internal("server failed to process the message")
                .with_details(details)
                .into_payload(),
        }
    });

    server.route("system.echo", |ctx| async move {
        let typed: EchoParams = ctx.bind_and_validate()?;
        let raw_message = ctx
            .require_param("message")?
            .as_str()
            .ok_or_else(|| ApiError::bad_request("message must be a string"))?;

        Ok(json!({
            "route": ctx.route(),
            "params": ctx.params().clone(),
            "message": raw_message,
            "typed_message": typed.message,
            "sample_file": typed.sample_file,
            "attachments": ctx.attachment_summaries(),
        }))
    });

    server.typed_route("system.echo.bound", |ctx, params: EchoParams| async move {
        Ok(json!({
            "route": ctx.route(),
            "typed_message": params.message,
            "sample_file": params.sample_file,
        }))
    });

    server.validated_route(
        "system.echo.typed",
        |ctx, params: TypedEchoParams| async move {
            Ok(json!({
                "route": ctx.route(),
                "message": params.message,
                "sample_file": params.sample_file,
                "request_id": ctx.request_id(),
            }))
        },
    );

    server.validated_route(
        "user.register",
        |_ctx, params: RegisterUserParams| async move {
            Ok(json!({
                "accepted": true,
                "display_name": params.display_name,
                "username": params.username,
                "email": params.email,
                "age": params.age,
                "login_count": params.login_count,
            }))
        },
    );

    server.route("files.inspect", |ctx| async move {
        let files = ctx
            .attachments()
            .iter()
            .map(|attachment| {
                json!({
                    "id": attachment.id,
                    "name": attachment.name,
                    "content_type": attachment.content_type,
                    "size": attachment.size,
                })
            })
            .collect::<Vec<_>>();

        Ok(json!({
            "params": ctx.params().clone(),
            "files": files,
        }))
    });

    let history_for_api = Arc::clone(&history);
    server.route("chat.history", move |_ctx| {
        let history = Arc::clone(&history_for_api);
        async move {
            let items = history.lock().await.clone();
            Ok(json!({ "messages": items }))
        }
    });

    let history_for_event = Arc::clone(&history);
    server.event_handler("chat.message", move |ctx| {
        let history = Arc::clone(&history_for_event);
        async move {
            let record = json!({
                "from": ctx
                    .metadata()
                    .get("client_name")
                    .and_then(|value| value.as_str())
                    .unwrap_or("anonymous"),
                "message": ctx
                    .data()
                    .get("message")
                    .and_then(|value| value.as_str())
                    .unwrap_or(""),
                "connection_id": ctx.connection_id(),
            });

            history.lock().await.push(record.clone());
            ctx.server()
                .broadcast_event("chat.message", record.clone(), Vec::<FileAttachment>::new())
                .await?;

            Ok(json!({ "stored": true, "echo": record }))
        }
    });

    server.listen("127.0.0.1:9001").await?;
    Ok(())
}
