use std::collections::HashMap;
use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::time::Duration;

use futures_util::{FutureExt, SinkExt, StreamExt, future::BoxFuture};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{RwLock, mpsc};
use tokio::time::{MissedTickBehavior, interval, timeout};
use tokio_tungstenite::{accept_async, tungstenite::Message};
use uuid::Uuid;
use validator::Validate;
use wscall_protocol::{
    EncryptionKind, ErrorPayload, FileAttachment, FrameCodec, PacketBody, PacketEnvelope,
};

use crate::server_types::{
    ApiContext, ApiError, EventContext, ExceptionContext, ServerConnectionContext,
    ServerDisconnectContext, ServerError, ServerHandle, ServerOutbound, ServerState,
};

const SERVER_IDLE_TIMEOUT: Duration = Duration::from_secs(45);
const SERVER_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(15);
const SERVER_OUTBOUND_QUEUE_CAPACITY: usize = 256;

type ApiHandler =
    Arc<dyn Fn(ApiContext) -> BoxFuture<'static, Result<Value, ApiError>> + Send + Sync>;
type Filter =
    Arc<dyn Fn(ApiContext) -> BoxFuture<'static, Result<ApiContext, ApiError>> + Send + Sync>;
type EventHandler =
    Arc<dyn Fn(EventContext) -> BoxFuture<'static, Result<Value, ApiError>> + Send + Sync>;
type ConnectionHandler = Arc<dyn Fn(ServerConnectionContext) -> BoxFuture<'static, ()> + Send + Sync>;
type DisconnectHandler = Arc<dyn Fn(ServerDisconnectContext) -> BoxFuture<'static, ()> + Send + Sync>;
type ExceptionHandler =
    Arc<dyn Fn(ExceptionContext) -> BoxFuture<'static, ErrorPayload> + Send + Sync>;

struct ApiRequestInput {
    request_id: String,
    route: String,
    params: Value,
    attachments: Vec<FileAttachment>,
    metadata: Value,
}

struct EventEmitInput {
    event_id: String,
    name: String,
    data: Value,
    attachments: Vec<FileAttachment>,
    metadata: Value,
}

impl ServerHandle {
    pub async fn broadcast_event(
        &self,
        name: impl Into<String>,
        data: Value,
        attachments: Vec<FileAttachment>,
    ) -> Result<(), ApiError> {
        let packet = PacketEnvelope::with_encryption(
            PacketBody::EventEmit {
                event_id: Uuid::new_v4().to_string(),
                name: name.into(),
                data,
                attachments,
                metadata: json!({ "source": "server" }),
                expect_ack: true,
            },
            self.default_encryption,
        );

        let clients = self.state.clients.read().await;
        let senders = clients.values().cloned().collect::<Vec<_>>();
        drop(clients);

        for sender in senders {
            sender
                .try_send(ServerOutbound::Packet(packet.clone()))
                .map_err(|_| ApiError::internal("failed to queue broadcast event"))?;
        }
        Ok(())
    }

    pub async fn send_event_to(
        &self,
        connection_id: &str,
        name: impl Into<String>,
        data: Value,
        attachments: Vec<FileAttachment>,
    ) -> Result<(), ApiError> {
        let packet = PacketEnvelope::with_encryption(
            PacketBody::EventEmit {
                event_id: Uuid::new_v4().to_string(),
                name: name.into(),
                data,
                attachments,
                metadata: json!({ "source": "server" }),
                expect_ack: true,
            },
            self.default_encryption,
        );

        let clients = self.state.clients.read().await;
        let sender = clients
            .get(connection_id)
            .cloned()
            .ok_or_else(|| ApiError::not_found("target connection not found"))?;
        drop(clients);
        sender
            .try_send(ServerOutbound::Packet(packet))
            .map_err(|_| ApiError::internal("failed to queue direct event"))
    }

    pub async fn connection_count(&self) -> usize {
        self.state.clients.read().await.len()
    }
}

pub struct WscallServer {
    state: Arc<ServerState>,
    routes: HashMap<String, ApiHandler>,
    filters: Vec<Filter>,
    event_handlers: HashMap<String, EventHandler>,
    connection_handlers: Vec<ConnectionHandler>,
    disconnect_handlers: Vec<DisconnectHandler>,
    exception_handler: Option<ExceptionHandler>,
    codec: FrameCodec,
    default_encryption: EncryptionKind,
}

impl Default for WscallServer {
    fn default() -> Self {
        Self::new()
    }
}

impl WscallServer {
    pub fn new() -> Self {
        Self {
            state: Arc::new(ServerState {
                clients: RwLock::new(HashMap::new()),
            }),
            routes: HashMap::new(),
            filters: Vec::new(),
            event_handlers: HashMap::new(),
            connection_handlers: Vec::new(),
            disconnect_handlers: Vec::new(),
            exception_handler: None,
            codec: FrameCodec::plaintext(),
            default_encryption: EncryptionKind::None,
        }
    }

    pub fn with_chacha20_key(mut self, key: [u8; 32]) -> Self {
        self.codec = self.codec.clone().with_chacha20_key(key);
        self.default_encryption = EncryptionKind::ChaCha20;
        self
    }

    pub fn with_aes256_key(mut self, key: [u8; 32]) -> Self {
        self.codec = self.codec.clone().with_aes256_key(key);
        self.default_encryption = EncryptionKind::Aes256;
        self
    }

    pub fn handle(&self) -> ServerHandle {
        ServerHandle {
            state: Arc::clone(&self.state),
            default_encryption: self.default_encryption,
        }
    }

    pub fn route<F, Fut>(&mut self, route: impl Into<String>, handler: F)
    where
        F: Fn(ApiContext) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Value, ApiError>> + Send + 'static,
    {
        let handler = Arc::new(move |ctx: ApiContext| {
            Box::pin(handler(ctx)) as BoxFuture<'static, Result<Value, ApiError>>
        });
        self.routes.insert(route.into(), handler);
    }

    pub fn typed_route<T, F, Fut>(&mut self, route: impl Into<String>, handler: F)
    where
        T: DeserializeOwned + Send + 'static,
        F: Fn(ApiContext, T) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Value, ApiError>> + Send + 'static,
    {
        let handler = Arc::new(handler);
        self.route(route, move |ctx| {
            let handler = Arc::clone(&handler);
            let params = ctx.bind::<T>();
            async move {
                let params = params?;
                handler(ctx, params).await
            }
        });
    }

    pub fn validated_route<T, F, Fut>(&mut self, route: impl Into<String>, handler: F)
    where
        T: DeserializeOwned + Validate + Send + 'static,
        F: Fn(ApiContext, T) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Value, ApiError>> + Send + 'static,
    {
        let handler = Arc::new(handler);
        self.route(route, move |ctx| {
            let handler = Arc::clone(&handler);
            let params = ctx.bind_validated::<T>();
            async move {
                let params = params?;
                handler(ctx, params).await
            }
        });
    }

    pub fn filter<F, Fut>(&mut self, filter: F)
    where
        F: Fn(ApiContext) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<ApiContext, ApiError>> + Send + 'static,
    {
        let filter = Arc::new(move |ctx: ApiContext| {
            Box::pin(filter(ctx)) as BoxFuture<'static, Result<ApiContext, ApiError>>
        });
        self.filters.push(filter);
    }

    pub fn event_handler<F, Fut>(&mut self, name: impl Into<String>, handler: F)
    where
        F: Fn(EventContext) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Value, ApiError>> + Send + 'static,
    {
        let handler = Arc::new(move |ctx: EventContext| {
            Box::pin(handler(ctx)) as BoxFuture<'static, Result<Value, ApiError>>
        });
        self.event_handlers.insert(name.into(), handler);
    }

    pub fn on_connected<F, Fut>(&mut self, handler: F)
    where
        F: Fn(ServerConnectionContext) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let handler = Arc::new(move |ctx: ServerConnectionContext| {
            Box::pin(handler(ctx)) as BoxFuture<'static, ()>
        });
        self.connection_handlers.push(handler);
    }

    pub fn on_disconnected<F, Fut>(&mut self, handler: F)
    where
        F: Fn(ServerDisconnectContext) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let handler = Arc::new(move |ctx: ServerDisconnectContext| {
            Box::pin(handler(ctx)) as BoxFuture<'static, ()>
        });
        self.disconnect_handlers.push(handler);
    }

    pub fn exception_handler<F, Fut>(&mut self, handler: F)
    where
        F: Fn(ExceptionContext) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ErrorPayload> + Send + 'static,
    {
        self.exception_handler = Some(Arc::new(move |ctx: ExceptionContext| {
            Box::pin(handler(ctx)) as BoxFuture<'static, ErrorPayload>
        }));
    }

    pub async fn listen(self, address: &str) -> Result<(), ServerError> {
        let listener = TcpListener::bind(address).await?;
        println!("WSCALL server listening on ws://{address}/socket");

        let shared = Arc::new(self);
        loop {
            let (stream, peer) = listener.accept().await?;
            let server = Arc::clone(&shared);
            tokio::spawn(async move {
                if let Err(error) = server.serve_connection(stream, peer).await {
                    eprintln!("connection {peer:?} failed: {error}");
                }
            });
        }
    }

    async fn serve_connection(
        self: Arc<Self>,
        stream: TcpStream,
        peer: std::net::SocketAddr,
    ) -> Result<(), ServerError> {
        let websocket = accept_async(stream).await?;
        let connection_id = Uuid::new_v4().to_string();
        let (mut sink, mut stream) = websocket.split();
        let (tx, mut rx) = mpsc::channel::<ServerOutbound>(SERVER_OUTBOUND_QUEUE_CAPACITY);

        self.state
            .clients
            .write()
            .await
            .insert(connection_id.clone(), tx.clone());

        self.notify_connected(&connection_id, Some(peer)).await;

        let codec = self.codec.clone();
        let writer = tokio::spawn(async move {
            while let Some(outbound) = rx.recv().await {
                match outbound {
                    ServerOutbound::Packet(packet) => {
                        let bytes = codec.encode(&packet)?;
                        sink.send(Message::Binary(bytes)).await?;
                    }
                    ServerOutbound::Ping(payload) => {
                        sink.send(Message::Ping(payload)).await?;
                    }
                    ServerOutbound::Pong(payload) => {
                        sink.send(Message::Pong(payload)).await?;
                    }
                    ServerOutbound::Close => {
                        let _ = sink.send(Message::Close(None)).await;
                        break;
                    }
                }
            }
            Ok::<(), ServerError>(())
        });

        let heartbeat_tx = tx.clone();
        let heartbeat = tokio::spawn(async move {
            let mut ticker = interval(SERVER_HEARTBEAT_INTERVAL);
            ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                if heartbeat_tx
                    .send(ServerOutbound::Ping(Vec::new()))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });

        let result = async {
            self.handle()
                .send_event_to(
                    &connection_id,
                    "system.notice",
                    json!({ "message": "connected", "connection_id": connection_id }),
                    Vec::new(),
                )
                .await
                .map_err(ServerError::Api)?;

            loop {
                let next_message = timeout(SERVER_IDLE_TIMEOUT, stream.next()).await;
                let Some(message) =
                    next_message.map_err(|_| ServerError::IdleTimeout(connection_id.clone()))?
                else {
                    break Ok(());
                };

                match message? {
                    Message::Binary(bytes) => {
                        let packet = self.codec.decode(&bytes)?;
                        self.process_packet(&connection_id, Some(peer), packet)
                            .await?;
                    }
                    Message::Close(_) => break Ok(()),
                    Message::Ping(payload) => {
                        if tx
                            .send(ServerOutbound::Pong(payload.to_vec()))
                            .await
                            .is_err()
                        {
                            break Ok(());
                        }
                    }
                    Message::Pong(_) => {}
                    Message::Text(_) => {}
                    Message::Frame(_) => {}
                }
            }
        }
        .await;

        self.state.clients.write().await.remove(&connection_id);
        let _ = tx.send(ServerOutbound::Close).await;
        heartbeat.abort();
        writer.abort();
        self.notify_disconnected(
            &connection_id,
            Some(peer),
            Self::disconnect_reason(&result),
        )
        .await;
        result
    }

    async fn process_packet(
        &self,
        connection_id: &str,
        peer_addr: Option<std::net::SocketAddr>,
        packet: PacketEnvelope,
    ) -> Result<(), ServerError> {
        match packet.body {
            PacketBody::ApiRequest {
                request_id,
                route,
                params,
                attachments,
                metadata,
            } => {
                let response = self
                    .run_api_request(
                        connection_id,
                        peer_addr,
                        ApiRequestInput {
                            request_id: request_id.clone(),
                            route,
                            params,
                            attachments,
                            metadata,
                        },
                    )
                    .await;
                self.queue_for(connection_id, response).await?;
            }
            PacketBody::EventEmit {
                event_id,
                name,
                data,
                attachments,
                metadata,
                ..
            } => {
                let ack = self
                    .run_event(
                        connection_id,
                        peer_addr,
                        EventEmitInput {
                            event_id: event_id.clone(),
                            name,
                            data,
                            attachments,
                            metadata,
                        },
                    )
                    .await;
                self.queue_for(connection_id, ack).await?;
            }
            PacketBody::EventAck {
                event_id,
                ok,
                receipt,
                error,
            } => {
                println!(
                    "received event ack from {} for {}: ok={}, receipt={}, error={:?}",
                    connection_id, event_id, ok, receipt, error
                );
            }
            PacketBody::ApiResponse { .. } => {}
        }
        Ok(())
    }

    async fn queue_for(
        &self,
        connection_id: &str,
        packet: PacketEnvelope,
    ) -> Result<(), ServerError> {
        let clients = self.state.clients.read().await;
        let sender = clients
            .get(connection_id)
            .cloned()
            .ok_or_else(|| ServerError::Api(ApiError::not_found("connection is closed")))?;
        drop(clients);
        sender
            .try_send(ServerOutbound::Packet(packet))
            .map_err(|error| match error {
                tokio::sync::mpsc::error::TrySendError::Full(_) => {
                    ServerError::OutboundQueueFull(connection_id.to_string())
                }
                tokio::sync::mpsc::error::TrySendError::Closed(_) => {
                    ServerError::Api(ApiError::internal("failed to queue outbound packet"))
                }
            })
    }

    async fn run_api_request(
        &self,
        connection_id: &str,
        peer_addr: Option<std::net::SocketAddr>,
        request: ApiRequestInput,
    ) -> PacketEnvelope {
        let ApiRequestInput {
            request_id,
            route,
            params,
            attachments,
            metadata,
        } = request;

        let mut ctx = ApiContext {
            connection_id: connection_id.to_string(),
            peer_addr,
            request_id: request_id.clone(),
            route: route.clone(),
            params,
            attachments,
            metadata,
            server: self.handle(),
        };

        for filter in &self.filters {
            match filter(ctx).await {
                Ok(next_ctx) => ctx = next_ctx,
                Err(error) => {
                    return self
                        .api_error_packet(connection_id, Some(request_id), route, error)
                        .await;
                }
            }
        }

        let Some(handler) = self.routes.get(&ctx.route) else {
            return self
                .api_error_packet(
                    connection_id,
                    Some(request_id),
                    route,
                    ApiError::not_found("route not found"),
                )
                .await;
        };

        match AssertUnwindSafe(handler(ctx)).catch_unwind().await {
            Ok(Ok(data)) => PacketEnvelope::with_encryption(
                PacketBody::ApiResponse {
                    request_id,
                    ok: true,
                    status: 200,
                    data,
                    error: None,
                    metadata: json!({}),
                },
                self.default_encryption,
            ),
            Ok(Err(error)) => {
                self.api_error_packet(connection_id, Some(request_id), route, error)
                    .await
            }
            Err(_) => {
                self.api_error_packet(
                    connection_id,
                    Some(request_id),
                    route,
                    ApiError::internal("handler panicked"),
                )
                .await
            }
        }
    }

    async fn run_event(
        &self,
        connection_id: &str,
        peer_addr: Option<std::net::SocketAddr>,
        event: EventEmitInput,
    ) -> PacketEnvelope {
        let EventEmitInput {
            event_id,
            name,
            data,
            attachments,
            metadata,
        } = event;

        let ctx = EventContext {
            connection_id: connection_id.to_string(),
            peer_addr,
            event_id: event_id.clone(),
            name: name.clone(),
            data,
            attachments,
            metadata,
            server: self.handle(),
        };

        let Some(handler) = self.event_handlers.get(&name) else {
            return PacketEnvelope::with_encryption(
                PacketBody::EventAck {
                    event_id,
                    ok: false,
                    receipt: json!({}),
                    error: Some(ApiError::not_found("event handler not found").into_payload()),
                },
                self.default_encryption,
            );
        };

        match AssertUnwindSafe(handler(ctx)).catch_unwind().await {
            Ok(Ok(receipt)) => PacketEnvelope::with_encryption(
                PacketBody::EventAck {
                    event_id,
                    ok: true,
                    receipt,
                    error: None,
                },
                self.default_encryption,
            ),
            Ok(Err(error)) => PacketEnvelope::with_encryption(
                PacketBody::EventAck {
                    event_id: event_id.clone(),
                    ok: false,
                    receipt: json!({}),
                    error: Some(
                        self.map_exception(ExceptionContext {
                            connection_id: connection_id.to_string(),
                            request_id: Some(event_id.clone()),
                            target: name,
                            message_kind: "event",
                            error,
                        })
                        .await,
                    ),
                },
                self.default_encryption,
            ),
            Err(_) => PacketEnvelope::with_encryption(
                PacketBody::EventAck {
                    event_id: event_id.clone(),
                    ok: false,
                    receipt: json!({}),
                    error: Some(
                        self.map_exception(ExceptionContext {
                            connection_id: connection_id.to_string(),
                            request_id: Some(event_id.clone()),
                            target: name,
                            message_kind: "event",
                            error: ApiError::internal("event handler panicked"),
                        })
                        .await,
                    ),
                },
                self.default_encryption,
            ),
        }
    }

    async fn api_error_packet(
        &self,
        connection_id: &str,
        request_id: Option<String>,
        route: String,
        error: ApiError,
    ) -> PacketEnvelope {
        let request_id = request_id.unwrap_or_else(|| Uuid::new_v4().to_string());
        let status = error.status;
        let payload = self
            .map_exception(ExceptionContext {
                connection_id: connection_id.to_string(),
                request_id: Some(request_id.clone()),
                target: route,
                message_kind: "api",
                error,
            })
            .await;

        PacketEnvelope::with_encryption(
            PacketBody::ApiResponse {
                request_id,
                ok: false,
                status,
                data: json!({}),
                error: Some(payload),
                metadata: json!({}),
            },
            self.default_encryption,
        )
    }

    async fn notify_connected(
        &self,
        connection_id: &str,
        peer_addr: Option<std::net::SocketAddr>,
    ) {
        let handlers = self.connection_handlers.clone();
        for handler in handlers {
            let context = ServerConnectionContext {
                connection_id: connection_id.to_string(),
                peer_addr,
                server: self.handle(),
            };

            if AssertUnwindSafe(handler(context)).catch_unwind().await.is_err() {
                eprintln!("server connected handler panicked");
            }
        }
    }

    async fn notify_disconnected(
        &self,
        connection_id: &str,
        peer_addr: Option<std::net::SocketAddr>,
        reason: String,
    ) {
        let handlers = self.disconnect_handlers.clone();
        for handler in handlers {
            let context = ServerDisconnectContext {
                connection_id: connection_id.to_string(),
                peer_addr,
                reason: reason.clone(),
                server: self.handle(),
            };

            if AssertUnwindSafe(handler(context)).catch_unwind().await.is_err() {
                eprintln!("server disconnected handler panicked");
            }
        }
    }

    fn disconnect_reason(result: &Result<(), ServerError>) -> String {
        match result {
            Ok(()) => "connection closed".to_string(),
            Err(ServerError::IdleTimeout(_)) => "idle timeout".to_string(),
            Err(error) => error.to_string(),
        }
    }

    async fn map_exception(&self, context: ExceptionContext) -> ErrorPayload {
        match &self.exception_handler {
            Some(handler) => handler(context).await,
            None => context.error.into_payload(),
        }
    }
}
