use std::collections::HashMap;
use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use bytes::Bytes;
use futures_util::{FutureExt, SinkExt, StreamExt, future::BoxFuture};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, mpsc};
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
/// Default cap on concurrently in-flight request/event handlers per connection.
const SERVER_DEFAULT_MAX_IN_FLIGHT: usize = 64;
/// Grace window given to the writer task to flush a close frame before abort.
const SERVER_CLOSE_GRACE: Duration = Duration::from_millis(500);

type ApiHandler =
    Arc<dyn Fn(ApiContext) -> BoxFuture<'static, Result<Value, ApiError>> + Send + Sync>;
type Filter =
    Arc<dyn Fn(ApiContext) -> BoxFuture<'static, Result<ApiContext, ApiError>> + Send + Sync>;
type EventHandler =
    Arc<dyn Fn(EventContext) -> BoxFuture<'static, Result<Value, ApiError>> + Send + Sync>;
type ConnectionHandler =
    Arc<dyn Fn(ServerConnectionContext) -> BoxFuture<'static, ()> + Send + Sync>;
type DisconnectHandler =
    Arc<dyn Fn(ServerDisconnectContext) -> BoxFuture<'static, ()> + Send + Sync>;
type ExceptionHandler =
    Arc<dyn Fn(ExceptionContext) -> BoxFuture<'static, ErrorPayload> + Send + Sync>;

struct ApiRequestInput {
    request_id: u64,
    route: String,
    params: Value,
    attachments: Vec<FileAttachment>,
    metadata: Value,
}

struct EventEmitInput {
    event_id: u64,
    name: String,
    data: Value,
    attachments: Vec<FileAttachment>,
    metadata: Value,
    storage_id: Option<u64>,
}

impl ServerHandle {
    /// Broadcasts an event to every live connection.
    ///
    /// The frame is encoded exactly once and shared as [`Bytes`] across all
    /// recipients, so the cost no longer scales with the connection count times
    /// the payload size. A full outbound queue for a single connection drops
    /// that one delivery instead of failing the whole broadcast.
    pub async fn broadcast_event(
        &self,
        name: impl Into<String>,
        data: Value,
        attachments: Vec<FileAttachment>,
    ) -> Result<(), ApiError> {
        self.broadcast_event_inner(name, data, attachments, None)
            .await
    }

    /// Broadcasts a persisted event to every live connection, carrying a
    /// storage id (`si` field) assigned by a database or other persistent store.
    pub async fn broadcast_persisted_event(
        &self,
        name: impl Into<String>,
        data: Value,
        attachments: Vec<FileAttachment>,
        storage_id: u64,
    ) -> Result<(), ApiError> {
        self.broadcast_event_inner(name, data, attachments, Some(storage_id))
            .await
    }

    async fn broadcast_event_inner(
        &self,
        name: impl Into<String>,
        data: Value,
        attachments: Vec<FileAttachment>,
        storage_id: Option<u64>,
    ) -> Result<(), ApiError> {
        let event_id = self.state.next_event_id.fetch_add(1, Ordering::Relaxed) + 1;
        let packet = PacketEnvelope::with_encryption(
            PacketBody::EventEmit {
                event_id,
                name: name.into(),
                data,
                attachments,
                metadata: json!({ "source": "server" }),
                expect_ack: true,
                storage_id,
            },
            self.default_encryption,
        );

        let encoded = self
            .codec
            .encode(&packet)
            .map_err(|_| ApiError::internal("failed to encode broadcast event"))?;
        let encoded = Bytes::from(encoded);

        for entry in self.state.clients.iter() {
            if entry
                .value()
                .try_send(ServerOutbound::PreEncoded(encoded.clone()))
                .is_err()
            {
                tracing::warn!("broadcast: outbound queue full, dropping event for a connection");
            }
        }
        Ok(())
    }

    /// Sends an event to a single connection by id.
    ///
    /// The frame is pre-encoded once so the writer task only ships bytes.
    pub async fn send_event_to(
        &self,
        connection_id: &str,
        name: impl Into<String>,
        data: Value,
        attachments: Vec<FileAttachment>,
    ) -> Result<(), ApiError> {
        self.send_event_to_inner(connection_id, name, data, attachments, None)
            .await
    }

    /// Sends a persisted event to a single connection by id, carrying a
    /// storage id (`si` field) assigned by a database or other persistent store.
    pub async fn send_persisted_event_to(
        &self,
        connection_id: &str,
        name: impl Into<String>,
        data: Value,
        attachments: Vec<FileAttachment>,
        storage_id: u64,
    ) -> Result<(), ApiError> {
        self.send_event_to_inner(connection_id, name, data, attachments, Some(storage_id))
            .await
    }

    async fn send_event_to_inner(
        &self,
        connection_id: &str,
        name: impl Into<String>,
        data: Value,
        attachments: Vec<FileAttachment>,
        storage_id: Option<u64>,
    ) -> Result<(), ApiError> {
        let event_id = self.state.next_event_id.fetch_add(1, Ordering::Relaxed) + 1;
        let packet = PacketEnvelope::with_encryption(
            PacketBody::EventEmit {
                event_id,
                name: name.into(),
                data,
                attachments,
                metadata: json!({ "source": "server" }),
                expect_ack: true,
                storage_id,
            },
            self.default_encryption,
        );

        let encoded = self
            .codec
            .encode(&packet)
            .map_err(|_| ApiError::internal("failed to encode direct event"))?;
        let encoded = Bytes::from(encoded);

        let entry = self
            .state
            .clients
            .get(connection_id)
            .ok_or_else(|| ApiError::not_found("target connection not found"))?;
        entry
            .try_send(ServerOutbound::PreEncoded(encoded))
            .map_err(|_| ApiError::internal("failed to queue direct event"))
    }

    /// Returns the current number of live connections.
    pub async fn connection_count(&self) -> usize {
        self.state.clients.len()
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
    /// Optional global cap on concurrent accepted connections.
    max_connections: Option<usize>,
    /// Per-connection cap on concurrently running request/event handlers.
    max_in_flight: usize,
}

impl Default for WscallServer {
    fn default() -> Self {
        Self::new()
    }
}

impl WscallServer {
    pub fn new() -> Self {
        Self {
            state: Arc::new(ServerState::new()),
            routes: HashMap::new(),
            filters: Vec::new(),
            event_handlers: HashMap::new(),
            connection_handlers: Vec::new(),
            disconnect_handlers: Vec::new(),
            exception_handler: None,
            codec: FrameCodec::plaintext(),
            default_encryption: EncryptionKind::None,
            max_connections: None,
            max_in_flight: SERVER_DEFAULT_MAX_IN_FLIGHT,
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

    /// Caps the number of concurrently accepted connections.
    ///
    /// When the cap is reached, new `accept` calls block until an existing
    /// connection drops, providing natural backpressure against connection
    /// flooding instead of spawning unbounded tasks.
    pub fn with_max_connections(mut self, max: usize) -> Self {
        self.max_connections = Some(max);
        self
    }

    /// Caps the number of concurrently in-flight request/event handlers per
    /// single connection, bounding per-connection CPU and memory usage.
    pub fn with_max_in_flight(mut self, max: usize) -> Self {
        self.max_in_flight = max;
        self
    }

    pub fn handle(&self) -> ServerHandle {
        ServerHandle {
            state: Arc::clone(&self.state),
            codec: self.codec.clone(),
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
        tracing::info!(%address, "wscall server listening on ws://{address}/socket");

        let shared = Arc::new(self);
        let conn_sem = shared
            .max_connections
            .map(|max| Arc::new(Semaphore::new(max)));

        loop {
            // Acquire a connection permit (when capped) before accepting so a
            // connection flood turns into backpressure rather than unbounded
            // task spawning.
            let permit = match &conn_sem {
                Some(sem) => match sem.clone().acquire_owned().await {
                    Ok(permit) => Some(permit),
                    Err(_) => continue,
                },
                None => None,
            };

            let (stream, peer) = listener.accept().await?;
            // Disable Nagle's algorithm for low-latency RPC frames.
            let _ = TcpStream::set_nodelay(&stream, true);

            let server = Arc::clone(&shared);
            tokio::spawn(async move {
                let _permit = permit;
                if let Err(error) = server.serve_connection(stream, peer).await {
                    tracing::warn!(?error, ?peer, "connection failed");
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
        let connection_id = Uuid::now_v7().to_string();
        let (mut sink, mut stream) = websocket.split();
        let (tx, mut rx) = mpsc::channel::<ServerOutbound>(SERVER_OUTBOUND_QUEUE_CAPACITY);
        let peer_addr = Some(peer);

        self.state.clients.insert(connection_id.clone(), tx.clone());

        self.notify_connected(&connection_id, peer_addr).await;

        let mut writer = tokio::spawn(async move {
            let mut ticker = interval(SERVER_HEARTBEAT_INTERVAL);
            ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    maybe_outbound = rx.recv() => {
                        let Some(outbound) = maybe_outbound else {
                            break Ok::<(), ServerError>(());
                        };
                        match outbound {
                            ServerOutbound::PreEncoded(bytes) => {
                                sink.send(Message::Binary(bytes.to_vec())).await?;
                            }
                            ServerOutbound::Pong(payload) => {
                                sink.send(Message::Pong(payload)).await?;
                            }
                            ServerOutbound::Close => {
                                let _ = sink.send(Message::Close(None)).await;
                                break Ok(());
                            }
                        }
                    }
                    _ = ticker.tick() => {
                        if let Err(error) = sink.send(Message::Ping(Vec::new())).await {
                            break Err(ServerError::WebSocket(error));
                        }
                    }
                }
            }
        });

        // Per-connection concurrency limit for handler execution. The reader
        // stays non-blocking under normal load; under overload it pauses reading
        // new frames, which is the desired backpressure signal.
        let in_flight = Arc::new(Semaphore::new(self.max_in_flight));

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

                        let spawn_handler = matches!(
                            &packet.body,
                            PacketBody::ApiRequest { .. } | PacketBody::EventEmit { .. }
                        );

                        if spawn_handler {
                            let permit = in_flight.clone().acquire_owned().await.map_err(|_| {
                                ServerError::Api(ApiError::internal("in-flight semaphore closed"))
                            })?;
                            let server = Arc::clone(&self);
                            let conn_id = connection_id.clone();
                            tokio::spawn(async move {
                                let _permit = permit;
                                if let Err(error) =
                                    server.process_packet(&conn_id, peer_addr, packet).await
                                {
                                    tracing::warn!(%error, "packet processing failed");
                                }
                            });
                        } else {
                            // Trivial control messages (acks / responses from
                            // clients) are handled inline without spawning.
                            self.process_packet(&connection_id, peer_addr, packet)
                                .await?;
                        }
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

        // Teardown: remove from the live table, attempt a graceful close, then
        // abort the writer. Aborting the writer drops the channel receiver so
        // any in-flight handler `queue_for` calls fail fast instead of hanging.
        self.state.clients.remove(&connection_id);
        let _ = tx.try_send(ServerOutbound::Close);
        let _ = timeout(SERVER_CLOSE_GRACE, &mut writer).await;
        writer.abort();
        self.notify_disconnected(&connection_id, peer_addr, Self::disconnect_reason(&result))
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
                            request_id,
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
                storage_id,
                ..
            } => {
                let ack = self
                    .run_event(
                        connection_id,
                        peer_addr,
                        EventEmitInput {
                            event_id,
                            name,
                            data,
                            attachments,
                            metadata,
                            storage_id,
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
                tracing::debug!(
                    connection_id,
                    event_id,
                    ok,
                    ?receipt,
                    ?error,
                    "received event ack from client",
                );
            }
            PacketBody::ApiResponse { .. } => {}
        }
        Ok(())
    }

    /// Queues a response packet for a connection.
    ///
    /// The frame is pre-encoded here (offloading the writer task and enabling
    /// parallel encoding across concurrent handlers) and sent with backpressure
    /// semantics: a slow consumer pauses the producer rather than being dropped.
    async fn queue_for(
        &self,
        connection_id: &str,
        packet: PacketEnvelope,
    ) -> Result<(), ServerError> {
        let encoded = self.codec.encode(&packet)?;
        let encoded = Bytes::from(encoded);

        // Clone the sender out of the DashMap guard before awaiting so the
        // shard lock is never held across an await point.
        let sender = match self.state.clients.get(connection_id) {
            Some(entry) => entry.clone(),
            None => {
                return Err(ServerError::Api(ApiError::not_found(
                    "connection is closed",
                )));
            }
        };

        sender
            .send(ServerOutbound::PreEncoded(encoded))
            .await
            .map_err(|_| ServerError::Api(ApiError::internal("failed to queue outbound packet")))
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
            request_id,
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
            storage_id,
        } = event;

        let ctx = EventContext {
            connection_id: connection_id.to_string(),
            peer_addr,
            event_id,
            name: name.clone(),
            data,
            attachments,
            metadata,
            storage_id,
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
                    event_id,
                    ok: false,
                    receipt: json!({}),
                    error: Some(
                        self.map_exception(ExceptionContext {
                            connection_id: connection_id.to_string(),
                            request_id: Some(event_id),
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
                    event_id,
                    ok: false,
                    receipt: json!({}),
                    error: Some(
                        self.map_exception(ExceptionContext {
                            connection_id: connection_id.to_string(),
                            request_id: Some(event_id),
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
        request_id: Option<u64>,
        route: String,
        error: ApiError,
    ) -> PacketEnvelope {
        let request_id = request_id.unwrap_or(0);
        let status = error.status;
        let payload = self
            .map_exception(ExceptionContext {
                connection_id: connection_id.to_string(),
                request_id: Some(request_id),
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

    async fn notify_connected(&self, connection_id: &str, peer_addr: Option<std::net::SocketAddr>) {
        let handlers = self.connection_handlers.clone();
        for handler in handlers {
            let context = ServerConnectionContext {
                connection_id: connection_id.to_string(),
                peer_addr,
                server: self.handle(),
            };

            if AssertUnwindSafe(handler(context))
                .catch_unwind()
                .await
                .is_err()
            {
                tracing::error!("server connected handler panicked");
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

            if AssertUnwindSafe(handler(context))
                .catch_unwind()
                .await
                .is_err()
            {
                tracing::error!("server disconnected handler panicked");
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
