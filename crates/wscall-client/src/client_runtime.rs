use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use arc_swap::ArcSwapOption;
use dashmap::DashMap;
use futures_util::{
    FutureExt, SinkExt, StreamExt,
    future::{BoxFuture, join_all},
};
use serde_json::{Map, Value, json};
use tokio::sync::{Mutex, RwLock, mpsc, oneshot};
use tokio::time::{MissedTickBehavior, interval, sleep, timeout};
use tokio_tungstenite::{connect_async, tungstenite::Message};
use wscall_protocol::{
    EcdhKeypair, ErrorPayload, FileAttachment, FrameCodec, PacketBody, PacketEnvelope,
    parse_peer_public,
};

use crate::client_types::{
    ClientConnectionEvent, ClientDisconnectEvent, ClientError, ClientOutbound, EventMessage,
    WscallClientConfig,
};

type EventHandler = Arc<dyn Fn(Arc<EventMessage>) -> BoxFuture<'static, Value> + Send + Sync>;
type ConnectionHandler = Arc<dyn Fn(ClientConnectionEvent) -> BoxFuture<'static, ()> + Send + Sync>;
type DisconnectHandler = Arc<dyn Fn(ClientDisconnectEvent) -> BoxFuture<'static, ()> + Send + Sync>;
type PendingSender = oneshot::Sender<Result<Value, ClientError>>;
/// Lock-free table of in-flight request/event correlations.
///
/// Replacing the previous `Mutex<HashMap>` removes the single contention point
/// that serialized every concurrent `call`/`send_event` and every inbound
/// response dispatch.
type PendingMap = Arc<DashMap<u64, PendingSender>>;

const CLIENT_IDLE_TIMEOUT: Duration = Duration::from_secs(45);
const CLIENT_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(15);
const CLIENT_OUTBOUND_QUEUE_CAPACITY: usize = 256;
const CLIENT_RECONNECT_BASE_DELAY_SECS: u64 = 3;
const CLIENT_RECONNECT_MAX_DELAY_SECS: u64 = 30;

/// Metadata attached to every outbound request/event.
///
/// The JSON object is constructed once and cloned thereafter, avoiding the
/// repeated map + string allocations that rebuilding `json!({...})` on every
/// `call`/`send_event` would incur.
fn client_metadata() -> Value {
    static METADATA: OnceLock<Value> = OnceLock::new();
    METADATA
        .get_or_init(|| json!({ "client_name": "rust-demo" }))
        .clone()
}

#[derive(Clone)]
pub struct WscallClient {
    /// All candidate server URLs: `[primary] + config.failover_urls`.
    urls: Arc<[Arc<str>]>,
    /// Index into `urls` of the last successfully connected server.
    last_url_idx: Arc<AtomicUsize>,
    /// Unified connection configuration (codec, encryption, reconnect, ECDH).
    config: WscallClientConfig,
    /// Lockless outbound channel handle. Reads via `load_full` never block, so
    /// `send_outbound` no longer takes a read lock and clones an `Option` per call.
    writer: Arc<ArcSwapOption<mpsc::Sender<ClientOutbound>>>,
    pending_api: PendingMap,
    pending_event: PendingMap,
    event_handlers: Arc<RwLock<std::collections::HashMap<String, Vec<EventHandler>>>>,
    connected_handlers: Arc<RwLock<Vec<ConnectionHandler>>>,
    disconnected_handlers: Arc<RwLock<Vec<DisconnectHandler>>>,
    default_timeout: Duration,
    is_connected: Arc<AtomicBool>,
    shutdown: Arc<AtomicBool>,
    connection_generation: Arc<AtomicU64>,
    /// Per-connection request id counter (starts at 1).
    next_request_id: Arc<AtomicU64>,
    /// Per-connection event id counter (starts at 1).
    next_event_id: Arc<AtomicU64>,
}

impl WscallClient {
    /// Connects to a WSCALL server with the given configuration.
    ///
    /// This is the unified entry point for establishing a client connection.
    /// Use [`WscallClientConfig`] to control encryption, ECDH key agreement,
    /// auto-reconnect behavior, and failover URLs.
    ///
    /// When [`WscallClientConfig::failover_urls`] is non-empty, the client
    /// iterates through `[url] + failover_urls` on each connection attempt,
    /// starting from the last successfully connected index. This provides
    /// automatic failover for multi-node deployments.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use wscall_client::{WscallClient, WscallClientConfig};
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// // ECDH dynamic key agreement (recommended default)
    /// let client = WscallClient::connect("ws://127.0.0.1:9001/socket", WscallClientConfig::ecdh()).await?;
    ///
    /// // With failover URLs for high availability
    /// let config = WscallClientConfig::ecdh()
    ///     .with_failover_url("ws://backup1:9001/socket")
    ///     .with_failover_url("ws://backup2:9001/socket");
    /// let client = WscallClient::connect("ws://primary:9001/socket", config).await?;
    ///
    /// // Plaintext (development only)
    /// let client = WscallClient::connect("ws://127.0.0.1:9001/socket", WscallClientConfig::plaintext()).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn connect(url: &str, config: WscallClientConfig) -> Result<Self, ClientError> {
        // Build the full URL list: primary first, then failover URLs.
        let mut urls: Vec<Arc<str>> = Vec::with_capacity(1 + config.failover_urls.len());
        urls.push(Arc::<str>::from(url));
        for failover in &config.failover_urls {
            urls.push(Arc::<str>::from(failover.as_str()));
        }

        let client = Self {
            urls: urls.into(),
            last_url_idx: Arc::new(AtomicUsize::new(0)),
            config,
            writer: Arc::new(ArcSwapOption::new(None)),
            pending_api: Arc::new(DashMap::new()),
            pending_event: Arc::new(DashMap::new()),
            event_handlers: Arc::new(RwLock::new(std::collections::HashMap::new())),
            connected_handlers: Arc::new(RwLock::new(Vec::new())),
            disconnected_handlers: Arc::new(RwLock::new(Vec::new())),
            default_timeout: Duration::from_secs(10),
            is_connected: Arc::new(AtomicBool::new(false)),
            shutdown: Arc::new(AtomicBool::new(false)),
            connection_generation: Arc::new(AtomicU64::new(0)),
            next_request_id: Arc::new(AtomicU64::new(0)),
            next_event_id: Arc::new(AtomicU64::new(0)),
        };

        let (ready_tx, ready_rx) = oneshot::channel();
        let supervisor_client = client.clone();
        tokio::spawn(async move {
            supervisor_client.run_connection_supervisor(ready_tx).await;
        });

        ready_rx.await.map_err(|_| {
            ClientError::ConnectionClosed("connection setup task stopped unexpectedly".to_string())
        })??;
        Ok(client)
    }

    /// Connect with plaintext transport (no encryption).
    #[deprecated(
        since = "0.5.0",
        note = "use WscallClient::connect(url, WscallClientConfig::plaintext())"
    )]
    pub async fn connect_plaintext(url: &str) -> Result<Self, ClientError> {
        Self::connect(url, WscallClientConfig::plaintext()).await
    }

    /// Connect with explicit control over auto-reconnect behavior.
    #[deprecated(
        since = "0.5.0",
        note = "use WscallClient::connect(url, config) with WscallClientConfig::plaintext().with_auto_reconnect(v)"
    )]
    pub async fn connect_with_auto_reconnect(
        url: &str,
        auto_reconnect: bool,
    ) -> Result<Self, ClientError> {
        Self::connect(
            url,
            WscallClientConfig::plaintext().with_auto_reconnect(auto_reconnect),
        )
        .await
    }

    /// Connect with a pre-shared ChaCha20-Poly1305 key.
    #[deprecated(
        since = "0.5.0",
        note = "use WscallClient::connect(url, WscallClientConfig::psk_chacha20(key))"
    )]
    pub async fn connect_with_chacha20(url: &str, key: [u8; 32]) -> Result<Self, ClientError> {
        Self::connect(url, WscallClientConfig::psk_chacha20(key)).await
    }

    /// Connect with a pre-shared AES-256-GCM key.
    #[deprecated(
        since = "0.5.0",
        note = "use WscallClient::connect(url, WscallClientConfig::psk_aes256(key))"
    )]
    pub async fn connect_with_aes256(url: &str, key: [u8; 32]) -> Result<Self, ClientError> {
        Self::connect(url, WscallClientConfig::psk_aes256(key)).await
    }

    /// Connect using ECDH dynamic key agreement.
    #[deprecated(
        since = "0.5.0",
        note = "use WscallClient::connect(url, WscallClientConfig::ecdh())"
    )]
    pub async fn connect_with_ecdh(url: &str) -> Result<Self, ClientError> {
        Self::connect(url, WscallClientConfig::ecdh()).await
    }

    pub fn is_connected(&self) -> bool {
        self.is_connected.load(Ordering::SeqCst)
    }

    pub async fn on_event<F, Fut>(&self, name: impl Into<String>, handler: F)
    where
        F: Fn(Arc<EventMessage>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Value> + Send + 'static,
    {
        let handler = Arc::new(move |event: Arc<EventMessage>| {
            Box::pin(handler(event)) as BoxFuture<'static, Value>
        });
        self.event_handlers
            .write()
            .await
            .entry(name.into())
            .or_default()
            .push(handler);
    }

    pub async fn on_connected<F, Fut>(&self, handler: F)
    where
        F: Fn(ClientConnectionEvent) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let handler: ConnectionHandler = Arc::new(move |event: ClientConnectionEvent| {
            Box::pin(handler(event)) as BoxFuture<'static, ()>
        });

        self.connected_handlers
            .write()
            .await
            .push(Arc::clone(&handler));

        if self.is_connected() {
            self.invoke_connection_handler(
                handler,
                ClientConnectionEvent {
                    url: self.current_url().to_string(),
                },
            )
            .await;
        }
    }

    pub async fn on_disconnected<F, Fut>(&self, handler: F)
    where
        F: Fn(ClientDisconnectEvent) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let handler: DisconnectHandler = Arc::new(move |event: ClientDisconnectEvent| {
            Box::pin(handler(event)) as BoxFuture<'static, ()>
        });
        self.disconnected_handlers.write().await.push(handler);
    }

    pub async fn call(
        &self,
        route: impl Into<String>,
        params: Value,
        attachments: Vec<FileAttachment>,
    ) -> Result<Value, ClientError> {
        if !self.is_connected.load(Ordering::SeqCst) {
            return Err(ClientError::Disconnected);
        }

        let request_id = self.next_request_id.fetch_add(1, Ordering::Relaxed) + 1;
        let route = route.into();
        let (tx, rx) = oneshot::channel();
        self.pending_api.insert(request_id, tx);
        if self
            .send_outbound(ClientOutbound::Packet(PacketEnvelope::with_encryption(
                PacketBody::ApiRequest {
                    request_id,
                    route,
                    params,
                    attachments,
                    metadata: client_metadata(),
                },
                self.config.default_encryption,
            )))
            .await
            .is_err()
        {
            self.pending_api.remove(&request_id);
            return Err(ClientError::Disconnected);
        }

        match timeout(self.default_timeout, rx).await {
            Ok(result) => result.map_err(|_| ClientError::Disconnected)?,
            Err(_) => {
                self.pending_api.remove(&request_id);
                Err(ClientError::Timeout)
            }
        }
    }

    pub async fn send_event(
        &self,
        name: impl Into<String>,
        data: Map<String, Value>,
        attachments: Vec<FileAttachment>,
    ) -> Result<Value, ClientError> {
        if !self.is_connected.load(Ordering::SeqCst) {
            return Err(ClientError::Disconnected);
        }

        let event_id = self.next_event_id.fetch_add(1, Ordering::Relaxed) + 1;
        let (tx, rx) = oneshot::channel();
        self.pending_event.insert(event_id, tx);
        if self
            .send_outbound(ClientOutbound::Packet(PacketEnvelope::with_encryption(
                PacketBody::EventEmit {
                    event_id,
                    name: name.into(),
                    data,
                    attachments,
                    metadata: client_metadata(),
                    expect_ack: true,
                },
                self.config.default_encryption,
            )))
            .await
            .is_err()
        {
            self.pending_event.remove(&event_id);
            return Err(ClientError::Disconnected);
        }

        match timeout(self.default_timeout, rx).await {
            Ok(result) => result.map_err(|_| ClientError::Disconnected)?,
            Err(_) => {
                self.pending_event.remove(&event_id);
                Err(ClientError::Timeout)
            }
        }
    }

    pub async fn close(&self) -> Result<(), ClientError> {
        self.shutdown.store(true, Ordering::SeqCst);

        if let Some(writer) = self.writer.load_full() {
            let _ = writer.send(ClientOutbound::Close).await;
        }

        let generation = self.connection_generation.load(Ordering::SeqCst);
        let (disconnect_tx, _disconnect_rx) = oneshot::channel();
        self.handle_disconnect(
            generation,
            ClientError::Disconnected,
            Arc::new(Mutex::new(Some(disconnect_tx))),
        )
        .await;
        Ok(())
    }

    async fn handle_packet(&self, packet: PacketEnvelope) {
        match packet.body {
            PacketBody::ApiResponse {
                request_id,
                ok,
                data,
                error,
                ..
            } => {
                if let Some((_, tx)) = self.pending_api.remove(&request_id) {
                    let result = if ok {
                        Ok(data)
                    } else {
                        Err(ClientError::Remote(error.unwrap_or_else(|| ErrorPayload {
                            code: "remote_error".to_string(),
                            message: "missing remote error".to_string(),
                            status: 500,
                            details: None,
                        })))
                    };
                    let _ = tx.send(result);
                }
            }
            PacketBody::EventAck {
                event_id,
                ok,
                receipt,
                error,
            } => {
                if let Some((_, tx)) = self.pending_event.remove(&event_id) {
                    let result = if ok {
                        Ok(receipt)
                    } else {
                        Err(ClientError::Remote(error.unwrap_or_else(|| ErrorPayload {
                            code: "remote_error".to_string(),
                            message: "missing remote error".to_string(),
                            status: 500,
                            details: None,
                        })))
                    };
                    let _ = tx.send(result);
                }
            }
            PacketBody::EventEmit {
                event_id,
                name,
                data,
                attachments,
                metadata,
                expect_ack,
            } => {
                let event = Arc::new(EventMessage {
                    event_id,
                    name: name.clone(),
                    data,
                    attachments,
                    metadata,
                });
                let handlers = self
                    .event_handlers
                    .read()
                    .await
                    .get(&name)
                    .cloned()
                    .unwrap_or_default();

                // Run all registered handlers concurrently so a single slow
                // handler no longer blocks the reader loop and subsequent
                // inbound messages. The last non-default receipt wins,
                // matching the previous serial semantics.
                let receipt = if handlers.is_empty() {
                    json!({ "handled": false })
                } else {
                    let futures = handlers.iter().map(|handler| handler(Arc::clone(&event)));
                    let results = join_all(futures).await;
                    results
                        .last()
                        .cloned()
                        .unwrap_or_else(|| json!({ "handled": false }))
                };

                if expect_ack {
                    let _ = self
                        .send_outbound(ClientOutbound::Packet(PacketEnvelope::with_encryption(
                            PacketBody::EventAck {
                                event_id,
                                ok: true,
                                receipt,
                                error: None,
                            },
                            self.config.default_encryption,
                        )))
                        .await;
                }
            }
            PacketBody::ApiRequest { .. }
            | PacketBody::AuthRequest { .. }
            | PacketBody::AuthResponse { .. } => {}
        }
    }

    async fn run_connection_supervisor(self, ready_tx: oneshot::Sender<Result<(), ClientError>>) {
        let mut ready_tx = Some(ready_tx);
        let mut reconnect_attempt = 0_u32;

        loop {
            if self.shutdown.load(Ordering::SeqCst) {
                return;
            }

            let generation = self.connection_generation.fetch_add(1, Ordering::SeqCst) + 1;
            match self.establish_connection(generation).await {
                Ok(disconnect_rx) => {
                    if let Some(ready_tx) = ready_tx.take() {
                        let _ = ready_tx.send(Ok(()));
                    }
                    reconnect_attempt = 0;
                    let _ = disconnect_rx.await;
                }
                Err(error) => {
                    if let Some(ready_tx) = ready_tx.take() {
                        let _ = ready_tx.send(Err(error));
                        return;
                    }
                }
            }

            if self.shutdown.load(Ordering::SeqCst) {
                return;
            }

            // If auto_reconnect is disabled, the supervisor exits after the
            // first disconnect instead of retrying.
            if !self.config.auto_reconnect {
                return;
            }

            reconnect_attempt = reconnect_attempt.saturating_add(1);
            // Exponential backoff plus a random sub-second jitter to avoid
            // synchronized reconnect storms when many clients recover together.
            sleep(Self::reconnect_delay(reconnect_attempt) + Self::reconnect_jitter()).await;
        }
    }

    async fn establish_connection(
        &self,
        generation: u64,
    ) -> Result<oneshot::Receiver<ClientError>, ClientError> {
        // Iterate through all candidate URLs starting from the last successful
        // index. This provides sticky failover: reconnects prefer the last
        // known-good server, falling through to alternatives on failure.
        let start = self.last_url_idx.load(Ordering::Relaxed);
        let count = self.urls.len();
        let mut last_error: Option<ClientError> = None;

        let mut socket = None;
        for offset in 0..count {
            let idx = (start + offset) % count;
            match connect_async(self.urls[idx].as_ref()).await {
                Ok((ws, _)) => {
                    self.last_url_idx.store(idx, Ordering::Relaxed);
                    socket = Some(ws);
                    break;
                }
                Err(e) => {
                    tracing::debug!(
                        url = self.urls[idx].as_ref(),
                        error = %e,
                        "failover: connection attempt failed, trying next"
                    );
                    last_error = Some(ClientError::WebSocket(e));
                }
            }
        }

        let mut socket = socket.ok_or_else(|| {
            last_error.unwrap_or_else(|| {
                ClientError::ConnectionClosed("all server URLs unreachable".to_string())
            })
        })?;

        // ECDH handshake: exchange X25519 public keys before splitting the
        // stream. The derived session key replaces the global codec for both
        // the writer and the reader.
        let session_codec = if self.config.use_ecdh {
            let keypair = EcdhKeypair::generate()?;

            // Send the client's 32-byte public key as a raw binary message.
            socket
                .send(Message::Binary(keypair.public_bytes().to_vec().into()))
                .await
                .map_err(|e| ClientError::ConnectionClosed(e.to_string()))?;

            // Read the server's 32-byte public key.
            let next = timeout(Duration::from_secs(10), socket.next()).await;
            let server_public = match next {
                Ok(Some(Ok(Message::Binary(bytes)))) => parse_peer_public(&bytes)?,
                _ => {
                    return Err(ClientError::ConnectionClosed(
                        "ECDH handshake failed: no valid server public key".to_string(),
                    ));
                }
            };

            let session_key = keypair.derive_session_key(&server_public);
            FrameCodec::plaintext().with_chacha20_key(session_key)
        } else {
            self.config.codec.clone()
        };

        // ── Auth phase ─────────────────────────────────────────────────
        // When a credential is configured, submit it to the server as an
        // AuthRequest frame (encrypted with the session key) and wait for
        // the AuthResponse verdict before completing the connection.
        if let Some(credential) = &self.config.credential {
            let request = PacketEnvelope::new(PacketBody::AuthRequest {
                credential: credential.clone(),
            });
            let encoded = session_codec.encode(&request)?;
            socket
                .send(Message::Binary(encoded.into()))
                .await
                .map_err(|e| ClientError::ConnectionClosed(e.to_string()))?;

            let next = timeout(Duration::from_secs(10), socket.next()).await;
            let response_frame = match next {
                Ok(Some(Ok(Message::Binary(bytes)))) => bytes,
                _ => {
                    return Err(ClientError::ConnectionClosed(
                        "auth handshake failed: no valid server response".to_string(),
                    ));
                }
            };

            let envelope = session_codec.decode(response_frame)?;
            match envelope.body {
                PacketBody::AuthResponse { ok: true, .. } => {}
                PacketBody::AuthResponse {
                    ok: false,
                    error: Some(error),
                    ..
                } => {
                    return Err(ClientError::AuthFailed(error));
                }
                PacketBody::AuthResponse { ok: false, .. } => {
                    return Err(ClientError::ConnectionClosed(
                        "authentication rejected by server".to_string(),
                    ));
                }
                _ => {
                    return Err(ClientError::ConnectionClosed(
                        "auth handshake failed: unexpected response frame".to_string(),
                    ));
                }
            }
        }

        let (mut sink, mut stream) = socket.split();
        let (tx, mut rx) = mpsc::channel::<ClientOutbound>(CLIENT_OUTBOUND_QUEUE_CAPACITY);
        let (disconnect_tx, disconnect_rx) = oneshot::channel();
        let disconnect_signal = Arc::new(Mutex::new(Some(disconnect_tx)));

        self.writer.store(Some(Arc::new(tx.clone())));
        self.is_connected.store(true, Ordering::SeqCst);
        self.emit_connected().await;

        let writer_codec = session_codec.clone();
        let writer_client = self.clone();
        let writer_signal = Arc::clone(&disconnect_signal);
        tokio::spawn(async move {
            let error = loop {
                let Some(outbound) = rx.recv().await else {
                    break ClientError::ConnectionClosed("writer loop stopped".to_string());
                };

                match outbound {
                    ClientOutbound::Packet(packet) => {
                        let encoded = match writer_codec.encode(&packet) {
                            Ok(encoded) => encoded,
                            Err(error) => {
                                tracing::warn!(%error, "failed to encode outbound frame");
                                continue;
                            }
                        };

                        if let Err(error) = sink.send(Message::Binary(encoded.into())).await {
                            break ClientError::ConnectionClosed(error.to_string());
                        }
                    }
                    ClientOutbound::Ping(payload) => {
                        if let Err(error) = sink.send(Message::Ping(payload.into())).await {
                            break ClientError::ConnectionClosed(error.to_string());
                        }
                    }
                    ClientOutbound::Pong(payload) => {
                        if let Err(error) = sink.send(Message::Pong(payload.into())).await {
                            break ClientError::ConnectionClosed(error.to_string());
                        }
                    }
                    ClientOutbound::Close => {
                        let _ = sink.send(Message::Close(None)).await;
                        break ClientError::ConnectionClosed("client closed".to_string());
                    }
                }
            };

            writer_client
                .handle_disconnect(generation, error, writer_signal)
                .await;
        });

        let heartbeat_client = self.clone();
        let heartbeat_tx = tx.clone();
        let heartbeat_signal = Arc::clone(&disconnect_signal);
        tokio::spawn(async move {
            let mut ticker = interval(CLIENT_HEARTBEAT_INTERVAL);
            ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                if !heartbeat_client.is_connection_generation_active(generation) {
                    break;
                }

                if heartbeat_tx
                    .send(ClientOutbound::Ping(Vec::new()))
                    .await
                    .is_err()
                {
                    heartbeat_client
                        .handle_disconnect(
                            generation,
                            ClientError::ConnectionClosed("heartbeat stopped".to_string()),
                            heartbeat_signal,
                        )
                        .await;
                    break;
                }
            }
        });

        let reader_client = self.clone();
        let reader_tx = tx;
        let reader_codec = session_codec.clone();
        let reader_signal = Arc::clone(&disconnect_signal);
        tokio::spawn(async move {
            let error = loop {
                let next_message = timeout(CLIENT_IDLE_TIMEOUT, stream.next()).await;
                let message = match next_message {
                    Ok(Some(message)) => message,
                    Ok(None) => {
                        break ClientError::ConnectionClosed("reader loop stopped".to_string());
                    }
                    Err(_) => break ClientError::IdleTimeout,
                };

                match message {
                    Ok(Message::Binary(bytes)) => match reader_codec.decode(bytes) {
                        Ok(packet) => {
                            if matches!(packet.body, PacketBody::EventEmit { .. }) {
                                // Event handlers may be slow and must compute an
                                // ack receipt, so run them on a dedicated task.
                                // This keeps the reader free to dispatch subsequent
                                // inbound frames (notably API responses) without
                                // head-of-line blocking, mirroring the server's
                                // spawn-per-request design.
                                let client = reader_client.clone();
                                tokio::spawn(async move {
                                    client.handle_packet(packet).await;
                                });
                            } else {
                                // API responses / event acks are trivial channel
                                // dispatches; handle them inline.
                                reader_client.handle_packet(packet).await;
                            }
                        }
                        Err(error) => tracing::warn!(%error, "failed to decode inbound frame"),
                    },
                    Ok(Message::Close(_)) => {
                        break ClientError::ConnectionClosed(
                            "server closed connection".to_string(),
                        );
                    }
                    Ok(Message::Ping(payload)) => {
                        if reader_tx
                            .send(ClientOutbound::Pong(payload.to_vec()))
                            .await
                            .is_err()
                        {
                            break ClientError::ConnectionClosed(
                                "failed to queue pong response".to_string(),
                            );
                        }
                    }
                    Ok(Message::Pong(_)) | Ok(Message::Text(_)) | Ok(Message::Frame(_)) => {}
                    Err(error) => {
                        tracing::warn!(%error, "client reader stopped");
                        break ClientError::ConnectionClosed(error.to_string());
                    }
                }
            };

            reader_client
                .handle_disconnect(generation, error, reader_signal)
                .await;
        });

        Ok(disconnect_rx)
    }

    async fn send_outbound(&self, outbound: ClientOutbound) -> Result<(), ClientError> {
        let Some(writer) = self.writer.load_full() else {
            return Err(ClientError::Disconnected);
        };

        writer
            .send(outbound)
            .await
            .map_err(|_| ClientError::Disconnected)
    }

    async fn handle_disconnect(
        &self,
        generation: u64,
        error: ClientError,
        disconnect_signal: Arc<Mutex<Option<oneshot::Sender<ClientError>>>>,
    ) {
        if !self.is_connection_generation_active(generation) {
            return;
        }

        let reason = Self::disconnect_reason(&error);

        if !self.is_connected.swap(false, Ordering::SeqCst) {
            return;
        }

        self.writer.store(None);

        // Drain the lock-free pending maps and notify each waiter. Keys are
        // collected first so we never hold a DashMap shard guard across an
        // await or a mutation.
        let api_keys: Vec<u64> = self.pending_api.iter().map(|kv| *kv.key()).collect();
        for key in api_keys {
            if let Some((_, sender)) = self.pending_api.remove(&key) {
                let _ = sender.send(Err(ClientError::ConnectionClosed(reason.clone())));
            }
        }

        let event_keys: Vec<u64> = self.pending_event.iter().map(|kv| *kv.key()).collect();
        for key in event_keys {
            if let Some((_, sender)) = self.pending_event.remove(&key) {
                let _ = sender.send(Err(ClientError::ConnectionClosed(reason.clone())));
            }
        }

        self.emit_disconnected(ClientDisconnectEvent {
            url: self.current_url().to_string(),
            reason,
            will_reconnect: !self.shutdown.load(Ordering::SeqCst) && self.config.auto_reconnect,
            retry_after: (!self.shutdown.load(Ordering::SeqCst) && self.config.auto_reconnect)
                .then_some(Self::reconnect_delay(1)),
        })
        .await;

        if let Some(sender) = disconnect_signal.lock().await.take() {
            let _ = sender.send(error);
        }
    }

    fn disconnect_reason(error: &ClientError) -> String {
        match error {
            ClientError::ConnectionClosed(reason) => reason.clone(),
            ClientError::IdleTimeout => "idle timeout".to_string(),
            ClientError::Disconnected => "disconnected".to_string(),
            other => other.to_string(),
        }
    }

    fn is_connection_generation_active(&self, generation: u64) -> bool {
        self.connection_generation.load(Ordering::SeqCst) == generation
    }

    /// Deterministic exponential backoff (without jitter) used for the reported
    /// `retry_after`. The supervisor adds jitter on top of this value so the
    /// displayed estimate stays stable while the actual sleep is randomized.
    fn reconnect_delay(attempt: u32) -> Duration {
        let attempt = attempt.max(1);
        let exponent = (attempt - 1).min(6);
        let seconds = CLIENT_RECONNECT_BASE_DELAY_SECS
            .saturating_mul(1u64 << exponent)
            .min(CLIENT_RECONNECT_MAX_DELAY_SECS);
        Duration::from_secs(seconds)
    }

    /// Random sub-second jitter in `[0, base/2)` to de-synchronize reconnecting
    /// clients and avoid thundering-herd spikes against a recovering server.
    fn reconnect_jitter() -> Duration {
        // OS-provided randomness keeps the jitter uncorrelated across clients;
        // the previous wall-clock nanosecond source could collide for clients
        // reconnecting in the same instant. Falls back to zero jitter (still
        // correct, just synchronized) if the entropy source ever fails.
        let mut buf = [0u8; 4];
        let nanos = match getrandom::getrandom(&mut buf) {
            Ok(()) => u32::from_le_bytes(buf) as u64,
            Err(_) => 0,
        };
        let max_nanos = (CLIENT_RECONNECT_BASE_DELAY_SECS * 1_000_000_000) / 2;
        Duration::from_nanos(nanos % max_nanos.max(1))
    }

    async fn emit_connected(&self) {
        let event = ClientConnectionEvent {
            url: self.current_url().to_string(),
        };
        let handlers = self.connected_handlers.read().await.clone();
        for handler in handlers {
            self.invoke_connection_handler(handler, event.clone()).await;
        }
    }

    async fn emit_disconnected(&self, event: ClientDisconnectEvent) {
        let handlers = self.disconnected_handlers.read().await.clone();
        for handler in handlers {
            self.invoke_disconnect_handler(handler, event.clone()).await;
        }
    }

    async fn invoke_connection_handler(
        &self,
        handler: ConnectionHandler,
        event: ClientConnectionEvent,
    ) {
        if AssertUnwindSafe(handler(event))
            .catch_unwind()
            .await
            .is_err()
        {
            tracing::error!("client connected handler panicked");
        }
    }

    async fn invoke_disconnect_handler(
        &self,
        handler: DisconnectHandler,
        event: ClientDisconnectEvent,
    ) {
        if AssertUnwindSafe(handler(event))
            .catch_unwind()
            .await
            .is_err()
        {
            tracing::error!("client disconnected handler panicked");
        }
    }

    /// Returns the URL of the last successfully connected server.
    fn current_url(&self) -> &str {
        let idx = self.last_url_idx.load(Ordering::Relaxed);
        &self.urls[idx]
    }
}
