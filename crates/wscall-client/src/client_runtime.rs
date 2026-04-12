use std::collections::HashMap;
use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use futures_util::{FutureExt, SinkExt, StreamExt, future::BoxFuture};
use serde_json::{Value, json};
use tokio::sync::{Mutex, RwLock, mpsc, oneshot};
use tokio::time::{MissedTickBehavior, interval, sleep, timeout};
use tokio_tungstenite::{connect_async, tungstenite::Message};
use uuid::Uuid;
use wscall_protocol::{
    EncryptionKind, ErrorPayload, FileAttachment, FrameCodec, PacketBody, PacketEnvelope,
};

use crate::client_types::{
    ClientConnectionEvent, ClientDisconnectEvent, ClientError, ClientOutbound, EventMessage,
};

type EventHandler = Arc<dyn Fn(EventMessage) -> BoxFuture<'static, Value> + Send + Sync>;
type ConnectionHandler = Arc<dyn Fn(ClientConnectionEvent) -> BoxFuture<'static, ()> + Send + Sync>;
type DisconnectHandler =
    Arc<dyn Fn(ClientDisconnectEvent) -> BoxFuture<'static, ()> + Send + Sync>;
type PendingSender = oneshot::Sender<Result<Value, ClientError>>;
type PendingMap = Arc<Mutex<HashMap<String, PendingSender>>>;

const CLIENT_IDLE_TIMEOUT: Duration = Duration::from_secs(45);
const CLIENT_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(15);
const CLIENT_OUTBOUND_QUEUE_CAPACITY: usize = 256;
const CLIENT_RECONNECT_BASE_DELAY_SECS: u64 = 3;
const CLIENT_RECONNECT_MAX_DELAY_SECS: u64 = 30;

#[derive(Clone)]
pub struct WscallClient {
    url: Arc<str>,
    codec: FrameCodec,
    writer: Arc<RwLock<Option<mpsc::Sender<ClientOutbound>>>>,
    pending_api: PendingMap,
    pending_event: PendingMap,
    event_handlers: Arc<RwLock<HashMap<String, Vec<EventHandler>>>>,
    connected_handlers: Arc<RwLock<Vec<ConnectionHandler>>>,
    disconnected_handlers: Arc<RwLock<Vec<DisconnectHandler>>>,
    default_timeout: Duration,
    default_encryption: EncryptionKind,
    is_connected: Arc<AtomicBool>,
    shutdown: Arc<AtomicBool>,
    connection_generation: Arc<AtomicU64>,
}

impl WscallClient {
    pub async fn connect(url: &str) -> Result<Self, ClientError> {
        Self::connect_with_settings(url, FrameCodec::plaintext(), EncryptionKind::None).await
    }

    pub async fn connect_with_chacha20(url: &str, key: [u8; 32]) -> Result<Self, ClientError> {
        Self::connect_with_settings(
            url,
            FrameCodec::plaintext().with_chacha20_key(key),
            EncryptionKind::ChaCha20,
        )
        .await
    }

    pub async fn connect_with_aes256(url: &str, key: [u8; 32]) -> Result<Self, ClientError> {
        Self::connect_with_settings(
            url,
            FrameCodec::plaintext().with_aes256_key(key),
            EncryptionKind::Aes256,
        )
        .await
    }

    async fn connect_with_settings(
        url: &str,
        codec: FrameCodec,
        default_encryption: EncryptionKind,
    ) -> Result<Self, ClientError> {
        let client = Self {
            url: Arc::<str>::from(url),
            codec,
            writer: Arc::new(RwLock::new(None)),
            pending_api: Arc::new(Mutex::new(HashMap::new())),
            pending_event: Arc::new(Mutex::new(HashMap::new())),
            event_handlers: Arc::new(RwLock::new(HashMap::new())),
            connected_handlers: Arc::new(RwLock::new(Vec::new())),
            disconnected_handlers: Arc::new(RwLock::new(Vec::new())),
            default_timeout: Duration::from_secs(10),
            default_encryption,
            is_connected: Arc::new(AtomicBool::new(false)),
            shutdown: Arc::new(AtomicBool::new(false)),
            connection_generation: Arc::new(AtomicU64::new(0)),
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

    pub fn is_connected(&self) -> bool {
        self.is_connected.load(Ordering::SeqCst)
    }

    pub async fn on_event<F, Fut>(&self, name: impl Into<String>, handler: F)
    where
        F: Fn(EventMessage) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Value> + Send + 'static,
    {
        let handler = Arc::new(move |event: EventMessage| {
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

        self.connected_handlers.write().await.push(Arc::clone(&handler));

        if self.is_connected() {
            self.invoke_connection_handler(
                handler,
                ClientConnectionEvent {
                    url: self.url.to_string(),
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

        let request_id = Uuid::new_v4().to_string();
        let route = route.into();
        let (tx, rx) = oneshot::channel();
        self.pending_api.lock().await.insert(request_id.clone(), tx);
        if self
            .send_outbound(ClientOutbound::Packet(PacketEnvelope::with_encryption(
                PacketBody::ApiRequest {
                    request_id: request_id.clone(),
                    route,
                    params,
                    attachments,
                    metadata: json!({ "client_name": "rust-demo" }),
                },
                self.default_encryption,
            )))
            .await
            .is_err()
        {
            self.pending_api.lock().await.remove(&request_id);
            return Err(ClientError::Disconnected);
        }

        match timeout(self.default_timeout, rx).await {
            Ok(result) => result.map_err(|_| ClientError::Disconnected)?,
            Err(_) => {
                self.pending_api.lock().await.remove(&request_id);
                Err(ClientError::Timeout)
            }
        }
    }

    pub async fn send_event(
        &self,
        name: impl Into<String>,
        data: Value,
        attachments: Vec<FileAttachment>,
    ) -> Result<Value, ClientError> {
        if !self.is_connected.load(Ordering::SeqCst) {
            return Err(ClientError::Disconnected);
        }

        let event_id = Uuid::new_v4().to_string();
        let (tx, rx) = oneshot::channel();
        self.pending_event.lock().await.insert(event_id.clone(), tx);
        if self
            .send_outbound(ClientOutbound::Packet(PacketEnvelope::with_encryption(
                PacketBody::EventEmit {
                    event_id: event_id.clone(),
                    name: name.into(),
                    data,
                    attachments,
                    metadata: json!({ "client_name": "rust-demo" }),
                    expect_ack: true,
                },
                self.default_encryption,
            )))
            .await
            .is_err()
        {
            self.pending_event.lock().await.remove(&event_id);
            return Err(ClientError::Disconnected);
        }

        match timeout(self.default_timeout, rx).await {
            Ok(result) => result.map_err(|_| ClientError::Disconnected)?,
            Err(_) => {
                self.pending_event.lock().await.remove(&event_id);
                Err(ClientError::Timeout)
            }
        }
    }

    pub async fn close(&self) -> Result<(), ClientError> {
        self.shutdown.store(true, Ordering::SeqCst);

        if let Some(writer) = self.writer.read().await.clone() {
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
                if let Some(tx) = self.pending_api.lock().await.remove(&request_id) {
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
                if let Some(tx) = self.pending_event.lock().await.remove(&event_id) {
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
                let event = EventMessage {
                    event_id: event_id.clone(),
                    name: name.clone(),
                    data,
                    attachments,
                    metadata,
                };
                let handlers = self
                    .event_handlers
                    .read()
                    .await
                    .get(&name)
                    .cloned()
                    .unwrap_or_default();

                let mut receipt = json!({ "handled": false });
                for handler in handlers {
                    receipt = handler(event.clone()).await;
                }

                if expect_ack {
                    let _ = self
                        .send_outbound(ClientOutbound::Packet(PacketEnvelope::with_encryption(
                            PacketBody::EventAck {
                                event_id,
                                ok: true,
                                receipt,
                                error: None,
                            },
                            self.default_encryption,
                        )))
                        .await;
                }
            }
            PacketBody::ApiRequest { .. } => {}
        }
    }

    async fn run_connection_supervisor(
        self,
        ready_tx: oneshot::Sender<Result<(), ClientError>>,
    ) {
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

            reconnect_attempt = reconnect_attempt.saturating_add(1);
            sleep(Self::reconnect_delay(reconnect_attempt)).await;
        }
    }

    async fn establish_connection(
        &self,
        generation: u64,
    ) -> Result<oneshot::Receiver<ClientError>, ClientError> {
        let (socket, _) = connect_async(self.url.as_ref()).await?;
        let (mut sink, mut stream) = socket.split();
        let (tx, mut rx) = mpsc::channel::<ClientOutbound>(CLIENT_OUTBOUND_QUEUE_CAPACITY);
        let (disconnect_tx, disconnect_rx) = oneshot::channel();
        let disconnect_signal = Arc::new(Mutex::new(Some(disconnect_tx)));

        *self.writer.write().await = Some(tx.clone());
        self.is_connected.store(true, Ordering::SeqCst);
        self.emit_connected().await;

        let writer_codec = self.codec.clone();
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
                                eprintln!("failed to encode outbound frame: {error}");
                                continue;
                            }
                        };

                        if let Err(error) = sink.send(Message::Binary(encoded)).await {
                            break ClientError::ConnectionClosed(error.to_string());
                        }
                    }
                    ClientOutbound::Ping(payload) => {
                        if let Err(error) = sink.send(Message::Ping(payload)).await {
                            break ClientError::ConnectionClosed(error.to_string());
                        }
                    }
                    ClientOutbound::Pong(payload) => {
                        if let Err(error) = sink.send(Message::Pong(payload)).await {
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
        let reader_codec = self.codec.clone();
        let reader_signal = Arc::clone(&disconnect_signal);
        tokio::spawn(async move {
            let error = loop {
                let next_message = timeout(CLIENT_IDLE_TIMEOUT, stream.next()).await;
                let message = match next_message {
                    Ok(Some(message)) => message,
                    Ok(None) => {
                        break ClientError::ConnectionClosed("reader loop stopped".to_string())
                    }
                    Err(_) => break ClientError::IdleTimeout,
                };

                match message {
                    Ok(Message::Binary(bytes)) => match reader_codec.decode(&bytes) {
                        Ok(packet) => reader_client.handle_packet(packet).await,
                        Err(error) => eprintln!("failed to decode inbound frame: {error}"),
                    },
                    Ok(Message::Close(_)) => {
                        break ClientError::ConnectionClosed("server closed connection".to_string())
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
                        eprintln!("client reader stopped: {error}");
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
        let Some(writer) = self.writer.read().await.clone() else {
            return Err(ClientError::Disconnected);
        };

        writer.send(outbound).await.map_err(|_| ClientError::Disconnected)
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

        *self.writer.write().await = None;

        let pending_api = std::mem::take(&mut *self.pending_api.lock().await);
        for sender in pending_api.into_values() {
            let _ = sender.send(Err(ClientError::ConnectionClosed(reason.clone())));
        }

        let pending_event = std::mem::take(&mut *self.pending_event.lock().await);
        for sender in pending_event.into_values() {
            let _ = sender.send(Err(ClientError::ConnectionClosed(reason.clone())));
        }

        self.emit_disconnected(ClientDisconnectEvent {
            url: self.url.to_string(),
            reason,
            will_reconnect: !self.shutdown.load(Ordering::SeqCst),
            retry_after: (!self.shutdown.load(Ordering::SeqCst))
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

    fn reconnect_delay(attempt: u32) -> Duration {
        let seconds = CLIENT_RECONNECT_BASE_DELAY_SECS
            .saturating_add(u64::from(attempt.saturating_sub(1)))
            .min(CLIENT_RECONNECT_MAX_DELAY_SECS);
        Duration::from_secs(seconds)
    }

    async fn emit_connected(&self) {
        let event = ClientConnectionEvent {
            url: self.url.to_string(),
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
        if AssertUnwindSafe(handler(event)).catch_unwind().await.is_err() {
            eprintln!("client connected handler panicked");
        }
    }

    async fn invoke_disconnect_handler(
        &self,
        handler: DisconnectHandler,
        event: ClientDisconnectEvent,
    ) {
        if AssertUnwindSafe(handler(event)).catch_unwind().await.is_err() {
            eprintln!("client disconnected handler panicked");
        }
    }
}
