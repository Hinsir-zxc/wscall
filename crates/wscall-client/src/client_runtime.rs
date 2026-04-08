use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt, future::BoxFuture};
use serde_json::{Value, json};
use tokio::sync::{Mutex, RwLock, mpsc, oneshot};
use tokio::time::{MissedTickBehavior, interval, timeout};
use tokio_tungstenite::{connect_async, tungstenite::Message};
use uuid::Uuid;
use wscall_protocol::{
    EncryptionKind, ErrorPayload, FileAttachment, FrameCodec, PacketBody, PacketEnvelope,
};

use crate::client_types::{ClientError, ClientOutbound, EventMessage};

type EventHandler = Arc<dyn Fn(EventMessage) -> BoxFuture<'static, Value> + Send + Sync>;
type PendingSender = oneshot::Sender<Result<Value, ClientError>>;
type PendingMap = Arc<Mutex<HashMap<String, PendingSender>>>;

const CLIENT_IDLE_TIMEOUT: Duration = Duration::from_secs(45);
const CLIENT_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(15);
const CLIENT_OUTBOUND_QUEUE_CAPACITY: usize = 256;

#[derive(Clone)]
pub struct WscallClient {
    writer: mpsc::Sender<ClientOutbound>,
    pending_api: PendingMap,
    pending_event: PendingMap,
    event_handlers: Arc<RwLock<HashMap<String, Vec<EventHandler>>>>,
    default_timeout: Duration,
    default_encryption: EncryptionKind,
    is_connected: Arc<AtomicBool>,
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
        let (socket, _) = connect_async(url).await?;
        let (mut sink, mut stream) = socket.split();
        let (tx, mut rx) = mpsc::channel::<ClientOutbound>(CLIENT_OUTBOUND_QUEUE_CAPACITY);

        let client = Self {
            writer: tx,
            pending_api: Arc::new(Mutex::new(HashMap::new())),
            pending_event: Arc::new(Mutex::new(HashMap::new())),
            event_handlers: Arc::new(RwLock::new(HashMap::new())),
            default_timeout: Duration::from_secs(10),
            default_encryption,
            is_connected: Arc::new(AtomicBool::new(true)),
        };

        let writer_codec = codec.clone();
        let writer_client = client.clone();
        tokio::spawn(async move {
            while let Some(outbound) = rx.recv().await {
                match outbound {
                    ClientOutbound::Packet(packet) => {
                        let encoded = match writer_codec.encode(&packet) {
                            Ok(encoded) => encoded,
                            Err(error) => {
                                eprintln!("failed to encode outbound frame: {error}");
                                continue;
                            }
                        };

                        if sink.send(Message::Binary(encoded)).await.is_err() {
                            break;
                        }
                    }
                    ClientOutbound::Ping(payload) => {
                        if sink.send(Message::Ping(payload)).await.is_err() {
                            break;
                        }
                    }
                    ClientOutbound::Pong(payload) => {
                        if sink.send(Message::Pong(payload)).await.is_err() {
                            break;
                        }
                    }
                    ClientOutbound::Close => {
                        let _ = sink.send(Message::Close(None)).await;
                        break;
                    }
                }
            }

            writer_client
                .handle_disconnect(ClientError::ConnectionClosed(
                    "writer loop stopped".to_string(),
                ))
                .await;
        });

        let heartbeat_client = client.clone();
        tokio::spawn(async move {
            let mut ticker = interval(CLIENT_HEARTBEAT_INTERVAL);
            ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                if !heartbeat_client.is_connected.load(Ordering::SeqCst) {
                    break;
                }

                if heartbeat_client
                    .writer
                    .send(ClientOutbound::Ping(Vec::new()))
                    .await
                    .is_err()
                {
                    heartbeat_client
                        .handle_disconnect(ClientError::ConnectionClosed(
                            "heartbeat stopped".to_string(),
                        ))
                        .await;
                    break;
                }
            }
        });

        let reader_client = client.clone();
        tokio::spawn(async move {
            loop {
                let next_message = timeout(CLIENT_IDLE_TIMEOUT, stream.next()).await;
                let message = match next_message {
                    Ok(Some(message)) => message,
                    Ok(None) => break,
                    Err(_) => {
                        reader_client
                            .handle_disconnect(ClientError::IdleTimeout)
                            .await;
                        break;
                    }
                };

                match message {
                    Ok(Message::Binary(bytes)) => match codec.decode(&bytes) {
                        Ok(packet) => reader_client.handle_packet(packet).await,
                        Err(error) => eprintln!("failed to decode inbound frame: {error}"),
                    },
                    Ok(Message::Close(_)) => break,
                    Ok(Message::Ping(payload)) => {
                        if reader_client
                            .writer
                            .send(ClientOutbound::Pong(payload.to_vec()))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    Ok(Message::Pong(_)) | Ok(Message::Text(_)) | Ok(Message::Frame(_)) => {}
                    Err(error) => {
                        eprintln!("client reader stopped: {error}");
                        reader_client
                            .handle_disconnect(ClientError::ConnectionClosed(error.to_string()))
                            .await;
                        break;
                    }
                }
            }

            reader_client
                .handle_disconnect(ClientError::ConnectionClosed(
                    "reader loop stopped".to_string(),
                ))
                .await;
        });

        Ok(client)
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
            .writer
            .send(ClientOutbound::Packet(PacketEnvelope::with_encryption(
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
            .writer
            .send(ClientOutbound::Packet(PacketEnvelope::with_encryption(
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
        self.is_connected.store(false, Ordering::SeqCst);
        self.writer
            .send(ClientOutbound::Close)
            .await
            .map_err(|_| ClientError::Disconnected)
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
                        .writer
                        .send(ClientOutbound::Packet(PacketEnvelope::with_encryption(
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

    async fn handle_disconnect(&self, error: ClientError) {
        if !self.is_connected.swap(false, Ordering::SeqCst) {
            return;
        }

        let reason = match &error {
            ClientError::ConnectionClosed(reason) => reason.clone(),
            ClientError::IdleTimeout => "idle timeout".to_string(),
            ClientError::Disconnected => "disconnected".to_string(),
            other => other.to_string(),
        };

        let pending_api = std::mem::take(&mut *self.pending_api.lock().await);
        for sender in pending_api.into_values() {
            let _ = sender.send(Err(ClientError::ConnectionClosed(reason.clone())));
        }

        let pending_event = std::mem::take(&mut *self.pending_event.lock().await);
        for sender in pending_event.into_values() {
            let _ = sender.send(Err(ClientError::ConnectionClosed(reason.clone())));
        }
    }
}
