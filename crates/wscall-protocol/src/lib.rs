//! Shared protocol definitions for WSCALL.
//!
//! This crate contains the transport envelope, frame codec, encryption modes,
//! and inline attachment model used by both the server and client crates.

use std::borrow::Cow;
use std::sync::Arc;

use aes_gcm::{Aes256Gcm, KeyInit as AesKeyInit, Nonce as AesNonce, aead::Aead as AesAead};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use getrandom::getrandom;
use serde::de::Deserializer;
use serde::ser::SerializeMap;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use thiserror::Error;

const AES256_NONCE_LEN: usize = 12;
const CHACHA20_NONCE_LEN: usize = 12;
const MAX_FRAME_BYTES: usize = 10 * 1024 * 1024;
const MAX_PAYLOAD_BYTES: usize = MAX_FRAME_BYTES - 6;

/// Distinguishes API messages from event messages inside a WSCALL frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum MessageType {
    /// API request or API response.
    Api = 0x00,
    /// Event emit or event acknowledgement.
    Event = 0x01,
}

impl TryFrom<u8> for MessageType {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(Self::Api),
            0x01 => Ok(Self::Event),
            _ => Err(ProtocolError::UnknownMessageType(value)),
        }
    }
}

/// Selects how the payload section of a frame is encoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum EncryptionKind {
    /// Unencrypted JSON payload.
    None = 0x00,
    /// ChaCha20-Poly1305 encrypted payload.
    ChaCha20 = 0x01,
    /// AES256-GCM encrypted payload.
    Aes256 = 0x02,
}

impl TryFrom<u8> for EncryptionKind {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(Self::None),
            0x01 => Ok(Self::ChaCha20),
            0x02 => Ok(Self::Aes256),
            _ => Err(ProtocolError::UnknownEncryption(value)),
        }
    }
}

/// Inline attachment carried alongside JSON params or event data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileAttachment {
    /// Attachment identifier referenced from JSON using `{ "$file": "..." }`.
    pub id: String,
    /// Original file name.
    pub name: String,
    /// MIME type supplied by the sender.
    pub content_type: String,
    /// Content transfer encoding. Current implementation uses Base64.
    pub encoding: String,
    /// Encoded attachment payload.
    pub data: String,
    /// Original byte length before encoding.
    pub size: usize,
}

impl FileAttachment {
    /// Builds an inline text attachment and encodes it as Base64.
    pub fn inline_text(
        id: impl Into<String>,
        name: impl Into<String>,
        content_type: impl Into<String>,
        text: impl AsRef<str>,
    ) -> Self {
        Self::inline_bytes(id, name, content_type, text.as_ref().as_bytes().to_vec())
    }

    /// Builds an inline binary attachment and encodes it as Base64.
    pub fn inline_bytes(
        id: impl Into<String>,
        name: impl Into<String>,
        content_type: impl Into<String>,
        bytes: Vec<u8>,
    ) -> Self {
        let size = bytes.len();
        Self {
            id: id.into(),
            name: name.into(),
            content_type: content_type.into(),
            encoding: "base64".to_string(),
            data: BASE64.encode(bytes),
            size,
        }
    }

    /// Decodes the attachment payload back into raw bytes.
    pub fn decode_bytes(&self) -> Result<Vec<u8>, ProtocolError> {
        BASE64
            .decode(self.data.as_bytes())
            .map_err(|source| ProtocolError::InvalidAttachmentEncoding(source.to_string()))
    }

    /// Returns a JSON reference object that points to an attachment by id.
    pub fn param_ref(id: impl Into<String>) -> Value {
        json!({ "$file": id.into() })
    }
}

/// Standard error payload embedded in API responses and event acknowledgements.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorPayload {
    pub code: String,
    pub message: String,
    pub status: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<Value>,
}

/// Compact numeric tag identifying each [`PacketBody`] variant in the JSON
/// wire format. Using a single-byte numeric field (`"k": 0`) instead of a
/// string tag (`"kind": "api_request"`) saves several bytes per frame.
pub const K_API_REQUEST: u8 = 0;
pub const K_EVENT_EMIT: u8 = 1;
pub const K_API_RESPONSE: u8 = 2;
pub const K_EVENT_ACK: u8 = 3;

/// JSON-level message body transported inside a WSCALL frame.
///
/// The wire format uses short single-letter keys and a numeric `k` tag to
/// minimize per-frame overhead:
///
/// | Variant | `k` | Fields |
/// | --- | --- | --- |
/// | `ApiRequest`  | 0 | `i` `r` `p` `a` `m` |
/// | `EventEmit`   | 1 | `i` `n` `d` `a` `m` `e` [`si`] |
/// | `ApiResponse` | 2 | `i` `o` `s` `d` `m` [`er`] |
/// | `EventAck`    | 3 | `i` `o` `rc` [`er`] |
#[derive(Debug, Clone)]
pub enum PacketBody {
    /// Client-to-server API request.
    ApiRequest {
        request_id: u64,
        route: String,
        params: Value,
        attachments: Vec<FileAttachment>,
        metadata: Value,
    },
    /// Server-to-client API response.
    ApiResponse {
        request_id: u64,
        ok: bool,
        status: u16,
        data: Value,
        error: Option<ErrorPayload>,
        metadata: Value,
    },
    /// Event emission in either direction.
    EventEmit {
        event_id: u64,
        name: String,
        data: Value,
        attachments: Vec<FileAttachment>,
        metadata: Value,
        expect_ack: bool,
        /// Storage ID assigned by a database or other persistent store.
        /// Serialized as `"si"` when present, omitted when `None`.
        storage_id: Option<u64>,
    },
    /// Acknowledgement for an emitted event.
    EventAck {
        event_id: u64,
        ok: bool,
        receipt: Value,
        error: Option<ErrorPayload>,
    },
}

// --- Manual Serialize: short keys + numeric `k` tag -------------------------

impl Serialize for PacketBody {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::ApiRequest {
                request_id,
                route,
                params,
                attachments,
                metadata,
            } => {
                let mut s = serializer.serialize_map(Some(6))?;
                s.serialize_entry("k", &K_API_REQUEST)?;
                s.serialize_entry("i", request_id)?;
                s.serialize_entry("r", route)?;
                s.serialize_entry("p", params)?;
                s.serialize_entry("a", attachments)?;
                s.serialize_entry("m", metadata)?;
                s.end()
            }
            Self::ApiResponse {
                request_id,
                ok,
                status,
                data,
                error,
                metadata,
            } => {
                let field_count = 5 + usize::from(error.is_some()) + 1;
                let mut s = serializer.serialize_map(Some(field_count))?;
                s.serialize_entry("k", &K_API_RESPONSE)?;
                s.serialize_entry("i", request_id)?;
                s.serialize_entry("o", ok)?;
                s.serialize_entry("s", status)?;
                s.serialize_entry("d", data)?;
                if let Some(err) = error {
                    s.serialize_entry("er", err)?;
                }
                s.serialize_entry("m", metadata)?;
                s.end()
            }
            Self::EventEmit {
                event_id,
                name,
                data,
                attachments,
                metadata,
                expect_ack,
                storage_id,
            } => {
                let field_count = 7 + usize::from(storage_id.is_some());
                let mut s = serializer.serialize_map(Some(field_count))?;
                s.serialize_entry("k", &K_EVENT_EMIT)?;
                s.serialize_entry("i", event_id)?;
                s.serialize_entry("n", name)?;
                s.serialize_entry("d", data)?;
                s.serialize_entry("a", attachments)?;
                s.serialize_entry("m", metadata)?;
                s.serialize_entry("e", expect_ack)?;
                if let Some(si) = storage_id {
                    s.serialize_entry("si", si)?;
                }
                s.end()
            }
            Self::EventAck {
                event_id,
                ok,
                receipt,
                error,
            } => {
                let field_count = 3 + usize::from(error.is_some()) + 1;
                let mut s = serializer.serialize_map(Some(field_count))?;
                s.serialize_entry("k", &K_EVENT_ACK)?;
                s.serialize_entry("i", event_id)?;
                s.serialize_entry("o", ok)?;
                s.serialize_entry("rc", receipt)?;
                if let Some(err) = error {
                    s.serialize_entry("er", err)?;
                }
                s.end()
            }
        }
    }
}

// --- Manual Deserialize: read numeric `k`, dispatch to short-key fields -------

/// Deserialization helper for [`PacketBody::ApiRequest`].
#[derive(Deserialize)]
struct ApiRequestFields {
    #[serde(rename = "i")]
    request_id: u64,
    #[serde(rename = "r")]
    route: String,
    #[serde(rename = "p", default)]
    params: Value,
    #[serde(rename = "a", default)]
    attachments: Vec<FileAttachment>,
    #[serde(rename = "m", default)]
    metadata: Value,
}

/// Deserialization helper for [`PacketBody::ApiResponse`].
#[derive(Deserialize)]
struct ApiResponseFields {
    #[serde(rename = "i")]
    request_id: u64,
    #[serde(rename = "o", default)]
    ok: bool,
    #[serde(rename = "s", default)]
    status: u16,
    #[serde(rename = "d", default)]
    data: Value,
    #[serde(rename = "er", default)]
    error: Option<ErrorPayload>,
    #[serde(rename = "m", default)]
    metadata: Value,
}

/// Deserialization helper for [`PacketBody::EventEmit`].
#[derive(Deserialize)]
struct EventEmitFields {
    #[serde(rename = "i")]
    event_id: u64,
    #[serde(rename = "n")]
    name: String,
    #[serde(rename = "d", default)]
    data: Value,
    #[serde(rename = "a", default)]
    attachments: Vec<FileAttachment>,
    #[serde(rename = "m", default)]
    metadata: Value,
    #[serde(rename = "e", default)]
    expect_ack: bool,
    #[serde(rename = "si", default)]
    storage_id: Option<u64>,
}

/// Deserialization helper for [`PacketBody::EventAck`].
#[derive(Deserialize)]
struct EventAckFields {
    #[serde(rename = "i")]
    event_id: u64,
    #[serde(rename = "o", default)]
    ok: bool,
    #[serde(rename = "rc", default)]
    receipt: Value,
    #[serde(rename = "er", default)]
    error: Option<ErrorPayload>,
}

impl<'de> Deserialize<'de> for PacketBody {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Parse into a generic JSON value first so we can inspect the numeric
        // `k` discriminator, then dispatch to the appropriate short-key struct.
        let value = Value::deserialize(deserializer)?;
        let k = value.get("k").and_then(|v| v.as_u64()).ok_or_else(|| {
            serde::de::Error::custom("missing or non-numeric 'k' field in packet body")
        })?;
        let k = u8::try_from(k).map_err(|_| {
            serde::de::Error::custom(format!("'k' value {k} is outside the valid range"))
        })?;

        match k {
            K_API_REQUEST => {
                let f = serde_json::from_value::<ApiRequestFields>(value)
                    .map_err(serde::de::Error::custom)?;
                Ok(Self::ApiRequest {
                    request_id: f.request_id,
                    route: f.route,
                    params: f.params,
                    attachments: f.attachments,
                    metadata: f.metadata,
                })
            }
            K_EVENT_EMIT => {
                let f = serde_json::from_value::<EventEmitFields>(value)
                    .map_err(serde::de::Error::custom)?;
                Ok(Self::EventEmit {
                    event_id: f.event_id,
                    name: f.name,
                    data: f.data,
                    attachments: f.attachments,
                    metadata: f.metadata,
                    expect_ack: f.expect_ack,
                    storage_id: f.storage_id,
                })
            }
            K_API_RESPONSE => {
                let f = serde_json::from_value::<ApiResponseFields>(value)
                    .map_err(serde::de::Error::custom)?;
                Ok(Self::ApiResponse {
                    request_id: f.request_id,
                    ok: f.ok,
                    status: f.status,
                    data: f.data,
                    error: f.error,
                    metadata: f.metadata,
                })
            }
            K_EVENT_ACK => {
                let f = serde_json::from_value::<EventAckFields>(value)
                    .map_err(serde::de::Error::custom)?;
                Ok(Self::EventAck {
                    event_id: f.event_id,
                    ok: f.ok,
                    receipt: f.receipt,
                    error: f.error,
                })
            }
            _ => Err(serde::de::Error::custom(format!("unknown 'k' value: {k}"))),
        }
    }
}

impl PacketBody {
    pub fn message_type(&self) -> MessageType {
        match self {
            Self::ApiRequest { .. } | Self::ApiResponse { .. } => MessageType::Api,
            Self::EventEmit { .. } | Self::EventAck { .. } => MessageType::Event,
        }
    }
}

/// Full transport envelope before frame encoding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketEnvelope {
    /// Message category declared in the frame header.
    pub message_type: MessageType,
    /// Encryption mode declared in the frame header.
    pub encryption: EncryptionKind,
    /// JSON body payload.
    pub body: PacketBody,
}

impl PacketEnvelope {
    /// Builds a plaintext envelope from a body.
    pub fn new(body: PacketBody) -> Self {
        Self {
            message_type: body.message_type(),
            encryption: EncryptionKind::None,
            body,
        }
    }

    /// Builds an envelope with an explicit encryption mode.
    pub fn with_encryption(body: PacketBody, encryption: EncryptionKind) -> Self {
        Self {
            message_type: body.message_type(),
            encryption,
            body,
        }
    }
}

/// Encodes and decodes WSCALL binary frames.
///
/// The symmetric ciphers are constructed once when a key is configured and shared
/// via [`Arc`] across every clone of the codec. This avoids redoing the key
/// schedule (which for AES-256-GCM is especially expensive) on every frame.
#[derive(Clone, Default)]
pub struct FrameCodec {
    aes256_cipher: Option<Arc<Aes256Gcm>>,
    chacha20_cipher: Option<Arc<ChaCha20Poly1305>>,
}

impl std::fmt::Debug for FrameCodec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FrameCodec")
            .field("aes256", &self.aes256_cipher.is_some())
            .field("chacha20", &self.chacha20_cipher.is_some())
            .finish()
    }
}

impl FrameCodec {
    /// Builds a codec configured for plaintext transport.
    pub fn plaintext() -> Self {
        Self::default()
    }

    /// Configures a ChaCha20-Poly1305 key.
    ///
    /// The cipher is constructed eagerly so that subsequent frame encoding never
    /// pays for the key schedule again.
    pub fn with_chacha20_key(self, key: [u8; 32]) -> Self {
        let cipher = ChaCha20Poly1305::new_from_slice(&key)
            .expect("a 32-byte key is always valid for ChaCha20-Poly1305");
        Self {
            chacha20_cipher: Some(Arc::new(cipher)),
            ..self
        }
    }

    /// Configures an AES256-GCM key.
    ///
    /// The cipher is constructed eagerly so that subsequent frame encoding never
    /// pays for the AES key expansion again.
    pub fn with_aes256_key(self, key: [u8; 32]) -> Self {
        let cipher =
            Aes256Gcm::new_from_slice(&key).expect("a 32-byte key is always valid for AES-256-GCM");
        Self {
            aes256_cipher: Some(Arc::new(cipher)),
            ..self
        }
    }

    /// Encodes an envelope into a binary WSCALL frame.
    pub fn encode(&self, packet: &PacketEnvelope) -> Result<Vec<u8>, ProtocolError> {
        let payload = serde_json::to_vec(&packet.body)?;

        // Pre-check the serialized JSON size before doing any crypto work so
        // that oversized payloads are rejected without paying for encryption.
        if payload.len() > MAX_PAYLOAD_BYTES {
            return Err(ProtocolError::PayloadTooLarge {
                actual: payload.len(),
                max: MAX_PAYLOAD_BYTES,
            });
        }

        let payload = match packet.encryption {
            EncryptionKind::None => payload,
            EncryptionKind::ChaCha20 => self.encrypt_chacha20(&payload)?,
            EncryptionKind::Aes256 => self.encrypt_aes256(&payload)?,
        };

        // The encrypted form (nonce + ciphertext + tag) can still overflow the
        // limit even when the plaintext fit, so guard once more.
        if payload.len() > MAX_PAYLOAD_BYTES {
            return Err(ProtocolError::PayloadTooLarge {
                actual: payload.len(),
                max: MAX_PAYLOAD_BYTES,
            });
        }

        let frame_len = 2 + payload.len();
        let mut frame = Vec::with_capacity(4 + frame_len);
        frame.extend_from_slice(&(frame_len as u32).to_be_bytes());
        frame.push(packet.message_type as u8);
        frame.push(packet.encryption as u8);
        frame.extend_from_slice(&payload);
        Ok(frame)
    }

    /// Decodes a binary WSCALL frame back into an envelope.
    pub fn decode(&self, frame: &[u8]) -> Result<PacketEnvelope, ProtocolError> {
        if frame.len() < 6 {
            return Err(ProtocolError::FrameTooShort);
        }

        let declared = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]) as usize;
        let actual = frame.len() - 4;
        if declared != actual {
            return Err(ProtocolError::FrameLengthMismatch { declared, actual });
        }

        let payload_len = actual - 2;
        if payload_len > MAX_PAYLOAD_BYTES {
            return Err(ProtocolError::PayloadTooLarge {
                actual: payload_len,
                max: MAX_PAYLOAD_BYTES,
            });
        }

        let message_type = MessageType::try_from(frame[4])?;
        let encryption = EncryptionKind::try_from(frame[5])?;
        // Borrow the plaintext slice directly instead of cloning it into a Vec.
        let payload: Cow<'_, [u8]> = match encryption {
            EncryptionKind::None => Cow::Borrowed(&frame[6..]),
            EncryptionKind::ChaCha20 => Cow::Owned(self.decrypt_chacha20(&frame[6..])?),
            EncryptionKind::Aes256 => Cow::Owned(self.decrypt_aes256(&frame[6..])?),
        };

        let body: PacketBody = serde_json::from_slice(&payload)?;
        if body.message_type() != message_type {
            return Err(ProtocolError::MessageTypeMismatch);
        }

        Ok(PacketEnvelope {
            message_type,
            encryption,
            body,
        })
    }

    fn encrypt_chacha20(&self, payload: &[u8]) -> Result<Vec<u8>, ProtocolError> {
        let cipher = self
            .chacha20_cipher
            .as_ref()
            .ok_or(ProtocolError::MissingEncryptionKey("chacha20"))?;
        let mut nonce_bytes = [0_u8; CHACHA20_NONCE_LEN];
        getrandom(&mut nonce_bytes).map_err(|source| ProtocolError::Random(source.to_string()))?;
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce_bytes), payload)
            .map_err(|_| ProtocolError::EncryptionFailed("chacha20"))?;

        let mut encoded = Vec::with_capacity(CHACHA20_NONCE_LEN + ciphertext.len());
        encoded.extend_from_slice(&nonce_bytes);
        encoded.extend_from_slice(&ciphertext);
        Ok(encoded)
    }

    fn decrypt_chacha20(&self, payload: &[u8]) -> Result<Vec<u8>, ProtocolError> {
        if payload.len() < CHACHA20_NONCE_LEN {
            return Err(ProtocolError::EncryptedPayloadTooShort {
                algorithm: "chacha20",
                expected_min: CHACHA20_NONCE_LEN,
                actual: payload.len(),
            });
        }

        let cipher = self
            .chacha20_cipher
            .as_ref()
            .ok_or(ProtocolError::MissingEncryptionKey("chacha20"))?;
        let (nonce_bytes, ciphertext) = payload.split_at(CHACHA20_NONCE_LEN);
        cipher
            .decrypt(Nonce::from_slice(nonce_bytes), ciphertext)
            .map_err(|_| ProtocolError::DecryptionFailed("chacha20"))
    }

    fn encrypt_aes256(&self, payload: &[u8]) -> Result<Vec<u8>, ProtocolError> {
        let cipher = self
            .aes256_cipher
            .as_ref()
            .ok_or(ProtocolError::MissingEncryptionKey("aes256"))?;
        let mut nonce_bytes = [0_u8; AES256_NONCE_LEN];
        getrandom(&mut nonce_bytes).map_err(|source| ProtocolError::Random(source.to_string()))?;
        let ciphertext = cipher
            .encrypt(AesNonce::from_slice(&nonce_bytes), payload)
            .map_err(|_| ProtocolError::EncryptionFailed("aes256"))?;

        let mut encoded = Vec::with_capacity(AES256_NONCE_LEN + ciphertext.len());
        encoded.extend_from_slice(&nonce_bytes);
        encoded.extend_from_slice(&ciphertext);
        Ok(encoded)
    }

    fn decrypt_aes256(&self, payload: &[u8]) -> Result<Vec<u8>, ProtocolError> {
        if payload.len() < AES256_NONCE_LEN {
            return Err(ProtocolError::EncryptedPayloadTooShort {
                algorithm: "aes256",
                expected_min: AES256_NONCE_LEN,
                actual: payload.len(),
            });
        }

        let cipher = self
            .aes256_cipher
            .as_ref()
            .ok_or(ProtocolError::MissingEncryptionKey("aes256"))?;
        let (nonce_bytes, ciphertext) = payload.split_at(AES256_NONCE_LEN);
        cipher
            .decrypt(AesNonce::from_slice(nonce_bytes), ciphertext)
            .map_err(|_| ProtocolError::DecryptionFailed("aes256"))
    }
}

/// Helper for encoding a plaintext frame without constructing a custom codec.
pub fn encode_frame(packet: &PacketEnvelope) -> Result<Vec<u8>, ProtocolError> {
    FrameCodec::plaintext().encode(packet)
}

/// Helper for decoding a plaintext frame without constructing a custom codec.
pub fn decode_frame(frame: &[u8]) -> Result<PacketEnvelope, ProtocolError> {
    FrameCodec::plaintext().decode(frame)
}

/// Errors returned while encoding or decoding WSCALL frames.
#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("frame too short")]
    FrameTooShort,
    #[error("frame length mismatch: declared={declared}, actual={actual}")]
    FrameLengthMismatch { declared: usize, actual: usize },
    #[error("payload too large: actual={actual}, max={max}")]
    PayloadTooLarge { actual: usize, max: usize },
    #[error("unknown message type: {0:#x}")]
    UnknownMessageType(u8),
    #[error("unknown encryption kind: {0:#x}")]
    UnknownEncryption(u8),
    #[error("unsupported encryption kind: {0:#x}")]
    UnsupportedEncryption(u8),
    #[error("missing encryption key for {0}")]
    MissingEncryptionKey(&'static str),
    #[error("invalid encryption key for {0}")]
    InvalidEncryptionKey(&'static str),
    #[error("secure random generation failed: {0}")]
    Random(String),
    #[error(
        "encrypted payload too short for {algorithm}: expected at least {expected_min}, actual={actual}"
    )]
    EncryptedPayloadTooShort {
        algorithm: &'static str,
        expected_min: usize,
        actual: usize,
    },
    #[error("encryption failed for {0}")]
    EncryptionFailed(&'static str),
    #[error("decryption failed for {0}")]
    DecryptionFailed(&'static str),
    #[error("message type does not match packet body")]
    MessageTypeMismatch,
    #[error("invalid attachment encoding: {0}")]
    InvalidAttachmentEncoding(String),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::{
        EncryptionKind, FrameCodec, MAX_PAYLOAD_BYTES, MessageType, PacketBody, PacketEnvelope,
        ProtocolError, decode_frame, encode_frame,
    };
    use serde_json::json;

    const TEST_KEY: [u8; 32] = [0x11; 32];

    #[test]
    fn plaintext_helpers_still_work() {
        let packet = PacketEnvelope::new(PacketBody::EventAck {
            event_id: 1,
            ok: true,
            receipt: json!({ "ok": true }),
            error: None,
        });

        let encoded = encode_frame(&packet).expect("encode plaintext");
        let decoded = decode_frame(&encoded).expect("decode plaintext");
        assert!(matches!(decoded.encryption, EncryptionKind::None));
    }

    #[test]
    fn aes256_roundtrip_works() {
        let codec = FrameCodec::plaintext().with_aes256_key(TEST_KEY);
        let packet = PacketEnvelope::with_encryption(
            PacketBody::ApiResponse {
                request_id: 1,
                ok: true,
                status: 200,
                data: json!({ "message": "encrypted" }),
                error: None,
                metadata: json!({}),
            },
            EncryptionKind::Aes256,
        );

        let encoded = codec.encode(&packet).expect("encode aes256");
        let decoded = codec.decode(&encoded).expect("decode aes256");
        assert!(matches!(decoded.encryption, EncryptionKind::Aes256));
    }

    #[test]
    fn encode_rejects_payloads_over_limit() {
        let codec = FrameCodec::plaintext();
        let packet = PacketEnvelope::new(PacketBody::ApiResponse {
            request_id: 999,
            ok: true,
            status: 200,
            data: json!({ "blob": "a".repeat(10 * 1024 * 1024) }),
            error: None,
            metadata: json!({}),
        });

        let error = codec
            .encode(&packet)
            .expect_err("oversized payload should fail");
        assert!(matches!(error, ProtocolError::PayloadTooLarge { .. }));
    }

    #[test]
    fn decode_rejects_payloads_over_limit() {
        let payload = vec![0_u8; MAX_PAYLOAD_BYTES + 1];
        let frame_len = 2 + payload.len();
        let mut frame = Vec::with_capacity(4 + frame_len);
        frame.extend_from_slice(&(frame_len as u32).to_be_bytes());
        frame.push(MessageType::Api as u8);
        frame.push(EncryptionKind::None as u8);
        frame.extend_from_slice(&payload);

        let error = FrameCodec::plaintext()
            .decode(&frame)
            .expect_err("oversized payload should fail");
        assert!(matches!(error, ProtocolError::PayloadTooLarge { .. }));
    }
}
