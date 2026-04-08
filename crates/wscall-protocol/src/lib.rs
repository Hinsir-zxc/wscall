//! Shared protocol definitions for WSCALL.
//!
//! This crate contains the transport envelope, frame codec, encryption modes,
//! and inline attachment model used by both the server and client crates.

use aes_gcm::{Aes256Gcm, KeyInit as AesKeyInit, Nonce as AesNonce, aead::Aead as AesAead};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use getrandom::getrandom;
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

/// JSON-level message body transported inside a WSCALL frame.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PacketBody {
    /// Client-to-server API request.
    ApiRequest {
        request_id: String,
        route: String,
        params: Value,
        attachments: Vec<FileAttachment>,
        metadata: Value,
    },
    /// Server-to-client API response.
    ApiResponse {
        request_id: String,
        ok: bool,
        status: u16,
        data: Value,
        #[serde(skip_serializing_if = "Option::is_none")]
        error: Option<ErrorPayload>,
        metadata: Value,
    },
    /// Event emission in either direction.
    EventEmit {
        event_id: String,
        name: String,
        data: Value,
        attachments: Vec<FileAttachment>,
        metadata: Value,
        expect_ack: bool,
    },
    /// Acknowledgement for an emitted event.
    EventAck {
        event_id: String,
        ok: bool,
        receipt: Value,
        #[serde(skip_serializing_if = "Option::is_none")]
        error: Option<ErrorPayload>,
    },
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
#[derive(Debug, Clone, Default)]
pub struct FrameCodec {
    aes256_key: Option<[u8; 32]>,
    chacha20_key: Option<[u8; 32]>,
}

impl FrameCodec {
    /// Builds a codec configured for plaintext transport.
    pub fn plaintext() -> Self {
        Self::default()
    }

    /// Configures a ChaCha20-Poly1305 key.
    pub fn with_chacha20_key(mut self, key: [u8; 32]) -> Self {
        self.chacha20_key = Some(key);
        self
    }

    /// Configures an AES256-GCM key.
    pub fn with_aes256_key(mut self, key: [u8; 32]) -> Self {
        self.aes256_key = Some(key);
        self
    }

    /// Encodes an envelope into a binary WSCALL frame.
    pub fn encode(&self, packet: &PacketEnvelope) -> Result<Vec<u8>, ProtocolError> {
        let payload = serde_json::to_vec(&packet.body)?;
        let payload = match packet.encryption {
            EncryptionKind::None => payload,
            EncryptionKind::ChaCha20 => self.encrypt_chacha20(&payload)?,
            EncryptionKind::Aes256 => self.encrypt_aes256(&payload)?,
        };

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
        let payload = match encryption {
            EncryptionKind::None => frame[6..].to_vec(),
            EncryptionKind::ChaCha20 => self.decrypt_chacha20(&frame[6..])?,
            EncryptionKind::Aes256 => self.decrypt_aes256(&frame[6..])?,
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
        let key = self
            .chacha20_key
            .ok_or(ProtocolError::MissingEncryptionKey("chacha20"))?;
        let cipher = ChaCha20Poly1305::new_from_slice(&key)
            .map_err(|_| ProtocolError::InvalidEncryptionKey("chacha20"))?;
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

        let key = self
            .chacha20_key
            .ok_or(ProtocolError::MissingEncryptionKey("chacha20"))?;
        let cipher = ChaCha20Poly1305::new_from_slice(&key)
            .map_err(|_| ProtocolError::InvalidEncryptionKey("chacha20"))?;
        let (nonce_bytes, ciphertext) = payload.split_at(CHACHA20_NONCE_LEN);
        cipher
            .decrypt(Nonce::from_slice(nonce_bytes), ciphertext)
            .map_err(|_| ProtocolError::DecryptionFailed("chacha20"))
    }

    fn encrypt_aes256(&self, payload: &[u8]) -> Result<Vec<u8>, ProtocolError> {
        let key = self
            .aes256_key
            .ok_or(ProtocolError::MissingEncryptionKey("aes256"))?;
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|_| ProtocolError::InvalidEncryptionKey("aes256"))?;
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

        let key = self
            .aes256_key
            .ok_or(ProtocolError::MissingEncryptionKey("aes256"))?;
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|_| ProtocolError::InvalidEncryptionKey("aes256"))?;
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
            event_id: "evt-1".to_string(),
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
                request_id: "req-1".to_string(),
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
            request_id: "req-oversize".to_string(),
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
