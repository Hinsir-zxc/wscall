//! Shared protocol definitions for WSCALL.
//!
//! This crate contains the transport envelope, frame codec, encryption modes,
//! and inline attachment model used by both the server and client crates.

use std::sync::Arc;

use aes_gcm::{Aes256Gcm, KeyInit as AesKeyInit, Nonce as AesNonce, aead::Aead as AesAead};
use bytes::Bytes;
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use getrandom::getrandom;
use serde::de::{Deserializer, MapAccess, SeqAccess, Visitor};
use serde::ser::SerializeMap;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};

// ─── ECDH Dynamic Key Agreement ─────────────────────────────────────────────
//
// When the ECDH handshake mode is enabled, the client and server exchange
// raw X25519 public keys (32 bytes each) over the WebSocket binary channel
// immediately after the TCP/TLS upgrade. Both sides derive the same 32-byte
// ChaCha20-Poly1305 session key via SHA-256(domain ‖ DH secret). This key is
// unique per connection and never travels over the wire.

/// Domain-separation tag mixed into the SHA-256 KDF so that wscall session
/// keys cannot collide with keys derived for any other protocol.
pub const ECDH_DOMAIN_TAG: &[u8] = b"wscall-ecdh-v1";

/// Byte length of an X25519 public key (also the secret key length).
pub const ECDH_KEY_LEN: usize = 32;

/// A freshly generated X25519 keypair for the ECDH handshake.
///
/// The secret is zeroized on drop. Keep the secret on the side that generated
/// it and send only the [`EcdhKeypair::public`] bytes to the peer.
pub struct EcdhKeypair {
    secret: StaticSecret,
    public: PublicKey,
}

impl EcdhKeypair {
    /// Generates a random X25519 keypair using the platform CSPRNG.
    pub fn generate() -> Result<Self, ProtocolError> {
        let mut secret_bytes = [0u8; ECDH_KEY_LEN];
        getrandom(&mut secret_bytes).map_err(|source| ProtocolError::Random(source.to_string()))?;
        let secret = StaticSecret::from(secret_bytes);
        let public = PublicKey::from(&secret);
        Ok(Self { secret, public })
    }

    /// Returns the 32-byte public key that should be sent to the peer.
    pub fn public_bytes(&self) -> [u8; ECDH_KEY_LEN] {
        self.public.to_bytes()
    }

    /// Derives the 32-byte ChaCha20-Poly1305 session key from the peer's
    /// 32-byte public key.
    ///
    /// `peer_public` must be exactly 32 bytes received from the other side.
    pub fn derive_session_key(&self, peer_public: &[u8; ECDH_KEY_LEN]) -> [u8; 32] {
        let peer = PublicKey::from(*peer_public);
        let shared = self.secret.diffie_hellman(&peer);
        derive_session_key(&shared.to_bytes())
    }
}

/// Derives a 32-byte symmetric key from a raw X25519 shared secret.
///
/// Uses SHA-256(domain ‖ shared_secret) for domain separation. The result is
/// suitable as a ChaCha20-Poly1305 or AES-256-GCM key.
pub fn derive_session_key(shared_secret: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ECDH_DOMAIN_TAG);
    hasher.update(shared_secret);
    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

/// Parses 32 raw bytes received from the peer into an X25519 public key.
///
/// Returns an error if the slice is not exactly 32 bytes.
pub fn parse_peer_public(bytes: &[u8]) -> Result<[u8; ECDH_KEY_LEN], ProtocolError> {
    if bytes.len() != ECDH_KEY_LEN {
        return Err(ProtocolError::InvalidEcdhPublicKey {
            expected: ECDH_KEY_LEN,
            actual: bytes.len(),
        });
    }
    let mut key = [0u8; ECDH_KEY_LEN];
    key.copy_from_slice(bytes);
    Ok(key)
}

const AES256_NONCE_LEN: usize = 12;
const CHACHA20_NONCE_LEN: usize = 12;

/// Default maximum frame size: 100 MiB.
///
/// This is no longer a hard protocol constant; the server configures it via
/// `WscallServer::with_max_frame_bytes(n)` and the codec carries the value.
pub const DEFAULT_MAX_FRAME_BYTES: usize = 100 * 1024 * 1024;

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

/// Binary attachment carried alongside JSON params or event data.
///
/// In protocol v2 the attachment payload is stored as raw bytes in a binary
/// section appended after the JSON metadata, eliminating the 33% overhead of
/// Base64 encoding used in protocol v1.
///
/// The payload uses [`Bytes`] (reference-counted, immutable) so that cloning
/// an attachment — e.g. during ECDH broadcasts — is a cheap refcount bump
/// rather than a deep copy of the entire buffer.
#[derive(Debug, Clone)]
pub struct FileAttachment {
    /// Attachment identifier referenced from JSON using `{ "$file": "..." }`.
    pub id: String,
    /// Original file name.
    pub name: String,
    /// MIME type supplied by the sender.
    pub content_type: String,
    /// Raw attachment payload bytes (zero-copy shared via `Bytes`).
    pub data: Bytes,
}

impl FileAttachment {
    /// Builds a text attachment from a string.
    pub fn inline_text(
        id: impl Into<String>,
        name: impl Into<String>,
        content_type: impl Into<String>,
        text: impl AsRef<str>,
    ) -> Self {
        Self::inline_bytes(
            id,
            name,
            content_type,
            Bytes::from(text.as_ref().to_owned()),
        )
    }

    /// Builds a binary attachment from raw bytes.
    ///
    /// Accepts anything convertible into [`Bytes`] (`Vec<u8>`, `Bytes`,
    /// `&'static [u8]`, etc.).
    pub fn inline_bytes(
        id: impl Into<String>,
        name: impl Into<String>,
        content_type: impl Into<String>,
        bytes: impl Into<Bytes>,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            content_type: content_type.into(),
            data: bytes.into(),
        }
    }

    /// Returns the byte length of the attachment payload.
    pub fn size(&self) -> usize {
        self.data.len()
    }

    /// Returns a JSON reference object that points to an attachment by id.
    pub fn param_ref(id: impl Into<String>) -> Value {
        json!({ "$file": id.into() })
    }

    /// Computes the total wire size of this attachment's binary section.
    ///
    /// Layout: id_len:u8 + id + name_len:u8 + name + ct_len:u8 + ct + data_len:u32 + data
    pub(crate) fn wire_size(&self) -> usize {
        1 + self.id.len() + 1 + self.name.len() + 1 + self.content_type.len() + 4 + self.data.len()
    }

    /// Appends this attachment's binary section to `buf`.
    pub(crate) fn write_wire(&self, buf: &mut Vec<u8>) {
        buf.push(self.id.len() as u8);
        buf.extend_from_slice(self.id.as_bytes());
        buf.push(self.name.len() as u8);
        buf.extend_from_slice(self.name.as_bytes());
        buf.push(self.content_type.len() as u8);
        buf.extend_from_slice(self.content_type.as_bytes());
        buf.extend_from_slice(&(self.data.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.data);
    }

    /// Parses one attachment binary section from `data`, returning the
    /// attachment and the remaining unconsumed bytes.
    ///
    /// The payload is extracted via [`Bytes::slice`] which shares the
    /// underlying buffer (zero-copy) rather than allocating a new `Vec`.
    pub(crate) fn read_wire(data: &Bytes) -> Result<(Self, Bytes), ProtocolError> {
        let mut pos = 0;

        // id
        if pos >= data.len() {
            return Err(ProtocolError::InvalidAttachmentEncoding(
                "truncated id_len".into(),
            ));
        }
        let id_len = data[pos] as usize;
        pos += 1;
        if pos + id_len > data.len() {
            return Err(ProtocolError::InvalidAttachmentEncoding(
                "truncated id".into(),
            ));
        }
        let id = String::from_utf8_lossy(&data[pos..pos + id_len]).into_owned();
        pos += id_len;

        // name
        if pos >= data.len() {
            return Err(ProtocolError::InvalidAttachmentEncoding(
                "truncated name_len".into(),
            ));
        }
        let name_len = data[pos] as usize;
        pos += 1;
        if pos + name_len > data.len() {
            return Err(ProtocolError::InvalidAttachmentEncoding(
                "truncated name".into(),
            ));
        }
        let name = String::from_utf8_lossy(&data[pos..pos + name_len]).into_owned();
        pos += name_len;

        // content_type
        if pos >= data.len() {
            return Err(ProtocolError::InvalidAttachmentEncoding(
                "truncated ct_len".into(),
            ));
        }
        let ct_len = data[pos] as usize;
        pos += 1;
        if pos + ct_len > data.len() {
            return Err(ProtocolError::InvalidAttachmentEncoding(
                "truncated content_type".into(),
            ));
        }
        let content_type = String::from_utf8_lossy(&data[pos..pos + ct_len]).into_owned();
        pos += ct_len;

        // data
        if pos + 4 > data.len() {
            return Err(ProtocolError::InvalidAttachmentEncoding(
                "truncated data_len".into(),
            ));
        }
        let data_len =
            u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;
        if pos + data_len > data.len() {
            return Err(ProtocolError::InvalidAttachmentEncoding(
                "truncated data".into(),
            ));
        }
        // Zero-copy: slice shares the underlying Bytes buffer.
        let payload = data.slice(pos..pos + data_len);
        pos += data_len;

        Ok((
            Self {
                id,
                name,
                content_type,
                data: payload,
            },
            data.slice(pos..),
        ))
    }
}

// ─── Serde impls for FileAttachment ─────────────────────────────────────────
//
// `Bytes` does not implement Serialize/Deserialize out of the box. We provide
// manual impls using `serialize_bytes` / `visit_bytes` so that the (rarely
// used) JSON `a` field round-trips correctly.

impl Serialize for FileAttachment {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(4))?;
        map.serialize_entry("id", &self.id)?;
        map.serialize_entry("name", &self.name)?;
        map.serialize_entry("content_type", &self.content_type)?;
        map.serialize_entry("data", &self.data.to_vec())?;
        map.end()
    }
}

impl<'de> Deserialize<'de> for FileAttachment {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "snake_case")]
        enum Field {
            Id,
            Name,
            ContentType,
            Data,
        }

        struct FileAttachmentVisitor;

        impl<'de> Visitor<'de> for FileAttachmentVisitor {
            type Value = FileAttachment;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("struct FileAttachment")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut id = None;
                let mut name = None;
                let mut content_type = None;
                let mut data: Option<Bytes> = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Id => id = Some(map.next_value()?),
                        Field::Name => name = Some(map.next_value()?),
                        Field::ContentType => content_type = Some(map.next_value()?),
                        Field::Data => {
                            let bytes: Vec<u8> = map.next_value()?;
                            data = Some(Bytes::from(bytes));
                        }
                    }
                }
                Ok(FileAttachment {
                    id: id.ok_or_else(|| serde::de::Error::missing_field("id"))?,
                    name: name.ok_or_else(|| serde::de::Error::missing_field("name"))?,
                    content_type: content_type
                        .ok_or_else(|| serde::de::Error::missing_field("content_type"))?,
                    data: data.ok_or_else(|| serde::de::Error::missing_field("data"))?,
                })
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let id = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let name = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;
                let content_type = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(2, &self))?;
                let bytes: Vec<u8> = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(3, &self))?;
                Ok(FileAttachment {
                    id,
                    name,
                    content_type,
                    data: Bytes::from(bytes),
                })
            }
        }

        const FIELDS: &[&str] = &["id", "name", "content_type", "data"];
        deserializer.deserialize_struct("FileAttachment", FIELDS, FileAttachmentVisitor)
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
/// | `EventEmit`   | 1 | `i` `n` `d` `a` `m` `e` |
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
    ///
    /// The `data` payload is always a JSON object (never a scalar or string).
    EventEmit {
        event_id: u64,
        name: String,
        data: Map<String, Value>,
        attachments: Vec<FileAttachment>,
        metadata: Value,
        expect_ack: bool,
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

/// Returns `true` when the metadata value carries no information (null or `{}`).
fn metadata_is_empty(v: &Value) -> bool {
    matches!(v, Value::Null) || v.as_object().is_some_and(|m| m.is_empty())
}

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
                attachments: _,
                metadata,
            } => {
                let include_meta = !metadata_is_empty(metadata);
                let field_count = 4 + usize::from(include_meta);
                let mut s = serializer.serialize_map(Some(field_count))?;
                s.serialize_entry("k", &K_API_REQUEST)?;
                s.serialize_entry("i", request_id)?;
                s.serialize_entry("r", route)?;
                s.serialize_entry("p", params)?;
                if include_meta {
                    s.serialize_entry("m", metadata)?;
                }
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
                let include_meta = !metadata_is_empty(metadata);
                let field_count = 5 + usize::from(error.is_some()) + usize::from(include_meta);
                let mut s = serializer.serialize_map(Some(field_count))?;
                s.serialize_entry("k", &K_API_RESPONSE)?;
                s.serialize_entry("i", request_id)?;
                s.serialize_entry("o", ok)?;
                s.serialize_entry("s", status)?;
                s.serialize_entry("d", data)?;
                if let Some(err) = error {
                    s.serialize_entry("er", err)?;
                }
                if include_meta {
                    s.serialize_entry("m", metadata)?;
                }
                s.end()
            }
            Self::EventEmit {
                event_id,
                name,
                data,
                attachments: _,
                metadata,
                expect_ack,
            } => {
                let include_meta = !metadata_is_empty(metadata);
                let field_count = 5 + usize::from(include_meta);
                let mut s = serializer.serialize_map(Some(field_count))?;
                s.serialize_entry("k", &K_EVENT_EMIT)?;
                s.serialize_entry("i", event_id)?;
                s.serialize_entry("n", name)?;
                s.serialize_entry("d", data)?;
                if include_meta {
                    s.serialize_entry("m", metadata)?;
                }
                s.serialize_entry("e", expect_ack)?;
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

// --- Manual Deserialize: read numeric `k`, move fields out directly ----------
//
// The body is parsed into a JSON object map exactly once; each variant then
// *moves* its fields out of that map. Nested payloads such as `params`, `data`,
// `metadata` and `receipt` are transferred without a second traversal, unlike
// the previous `Value::deserialize` + `serde_json::from_value` pair which walked
// the whole tree twice.

/// Moves a required unsigned integer field out of the map.
fn take_u64<E: serde::de::Error>(map: &mut Map<String, Value>, key: &str) -> Result<u64, E> {
    map.remove(key).and_then(|v| v.as_u64()).ok_or_else(|| {
        E::custom(format!(
            "missing or non-numeric '{key}' field in packet body"
        ))
    })
}

/// Moves a required string field out of the map.
fn take_string<E: serde::de::Error>(map: &mut Map<String, Value>, key: &str) -> Result<String, E> {
    match map.remove(key) {
        Some(Value::String(s)) => Ok(s),
        _ => Err(E::custom(format!(
            "missing or non-string '{key}' field in packet body"
        ))),
    }
}

/// Moves an optional JSON object field, defaulting to an empty map.
fn take_object<E: serde::de::Error>(
    map: &mut Map<String, Value>,
    key: &str,
) -> Result<Map<String, Value>, E> {
    match map.remove(key) {
        None => Ok(Map::new()),
        Some(Value::Object(o)) => Ok(o),
        Some(_) => Err(E::custom(format!("'{key}' field must be a JSON object"))),
    }
}

/// Moves an optional boolean field, defaulting to `false`.
fn take_bool(map: &mut Map<String, Value>, key: &str) -> bool {
    map.remove(key).and_then(|v| v.as_bool()).unwrap_or(false)
}

/// Moves an optional `u16` field, defaulting to `0`.
fn take_u16(map: &mut Map<String, Value>, key: &str) -> u16 {
    map.remove(key).and_then(|v| v.as_u64()).unwrap_or(0) as u16
}

/// Moves the optional binary-attachment reference list (`a`).
///
/// Attachments normally travel in the frame's binary section and are injected
/// via [`PacketBody::set_attachments`]; the JSON `a` field is only honoured for
/// completeness and is almost always absent.
fn take_attachments<E: serde::de::Error>(
    map: &mut Map<String, Value>,
) -> Result<Vec<FileAttachment>, E> {
    match map.remove("a") {
        None => Ok(Vec::new()),
        Some(value) => serde_json::from_value(value).map_err(E::custom),
    }
}

/// Moves the optional error payload (`er`).
fn take_error<E: serde::de::Error>(
    map: &mut Map<String, Value>,
) -> Result<Option<ErrorPayload>, E> {
    match map.remove("er") {
        None => Ok(None),
        Some(value) => serde_json::from_value(value).map(Some).map_err(E::custom),
    }
}

impl<'de> Deserialize<'de> for PacketBody {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Parse into a JSON object map once so we can inspect the numeric `k`
        // discriminator, then move the remaining fields out by short key.
        let mut map = match Value::deserialize(deserializer)? {
            Value::Object(map) => map,
            _ => {
                return Err(serde::de::Error::custom(
                    "packet body must be a JSON object",
                ));
            }
        };

        let k = map.get("k").and_then(|v| v.as_u64()).ok_or_else(|| {
            serde::de::Error::custom("missing or non-numeric 'k' field in packet body")
        })?;
        let k = u8::try_from(k).map_err(|_| {
            serde::de::Error::custom(format!("'k' value {k} is outside the valid range"))
        })?;

        match k {
            K_API_REQUEST => Ok(Self::ApiRequest {
                request_id: take_u64(&mut map, "i")?,
                route: take_string(&mut map, "r")?,
                params: map.remove("p").unwrap_or(Value::Null),
                attachments: take_attachments(&mut map)?,
                metadata: map.remove("m").unwrap_or(Value::Null),
            }),
            K_EVENT_EMIT => Ok(Self::EventEmit {
                event_id: take_u64(&mut map, "i")?,
                name: take_string(&mut map, "n")?,
                data: take_object(&mut map, "d")?,
                attachments: take_attachments(&mut map)?,
                metadata: map.remove("m").unwrap_or(Value::Null),
                expect_ack: take_bool(&mut map, "e"),
            }),
            K_API_RESPONSE => Ok(Self::ApiResponse {
                request_id: take_u64(&mut map, "i")?,
                ok: take_bool(&mut map, "o"),
                status: take_u16(&mut map, "s"),
                data: map.remove("d").unwrap_or(Value::Null),
                error: take_error(&mut map)?,
                metadata: map.remove("m").unwrap_or(Value::Null),
            }),
            K_EVENT_ACK => Ok(Self::EventAck {
                event_id: take_u64(&mut map, "i")?,
                ok: take_bool(&mut map, "o"),
                receipt: map.remove("rc").unwrap_or(Value::Null),
                error: take_error(&mut map)?,
            }),
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

    /// Returns the attachments carried by this packet (empty for responses/acks).
    pub fn attachments(&self) -> &[FileAttachment] {
        match self {
            Self::ApiRequest { attachments, .. } => attachments,
            Self::EventEmit { attachments, .. } => attachments,
            _ => &[],
        }
    }

    /// Injects decoded binary attachments back into the packet body.
    pub fn set_attachments(&mut self, attachments: Vec<FileAttachment>) {
        match self {
            Self::ApiRequest { attachments: a, .. } => *a = attachments,
            Self::EventEmit { attachments: a, .. } => *a = attachments,
            _ => {}
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

/// Encodes and decodes WSCALL binary frames (protocol v2).
///
/// Protocol v2 uses a composite payload format: JSON metadata followed by raw
/// binary attachment sections, eliminating the Base64 overhead of protocol v1.
///
/// The symmetric ciphers are constructed once when a key is configured and shared
/// via [`Arc`] across every clone of the codec. This avoids redoing the key
/// schedule (which for AES-256-GCM is especially expensive) on every frame.
#[derive(Clone)]
pub struct FrameCodec {
    aes256_cipher: Option<Arc<Aes256Gcm>>,
    chacha20_cipher: Option<Arc<ChaCha20Poly1305>>,
    /// Maximum total frame size (including the 4-byte length prefix).
    max_frame_bytes: usize,
}

impl Default for FrameCodec {
    fn default() -> Self {
        Self {
            aes256_cipher: None,
            chacha20_cipher: None,
            max_frame_bytes: DEFAULT_MAX_FRAME_BYTES,
        }
    }
}

impl std::fmt::Debug for FrameCodec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FrameCodec")
            .field("aes256", &self.aes256_cipher.is_some())
            .field("chacha20", &self.chacha20_cipher.is_some())
            .field("max_frame_bytes", &self.max_frame_bytes)
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

    /// Sets the maximum total frame size (including the 4-byte length prefix).
    ///
    /// Frames exceeding this limit are rejected during encode/decode.
    pub fn with_max_frame_bytes(mut self, max: usize) -> Self {
        self.max_frame_bytes = max;
        self
    }

    /// Returns the configured maximum frame size.
    pub fn max_frame_bytes(&self) -> usize {
        self.max_frame_bytes
    }

    /// Encodes an envelope into a binary WSCALL frame (protocol v2 composite format).
    ///
    /// The composite payload layout (before encryption):
    /// ```text
    /// | meta_len:u32(be) | JSON_bytes | att_count:u8 | [att sections...] |
    /// ```
    pub fn encode(&self, packet: &PacketEnvelope) -> Result<Vec<u8>, ProtocolError> {
        let max_payload = self.max_frame_bytes.saturating_sub(6);
        let attachments = packet.body.attachments();
        let att_size: usize = attachments.iter().map(|a| a.wire_size()).sum();
        let message_type = packet.message_type as u8;
        let encryption = packet.encryption as u8;

        // Plaintext fast path: build the final frame in a single buffer with no
        // intermediate copies. The JSON metadata is written directly into the
        // frame via `to_writer` (no temporary `json_bytes` Vec), and the
        // `frame_len` / `meta_len` prefixes are patched in place once known.
        //
        // Layout: frame_len:u32 | msg_type:u8 | enc:u8 | meta_len:u32 | json | att_count:u8 | [atts]
        if packet.encryption == EncryptionKind::None {
            let mut frame = Vec::with_capacity(4 + 2 + 4 + 1 + att_size + 64);
            frame.extend_from_slice(&[0u8; 4]); // frame_len placeholder
            frame.push(message_type);
            frame.push(encryption);
            frame.extend_from_slice(&[0u8; 4]); // meta_len placeholder
            serde_json::to_writer(&mut frame, &packet.body)?;
            let json_len = frame.len() - 10;
            frame.push(attachments.len() as u8);
            for att in attachments {
                att.write_wire(&mut frame);
            }
            let payload_len = frame.len() - 6;
            if payload_len > max_payload {
                return Err(ProtocolError::PayloadTooLarge {
                    actual: payload_len,
                    max: max_payload,
                });
            }
            let frame_len = (frame.len() - 4) as u32;
            frame[0..4].copy_from_slice(&frame_len.to_be_bytes());
            frame[6..10].copy_from_slice(&(json_len as u32).to_be_bytes());
            return Ok(frame);
        }

        // Encrypted path: build the composite payload (meta_len | json |
        // att_count | atts) writing JSON directly, encrypt it, then wrap with
        // the frame header.
        let mut composite = Vec::with_capacity(4 + 1 + att_size + 64);
        composite.extend_from_slice(&[0u8; 4]); // meta_len placeholder
        serde_json::to_writer(&mut composite, &packet.body)?;
        let json_len = composite.len() - 4;
        composite[0..4].copy_from_slice(&(json_len as u32).to_be_bytes());
        composite.push(attachments.len() as u8);
        for att in attachments {
            att.write_wire(&mut composite);
        }

        // Pre-check size before encryption.
        if composite.len() > max_payload {
            return Err(ProtocolError::PayloadTooLarge {
                actual: composite.len(),
                max: max_payload,
            });
        }

        let payload = match packet.encryption {
            EncryptionKind::ChaCha20 => self.encrypt_chacha20(&composite)?,
            EncryptionKind::Aes256 => self.encrypt_aes256(&composite)?,
            EncryptionKind::None => unreachable!("plaintext is handled by the fast path above"),
        };

        // Post-encryption size check (nonce + tag add overhead).
        if payload.len() > max_payload {
            return Err(ProtocolError::PayloadTooLarge {
                actual: payload.len(),
                max: max_payload,
            });
        }

        let frame_len = 2 + payload.len();
        let mut frame = Vec::with_capacity(4 + frame_len);
        frame.extend_from_slice(&(frame_len as u32).to_be_bytes());
        frame.push(message_type);
        frame.push(encryption);
        frame.extend_from_slice(&payload);
        Ok(frame)
    }

    /// Decodes a binary WSCALL frame back into an envelope (protocol v2 composite format).
    ///
    /// Accepts [`Bytes`] so that plaintext attachment payloads can be extracted
    /// via zero-copy slicing of the original buffer (no intermediate `Vec`).
    pub fn decode(&self, frame: Bytes) -> Result<PacketEnvelope, ProtocolError> {
        if frame.len() < 6 {
            return Err(ProtocolError::FrameTooShort);
        }

        let declared = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]) as usize;
        let actual = frame.len() - 4;
        if declared != actual {
            return Err(ProtocolError::FrameLengthMismatch { declared, actual });
        }

        if frame.len() > self.max_frame_bytes {
            return Err(ProtocolError::FrameTooLarge {
                actual: frame.len(),
                max: self.max_frame_bytes,
            });
        }

        let message_type = MessageType::try_from(frame[4])?;
        let encryption = EncryptionKind::try_from(frame[5])?;

        // Obtain the composite payload as `Bytes`. In the plaintext path this
        // is a zero-copy slice of the original frame buffer; in the encrypted
        // path the decrypted `Vec` is wrapped into a fresh `Bytes`.
        let composite: Bytes = match encryption {
            EncryptionKind::None => frame.slice(6..),
            EncryptionKind::ChaCha20 => Bytes::from(self.decrypt_chacha20(&frame[6..])?),
            EncryptionKind::Aes256 => Bytes::from(self.decrypt_aes256(&frame[6..])?),
        };

        // Parse composite: meta_len:u32 | JSON | att_count:u8 | [att sections]
        if composite.len() < 5 {
            return Err(ProtocolError::FrameTooShort);
        }
        let meta_len =
            u32::from_be_bytes([composite[0], composite[1], composite[2], composite[3]]) as usize;
        if composite.len() < 4 + meta_len + 1 {
            return Err(ProtocolError::FrameTooShort);
        }
        let json_slice = &composite[4..4 + meta_len];
        let att_count = composite[4 + meta_len] as usize;
        let mut att_data = composite.slice(4 + meta_len + 1..);

        // Parse binary attachment sections (zero-copy via Bytes::slice).
        let mut attachments = Vec::with_capacity(att_count);
        for _ in 0..att_count {
            let (att, rest) = FileAttachment::read_wire(&att_data)?;
            attachments.push(att);
            att_data = rest;
        }

        // Parse JSON body and inject attachments.
        let mut body: PacketBody = serde_json::from_slice(json_slice)?;
        body.set_attachments(attachments);

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
pub fn decode_frame(frame: Bytes) -> Result<PacketEnvelope, ProtocolError> {
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
    #[error("frame too large: actual={actual}, max={max}")]
    FrameTooLarge { actual: usize, max: usize },
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
    #[error("invalid ECDH public key: expected {expected} bytes, got {actual}")]
    InvalidEcdhPublicKey { expected: usize, actual: usize },
    #[error("ECDH handshake failed: {0}")]
    EcdhHandshake(String),
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
        Bytes, EncryptionKind, FileAttachment, FrameCodec, PacketBody, PacketEnvelope,
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
        let decoded = decode_frame(Bytes::from(encoded)).expect("decode plaintext");
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
        let decoded = codec.decode(Bytes::from(encoded)).expect("decode aes256");
        assert!(matches!(decoded.encryption, EncryptionKind::Aes256));
    }

    #[test]
    fn attachment_roundtrip_plaintext() {
        let att = FileAttachment::inline_bytes(
            "f1",
            "test.bin",
            "application/octet-stream",
            vec![1, 2, 3, 4, 5],
        );
        let packet = PacketEnvelope::new(PacketBody::ApiRequest {
            request_id: 42,
            route: "files.upload".to_string(),
            params: json!({ "file": { "$file": "f1" } }),
            attachments: vec![att],
            metadata: json!({}),
        });

        let encoded = encode_frame(&packet).expect("encode with attachment");
        let decoded = decode_frame(Bytes::from(encoded)).expect("decode with attachment");

        let atts = decoded.body.attachments();
        assert_eq!(atts.len(), 1);
        assert_eq!(atts[0].id, "f1");
        assert_eq!(atts[0].name, "test.bin");
        assert_eq!(atts[0].content_type, "application/octet-stream");
        assert_eq!(&atts[0].data[..], &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn attachment_roundtrip_encrypted() {
        let codec = FrameCodec::plaintext().with_chacha20_key(TEST_KEY);
        let att = FileAttachment::inline_text("f2", "hello.txt", "text/plain", "hello world");
        let packet = PacketEnvelope::with_encryption(
            PacketBody::EventEmit {
                event_id: 7,
                name: "chat.message".to_string(),
                data: json!({ "text": "see attached" })
                    .as_object()
                    .unwrap()
                    .clone(),
                attachments: vec![att],
                metadata: json!({}),
                expect_ack: true,
            },
            EncryptionKind::ChaCha20,
        );

        let encoded = codec
            .encode(&packet)
            .expect("encode encrypted with attachment");
        let decoded = codec
            .decode(Bytes::from(encoded))
            .expect("decode encrypted with attachment");

        let atts = decoded.body.attachments();
        assert_eq!(atts.len(), 1);
        assert_eq!(atts[0].id, "f2");
        assert_eq!(&atts[0].data[..], b"hello world");
    }

    #[test]
    fn encode_rejects_payloads_over_limit() {
        // Use a small max to trigger the limit without allocating 100 MiB.
        let codec = FrameCodec::plaintext().with_max_frame_bytes(1024);
        let packet = PacketEnvelope::new(PacketBody::ApiResponse {
            request_id: 999,
            ok: true,
            status: 200,
            data: json!({ "blob": "a".repeat(2048) }),
            error: None,
            metadata: json!({}),
        });

        let error = codec
            .encode(&packet)
            .expect_err("oversized payload should fail");
        assert!(matches!(error, ProtocolError::PayloadTooLarge { .. }));
    }

    #[test]
    fn decode_rejects_frames_over_limit() {
        let codec = FrameCodec::plaintext().with_max_frame_bytes(64);
        // Build a valid frame that exceeds 64 bytes total.
        let packet = PacketEnvelope::new(PacketBody::ApiResponse {
            request_id: 1,
            ok: true,
            status: 200,
            data: json!({ "msg": "a]".repeat(50) }),
            error: None,
            metadata: json!({}),
        });
        let encoded = FrameCodec::plaintext()
            .encode(&packet)
            .expect("encode with default limit");
        assert!(encoded.len() > 64);

        let error = codec
            .decode(Bytes::from(encoded))
            .expect_err("oversized frame should fail");
        assert!(matches!(error, ProtocolError::FrameTooLarge { .. }));
    }
}
