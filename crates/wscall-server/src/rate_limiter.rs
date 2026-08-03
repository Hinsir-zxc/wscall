//! Configurable rate limiting for inbound traffic.
//!
//! The [`RateLimiter`] supports per-connection and per-IP limits on both
//! message frequency and cumulative byte volume within a sliding time window.
//! When a threshold is exceeded the limiter can optionally ban the offender
//! for a configurable duration, during which:
//!
//! - New connections from a banned IP are rejected before the WebSocket
//!   handshake (the TCP stream is dropped immediately).
//! - Route requests on existing connections receive a `503 service_busy`
//!   error response.
//! - Inbound events are silently discarded (an empty `ok:true` ack is sent
//!   to preserve protocol consistency, but no handler is invoked).

use std::net::IpAddr;
use std::time::{Duration, Instant};

use dashmap::DashMap;

/// Per-dimension rate limit configuration.
///
/// At least one of `max_messages` / `max_bytes` must be set for the
/// dimension to have any effect.
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// The time window over which counters are accumulated.
    ///
    /// Once the window elapses, counters reset to zero.
    pub period: Duration,
    /// Maximum number of inbound messages allowed per window.
    /// `None` means no message-count limit.
    pub max_messages: Option<u64>,
    /// Maximum cumulative inbound bytes allowed per window.
    /// `None` means no byte-volume limit.
    pub max_bytes: Option<u64>,
}

impl RateLimitConfig {
    /// Creates a config with the given period and no limits.
    pub fn new(period: Duration) -> Self {
        Self {
            period,
            max_messages: None,
            max_bytes: None,
        }
    }

    /// Sets the maximum message count per window.
    pub fn max_messages(mut self, max: u64) -> Self {
        self.max_messages = Some(max);
        self
    }

    /// Sets the maximum cumulative byte volume per window.
    pub fn max_bytes(mut self, max: u64) -> Self {
        self.max_bytes = Some(max);
        self
    }
}

/// Builder for configuring server-wide rate limiting.
///
/// # Example
///
/// ```rust
/// use std::time::Duration;
/// use wscall_server::rate_limiter::{RateLimiter, RateLimitConfig};
///
/// let limiter = RateLimiter::new()
///     .connection(
///         RateLimitConfig::new(Duration::from_secs(1))
///             .max_messages(100)
///             .max_bytes(1024 * 1024),
///     )
///     .ip(
///         RateLimitConfig::new(Duration::from_secs(10))
///             .max_messages(1000)
///             .max_bytes(10 * 1024 * 1024),
///     )
///     .ban_duration(Duration::from_secs(60));
/// ```
#[derive(Debug, Clone)]
pub struct RateLimiter {
    /// Per-connection rate limit configuration.
    connection: Option<RateLimitConfig>,
    /// Per-IP rate limit configuration (aggregates all connections from the
    /// same IP address).
    ip: Option<RateLimitConfig>,
    /// Duration for which an offender is banned after exceeding a threshold.
    ///
    /// During the ban:
    /// - New connections from a banned IP are rejected at the TCP level.
    /// - Route requests receive `503 service_busy`.
    /// - Events are silently discarded.
    ///
    /// `None` means rate limiting is enforced only within the window (no
    /// extended ban period).
    ban_duration: Option<Duration>,
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl RateLimiter {
    /// Creates an empty rate limiter with no limits configured.
    pub fn new() -> Self {
        Self {
            connection: None,
            ip: None,
            ban_duration: None,
        }
    }

    /// Enables per-connection rate limiting.
    pub fn connection(mut self, config: RateLimitConfig) -> Self {
        self.connection = Some(config);
        self
    }

    /// Enables per-IP rate limiting.
    pub fn ip(mut self, config: RateLimitConfig) -> Self {
        self.ip = Some(config);
        self
    }

    /// Sets the ban duration applied when a threshold is exceeded.
    pub fn ban_duration(mut self, duration: Duration) -> Self {
        self.ban_duration = Some(duration);
        self
    }

    /// Builds the internal shared state used by the server runtime.
    pub(crate) fn build(self) -> RateLimiterState {
        RateLimiterState {
            config: self,
            conn_counters: DashMap::new(),
            ip_counters: DashMap::new(),
            conn_bans: DashMap::new(),
            ip_bans: DashMap::new(),
        }
    }
}

/// The verdict returned by a rate limit check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// The message is within limits and may be processed.
    Allowed,
    /// A threshold was exceeded; the message should be rejected.
    Limited,
    /// The source is currently banned; the message should be rejected.
    Banned,
}

/// Fixed-window counter for a single dimension (connection or IP).
struct WindowCounter {
    window_start: Instant,
    message_count: u64,
    byte_count: u64,
}

impl WindowCounter {
    /// Resets the counter if the window has elapsed.
    fn maybe_reset(&mut self, now: Instant, period: Duration) {
        if now.duration_since(self.window_start) >= period {
            self.window_start = now;
            self.message_count = 0;
            self.byte_count = 0;
        }
    }
}

/// Shared rate limiter state stored inside `WscallServer`.
///
/// All maps are lock-free (`DashMap`) so concurrent connections never
/// contend on a global mutex.
pub(crate) struct RateLimiterState {
    config: RateLimiter,
    /// connection_id -> window counter
    conn_counters: DashMap<String, WindowCounter>,
    /// IpAddr -> window counter
    ip_counters: DashMap<IpAddr, WindowCounter>,
    /// connection_id -> ban expiry
    conn_bans: DashMap<String, Instant>,
    /// IpAddr -> ban expiry
    ip_bans: DashMap<IpAddr, Instant>,
}

impl RateLimiterState {
    /// Returns `true` if the given IP is currently banned.
    ///
    /// Called before the WebSocket handshake to reject banned clients early.
    pub(crate) fn is_ip_banned(&self, ip: IpAddr) -> bool {
        if let Some(entry) = self.ip_bans.get(&ip) {
            if Instant::now() < *entry.value() {
                return true;
            }
            // Ban expired – remove lazily.
            drop(entry);
            self.ip_bans.remove(&ip);
        }
        false
    }

    /// Checks rate limits and records the inbound frame.
    ///
    /// Returns the verdict indicating whether the frame may be processed.
    ///
    /// This method is on the hot path (called once per inbound data frame).
    /// It uses `get_mut` with borrowed keys to avoid heap allocations on
    /// the common path (entry already exists). Allocations only happen on
    /// the first frame from a new connection/IP.
    pub(crate) fn check_and_record(
        &self,
        connection_id: &str,
        ip: IpAddr,
        frame_len: usize,
    ) -> Verdict {
        let now = Instant::now();

        // 1. Check existing bans (fast-path: entry absent → single get).
        if let Some(entry) = self.conn_bans.get(connection_id) {
            if now < *entry.value() {
                return Verdict::Banned;
            }
            drop(entry);
            self.conn_bans.remove(connection_id);
        }
        if let Some(entry) = self.ip_bans.get(&ip) {
            if now < *entry.value() {
                return Verdict::Banned;
            }
            drop(entry);
            self.ip_bans.remove(&ip);
        }

        let mut limited = false;

        // 2. Per-connection check.
        // Use get_mut (accepts &str, no allocation) instead of entry()
        // which requires an owned String key.
        if let Some(conn_cfg) = &self.config.connection {
            if let Some(mut entry) = self.conn_counters.get_mut(connection_id) {
                let counter = entry.value_mut();
                counter.maybe_reset(now, conn_cfg.period);
                counter.message_count += 1;
                counter.byte_count += frame_len as u64;
                if Self::exceeds(counter, conn_cfg) {
                    limited = true;
                    if let Some(ban_dur) = self.config.ban_duration {
                        self.conn_bans
                            .insert(connection_id.to_string(), now + ban_dur);
                    }
                }
            } else {
                // First frame from this connection: allocate + insert.
                self.conn_counters.insert(
                    connection_id.to_string(),
                    WindowCounter {
                        window_start: now,
                        message_count: 1,
                        byte_count: frame_len as u64,
                    },
                );
                // Check if the very first frame already exceeds a
                // max_messages=0 or max_bytes=0 threshold.
                if conn_cfg.max_messages == Some(0) || conn_cfg.max_bytes == Some(0) {
                    limited = true;
                    if let Some(ban_dur) = self.config.ban_duration {
                        self.conn_bans
                            .insert(connection_id.to_string(), now + ban_dur);
                    }
                }
            }
        }

        // 3. Per-IP check (same get_mut pattern).
        if let Some(ip_cfg) = &self.config.ip {
            if let Some(mut entry) = self.ip_counters.get_mut(&ip) {
                let counter = entry.value_mut();
                counter.maybe_reset(now, ip_cfg.period);
                counter.message_count += 1;
                counter.byte_count += frame_len as u64;
                if Self::exceeds(counter, ip_cfg) {
                    limited = true;
                    if let Some(ban_dur) = self.config.ban_duration {
                        self.ip_bans.insert(ip, now + ban_dur);
                    }
                }
            } else {
                self.ip_counters.insert(
                    ip,
                    WindowCounter {
                        window_start: now,
                        message_count: 1,
                        byte_count: frame_len as u64,
                    },
                );
                if ip_cfg.max_messages == Some(0) || ip_cfg.max_bytes == Some(0) {
                    limited = true;
                    if let Some(ban_dur) = self.config.ban_duration {
                        self.ip_bans.insert(ip, now + ban_dur);
                    }
                }
            }
        }

        if limited {
            Verdict::Limited
        } else {
            Verdict::Allowed
        }
    }

    /// Removes stale counters and expired bans.
    ///
    /// Called periodically by a background task spawned in `listen()`.
    pub(crate) fn cleanup(&self) {
        let now = Instant::now();

        // Determine the longest configured period for staleness detection.
        let max_period = self
            .config
            .connection
            .as_ref()
            .map(|c| c.period)
            .into_iter()
            .chain(self.config.ip.as_ref().map(|c| c.period))
            .max()
            .unwrap_or(Duration::from_secs(60));

        let stale_threshold = max_period * 2;

        self.conn_counters
            .retain(|_, v| now.duration_since(v.window_start) < stale_threshold);
        self.ip_counters
            .retain(|_, v| now.duration_since(v.window_start) < stale_threshold);
        self.conn_bans.retain(|_, v| now < *v);
        self.ip_bans.retain(|_, v| now < *v);
    }

    /// Returns the cleanup interval (derived from the shortest period).
    pub(crate) fn cleanup_interval(&self) -> Duration {
        let min_period = self
            .config
            .connection
            .as_ref()
            .map(|c| c.period)
            .into_iter()
            .chain(self.config.ip.as_ref().map(|c| c.period))
            .min()
            .unwrap_or(Duration::from_secs(5));
        // Clean up at least once per period, but no more often than 1s.
        min_period.max(Duration::from_secs(1))
    }

    fn exceeds(counter: &WindowCounter, config: &RateLimitConfig) -> bool {
        if let Some(max_msgs) = config.max_messages {
            if counter.message_count > max_msgs {
                return true;
            }
        }
        if let Some(max_bytes) = config.max_bytes {
            if counter.byte_count > max_bytes {
                return true;
            }
        }
        false
    }
}
