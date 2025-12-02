// ============================================================================
// CONNECTION HISTORY TRACKING AND TREND ANALYSIS
// ============================================================================
// This module tracks historical TCP connection metrics to enable statistical
// analysis and detect connection degradation patterns.
//
// === WHY TRACK HISTORY? ===
// A single snapshot cannot detect problems:
// - Is the queue growing (getting worse)?
// - Is the connection stable or unstable?
// - Are problems persistent or transient?
//
// Historical tracking answers these questions by:
// 1. Storing last 10 samples of TCP metrics
// 2. Calculating velocity (rate of change)
// 3. Calculating acceleration (is change accelerating?)
// 4. Detecting persistent problems (repeated high metrics)

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

// ============================================================================
// CONSTANTS: CONFIGURATION VALUES
// ============================================================================

/// Maximum number of historical samples to keep per connection (10 samples)
///
/// === TECHNICAL ===
/// Each TcpHealthSample is ~160 bytes
/// 10 samples = ~1.6 KB per connection
/// With 100 connections = ~160 KB total
///
/// === WHY 10 SAMPLES? ===
/// - Provides ~10 seconds of data (with 1-second sampling)
/// - Enough for trend analysis (velocity, acceleration)
/// - Minimal memory overhead per connection
/// - Ring buffer provides O(1) add/remove operations
const MAX_HISTORY_SIZE: usize = 10;

/// Short-window moving average (last 3 samples)
///
/// === USAGE ===
/// Combines short-window (responsive) and long-window (smooth) moving averages
/// to detect trends:
/// - Short MA > Long MA: Queue growing (recent values higher than average)
/// - Short MA < Long MA: Queue shrinking (recent values lower than average)
const MA_SHORT_WINDOW: usize = 3;

// ============================================================================
// TCP CONNECTION HEALTH METRIC THRESHOLDS
// ============================================================================
// These constants define the sensitivity of connection health detection.
// Tuned for small message delivery (~1KB messages) where latency is critical.

/// No data sent for >1.5 seconds = EARLY WARNING of frozen send-side
///
/// === TECHNICAL ===
/// Measures tcpi_last_data_sent_ms from kernel tcp_info structure.
///
/// === WHY 1500 MS? ===
/// - Typical application keepalive: 2-5 seconds (we detect issues faster)
/// - 5-25x the normal ACK delay (~40-200ms)
/// - Fast enough to detect hangs before standard timeouts
///
/// === USE CASE ===
/// For request/response patterns with expected response < 1 second.
/// Catches frozen connections quickly, but allows for legitimate idle periods.
const STALE_SUSPECT_SEND_MS: u32 = 1500;

/// No ACK received for >1.5 seconds = EARLY WARNING of frozen receive-side
///
/// === TECHNICAL ===
/// Measures tcpi_last_ack_recv_ms from kernel tcp_info structure.
///
/// === WHY SEPARATE FROM SEND? ===
/// Directional detection:
/// - Send-side stale: Application or local side frozen
/// - Recv-side stale: Peer or return path broken
///
/// === USE CASE ===
/// Identifies one-way failures (peer dead but we don't know yet).
const STALE_SUSPECT_RECV_MS: u32 = 1500;

/// No data sent for >3 seconds = CONFIRMED DEAD (send-side frozen)
///
/// === TECHNICAL ===
/// Measures tcpi_last_data_sent_ms from kernel tcp_info structure.
///
/// === WHY 3000 MS? ===
/// - 2x the suspect threshold (avoids flapping on borderline cases)
/// - Still faster than TCP keepalive (30-60 seconds)
/// - Clear separation between "suspect" and "dead" states
///
/// === RECOMMENDATION ===
/// Close and reconnect when confirmed. Connection is unresponsive.
const STALE_CONFIRMED_SEND_MS: u32 = 3000;

/// No ACK received for >3 seconds = CONFIRMED DEAD (peer not responding)
///
/// === RECOMMENDATION ===
/// Close and reconnect. Peer is not responding to our data.
const STALE_CONFIRMED_RECV_MS: u32 = 3000;

/// Half-open detection: no ACK received for >1 second (fast threshold)
///
/// === TECHNICAL ===
/// Measures tcpi_last_ack_recv_ms from kernel tcp_info structure.
/// Kernel 3.10+ (RHEL 7+)
///
/// === HALF-OPEN CONNECTIONS ===
/// When remote peer crashes without sending RST:
/// - Peer is dead
/// - We keep sending data into the void
/// - No error reported until timeout (15+ minutes!)
///
/// === WHY 1000 MS? ===
/// - Normal ACK delay: 40-200ms (delayed ACK timer)
/// - 1 second is 5-25x normal delay
/// - Faster than retransmit timeout (RTO ~1-3 seconds)
/// - Early enough to detect before retransmissions occur
///
/// === CRITICAL FOR SMALL MESSAGES ===
/// ~1KB messages: ANY packet loss causes latency increase.
/// Fast detection enables quick failover to healthy connection.
const HALF_OPEN_NO_ACK_MS: u32 = 1000;

/// Critical packet loss ratio threshold (1%)
///
/// === TECHNICAL ===
/// Calculated as: bytes_retrans / bytes_sent
/// Kernel 5.5+ (RHEL 9+) for byte-level counters
///
/// === WHY 1%? ===
/// - TCP targets ZERO loss (each loss triggers congestion control)
/// - 1% loss can reduce throughput by 50%+
/// - Industry standard for "acceptable" loss is 0.1%
/// - We use 1% as CRITICAL threshold for action
///
/// === NOTE ===
/// For your use case (1KB messages), ANY retransmission is critical.
/// This threshold is kept for future bulk transfer monitoring.
const LOSS_CRITICAL_RATE_THRESHOLD: f64 = 0.01;

/// RTT drift threshold (current_rtt / min_rtt baseline)
///
/// === TECHNICAL ===
/// Requires tcpi_min_rtt from kernel tcp_info structure.
/// Kernel 4.6+ (RHEL 8+)
///
/// === WHAT THIS DETECTS ===
/// RTT inflated to 3x baseline indicates:
/// - Network congestion (queuing delay buildup)
/// - Routing changes (longer network path)
/// - Degraded link quality (interference, packet loss)
///
/// === EXAMPLE ===
/// Baseline: 20ms clean path → Current: 60ms = 3.0x ratio THRESHOLD EXCEEDED
///
/// === WHY 3.0? ===
/// - Normal variation: 1.0-1.5x (noise, delayed ACK)
/// - Moderate congestion: 1.5-2.5x (growing queues)
/// - Severe congestion: 3.0x+ (deep queues, drops imminent)
const RTT_DRIFT_THRESHOLD: f64 = 3.0;

/// Jitter threshold (RTT variance / average RTT)
///
/// === TECHNICAL ===
/// Calculated as: rttvar / rtt
/// Both from kernel tcp_info structure
/// Kernel 3.10+ (RHEL 7+)
///
/// === WHAT THIS DETECTS ===
/// RTT variance is 35%+ of average RTT indicates:
/// - Fluctuating network delay
/// - Route flapping
/// - Wireless link instability
///
/// === EXAMPLE ===
/// Avg RTT: 50ms, Variance: 20ms (40% of avg) → 0.40 THRESHOLD EXCEEDED (>0.35)
///
/// === IMPACT ===
/// High jitter causes RTO inflation and poor application performance.
/// Unpredictable latency is worse than high latency for latency-sensitive apps.
///
/// === WHY 0.35? ===
/// - Stable network: 0.05-0.15 (5-15% variation)
/// - Moderate instability: 0.15-0.30
/// - High instability: 0.35+ (action needed)
const JITTER_INDEX_THRESHOLD: f64 = 0.35;

/// Receiver window limitation percentage (40%)
///
/// === TECHNICAL ===
/// Calculated as: rwnd_limited_us / busy_time_us
/// Kernel 4.9+ (RHEL 8+)
///
/// === WHAT THIS DETECTS ===
/// Connection limited by receiver window (rwnd) for 40%+ of time.
/// RECEIVER is the bottleneck (cannot process data fast enough).
///
/// === BOTTLENECK ANALYSIS ===
/// TCP flow control: min(rwnd, cwnd)
/// - rwnd: Receiver says "I can accept N bytes"
/// - cwnd: Sender estimates network capacity
///
/// If rwnd_limited is high: Receiver can't keep up with sender.
///
/// === WHY 0.4 (40%)? ===
/// - Normal (0-20%): Occasional receiver backpressure
/// - Moderate (20-40%): Receiver under load
/// - Severe (40%+): Receiver is the bottleneck
const RECV_LIMITED_PCT_THRESHOLD: f64 = 0.4;

/// Send buffer limitation percentage (40%)
///
/// === TECHNICAL ===
/// Calculated as: sndbuf_limited_us / busy_time_us
/// Kernel 4.9+ (RHEL 8+)
///
/// === WHAT THIS DETECTS ===
/// Application limited by send buffer for 40%+ of time.
/// APPLICATION is the bottleneck (not writing data fast enough).
///
/// === BOTTLENECK ANALYSIS ===
/// TCP send buffer (SO_SNDBUF) holds data waiting to be sent.
/// If application doesn't write fast enough:
/// - Send buffer becomes empty
/// - TCP has nothing to send
/// - Network link is underutilized
///
/// If sndbuf_limited is high: Application is too slow for the network.
///
/// === WHY 0.4 (40%)? ===
/// Same reasoning as receiver limitation threshold.
const SENDER_LIMITED_PCT_THRESHOLD: f64 = 0.4;

/// RTO inflation ratio threshold (4.0x)
///
/// === TECHNICAL ===
/// Calculated as: rto / srtt (retransmit timeout / smoothed RTT)
/// From kernel tcp_info structure
/// Kernel 3.10+ (RHEL 7+)
///
/// === WHAT THIS DETECTS ===
/// RTO is 4x or more of smoothed RTT indicates TCP expects high packet loss.
///
/// === RTO CALCULATION ===
/// RTO = srtt + 4 * rttvar (typically 1-3x srtt normally)
/// High RTO = TCP has seen high variance or previous loss
///
/// === IMPACT ===
/// Long RTO delays recovery from packet loss (seconds, not milliseconds).
/// Often precursor to connection failure.
///
/// === WHY 4.0? ===
/// - Normal: 1.0-2.0x srtt (healthy connection)
/// - Moderate: 2.0-3.5x srtt (some packet loss)
/// - Severe: 4.0x+ srtt (frequent loss, unstable)
const RTO_RATIO_THRESHOLD: f64 = 4.0;

/// TCP state constant: ESTABLISHED connections (value = 1)
///
/// === TECHNICAL ===
/// From Linux kernel tcp_states.h
/// TCP_ESTABLISHED = 1 (active connection with data flow)
///
/// === USAGE ===
/// Health metrics only meaningful for ESTABLISHED connections.
/// Other states (SYN_SENT, CLOSE_WAIT, etc.) don't apply.
const TCP_ESTABLISHED: u8 = 1;

/// Congestion window decrease detection threshold (2 segments)
///
/// === TECHNICAL ===
/// Measured in segments (typical segment = 1460 bytes)
/// From kernel tcp_info structure (tcpi_snd_cwnd)
/// Kernel 3.10+ (RHEL 7+)
///
/// === WHAT THIS DETECTS ===
/// cwnd reduced by 2+ segments indicates TCP detected congestion.
/// Typical congestion response: cwnd reduced by 50%
///
/// === WHY 2 SEGMENTS? ===
/// - Normal ACK processing can fluctuate cwnd by 1 segment
/// - Reduction by 2+ segments indicates actual congestion event
/// - Avoids false positives from minor window adjustments
const CWND_DECREASE_THRESHOLD: u32 = 2;

// ============================================================================
// HEALTH METRIC TYPES
// ============================================================================

/// Health metric: value + human-readable explanation
///
/// === PURPOSE ===
/// Combines metric value with context (threshold, unit, significance).
/// Makes JSON responses self-documenting.
///
/// === SERIALIZATION ===
/// - Debug: For development and logging
/// - Clone: For making copies (small data)
/// - Serialize/Deserialize: For JSON conversion
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthMetric<T> {
    /// The calculated metric value
    pub value: T,

    /// Human-readable explanation
    /// Should include: what was measured, current value, threshold, context
    pub explanation: String,
}

impl<T> HealthMetric<T> {
    pub fn new(value: T, explanation: String) -> Self {
        Self { value, explanation }
    }
}

/// Boolean health flag (true = issue detected, false = normal)
pub type HealthFlag = HealthMetric<bool>;

/// Numeric health metric (for ratios, percentages, rates)
pub type HealthValue = HealthMetric<f64>;

/// Optional health metric (None if cannot calculate)
///
/// === WHY OPTIONAL? ===
/// Some metrics require kernel features not available on all systems:
/// - RTT drift requires tcpi_min_rtt (kernel 4.6+)
/// - Bottleneck detection requires tcpi_busy_time (kernel 4.9+)
/// - Loss rate requires tcpi_bytes_sent (kernel 5.5+)
pub type OptionalHealthMetric<T> = Option<HealthMetric<T>>;

/// Snapshot of TCP queue sizes at a specific time
///
/// === PURPOSE ===
/// Simple, lightweight sample (24 bytes) for queue-only metrics.
/// Can be efficiently copied and stored.
///
/// === COPY TRAIT ===
/// All fields are primitive types (safe to bitwise copy).
/// Assignment creates copy automatically (no .clone() needed).
/// Efficient for stack operations.
#[derive(Debug, Clone, Copy)]
pub struct QueueSample {
    pub timestamp: Instant,    // When this sample was taken
    pub send_queue_bytes: u32, // Bytes waiting to be sent
    pub recv_queue_bytes: u32, // Bytes waiting to be received
}

impl QueueSample {
    /// Create new queue sample with current timestamp
    #[must_use]
    pub fn new(send_queue_bytes: u32, recv_queue_bytes: u32) -> Self {
        Self {
            timestamp: Instant::now(),
            send_queue_bytes,
            recv_queue_bytes,
        }
    }

    /// Get total queue size (both directions)
    ///
    /// === TYPE CASTING ===
    /// Cast u32 to u64 before adding to prevent overflow.
    /// Two full queues: 4GB + 4GB = 8GB (won't fit in u32)
    #[must_use]
    pub fn total_queue(&self) -> u64 {
        (self.send_queue_bytes as u64) + (self.recv_queue_bytes as u64)
    }
}

// ============================================================================
// TCP HEALTH SAMPLE: COMPREHENSIVE TCP_INFO DATA
// ============================================================================

/// Comprehensive TCP connection health sample (~160 bytes)
///
/// === PURPOSE ===
/// Stores all TCP_INFO fields needed for advanced health detection:
/// - Stale/dead connection detection
/// - Half-open connection detection
/// - Packet loss and retransmission tracking
/// - RTT drift and jitter analysis
/// - Bottleneck identification
/// - Congestion state tracking
///
/// === MEMORY FOOTPRINT ===
/// - Single sample: ~160 bytes
/// - 10 samples per connection: ~1.6 KB
/// - 100 connections: ~160 KB (reasonable)
/// - 1,000 connections: ~1.6 MB (acceptable)
///
/// === KERNEL VERSION COMPATIBILITY ===
/// - Fields use 0 for unavailable data (rather than Option<T>)
/// - Kernel 3.10+: Basic fields
/// - Kernel 4.6+: Extended fields (min_rtt, delivery_rate)
/// - Kernel 4.9+: Bottleneck fields (busy_time, rwnd_limited)
/// - Kernel 5.5+: Byte counters (bytes_sent, bytes_retrans)
///
/// === COPY TRAIT ===
/// All fields are primitives (safe to bitwise copy).
/// Assignment creates copy automatically (no .clone() needed).
#[derive(Debug, Clone, Copy)]
pub struct TcpHealthSample {
    // === TIMESTAMP ===
    /// When this sample was captured (monotonic, doesn't go backwards)
    pub timestamp: Instant,

    // === QUEUE SIZES ===
    /// Bytes waiting in send queue
    /// High: Application/receiver can't keep up with network speed
    /// Low/Zero: Network is the bottleneck (sending as fast as possible)
    pub send_queue_bytes: u32,

    /// Bytes waiting in receive queue
    /// High: Application reading slower than data arriving
    /// Low/Zero: Network is limiting (slow download)
    pub recv_queue_bytes: u32,

    // === TCP STATE AND TIMING ===
    /// TCP state (1=ESTABLISHED, 2=SYN_SENT, etc.)
    /// Most health metrics only apply to ESTABLISHED connections
    pub tcp_state: u8,

    /// Milliseconds since last data sent (tcpi_last_data_sent)
    /// Used for send-side stale detection
    /// High: Send-side frozen (application not sending)
    /// Low: Send-side active (data flowing)
    /// Kernel: 3.10+ (RHEL 7+)
    pub last_data_sent_ms: u32,

    /// Milliseconds since last ACK received (tcpi_last_ack_recv)
    /// Used for receive-side stale and half-open detection
    /// High: Peer not acknowledging (peer dead or return path broken)
    /// Low: Peer responding normally
    /// Kernel: 3.10+ (RHEL 7+)
    pub last_ack_recv_ms: u32,

    /// Milliseconds since last data received (tcpi_last_data_recv)
    /// Used for receive-side stale detection
    /// High: No data received (peer not sending)
    /// Low: Data arriving
    /// Kernel: 3.10+ (RHEL 7+)
    pub last_data_recv_ms: u32,

    // === RTT METRICS ===
    /// Smoothed round-trip time in microseconds (tcpi_rtt)
    /// Average RTT over recent samples
    /// High: Slow network or congestion
    /// Low: Fast, responsive connection
    /// Kernel: 3.10+ (RHEL 7+)
    pub rtt_us: u32,

    /// RTT variance in microseconds (tcpi_rttvar)
    /// Measures RTT stability
    /// High: Unstable latency (jitter)
    /// Low: Stable, predictable latency
    /// Kernel: 3.10+ (RHEL 7+)
    pub rtt_var_us: u32,

    /// Minimum RTT observed in microseconds (tcpi_min_rtt)
    /// Baseline RTT (clean path, no congestion)
    /// 0 if unavailable (kernel < 4.6)
    /// Used for RTT drift calculation (current_rtt / min_rtt)
    /// Kernel: 4.6+ (RHEL 8+)
    pub min_rtt_us: u32,

    // === CONGESTION AND PACKET COUNTS ===
    /// Congestion window size in segments (tcpi_snd_cwnd)
    /// TCP's estimate of safe data in flight
    /// High: Large window (network has capacity)
    /// Low: Small window (congestion, recovery)
    /// Kernel: 3.10+ (RHEL 7+)
    pub snd_cwnd: u32,

    /// Slow start threshold in segments (tcpi_snd_ssthresh)
    /// Threshold below which TCP is in congestion avoidance
    /// High: Connection recovered from congestion
    /// Low: Connection experienced loss (reduced threshold)
    /// Kernel: 3.10+ (RHEL 7+)
    pub snd_ssthresh: u32,

    /// Unacknowledged packets in flight (tcpi_unacked)
    /// Data sent but not yet acknowledged
    /// High: Many outstanding packets (either normal or retransmissions)
    /// Low/Zero: No in-flight data
    /// Kernel: 3.10+ (RHEL 7+)
    pub unacked: u32,

    /// Lost packets estimate (tcpi_lost)
    /// Current estimate of packets still unrecovered
    /// High: Significant packet loss
    /// Zero: No known loss
    /// Kernel: 3.10+ (RHEL 7+)
    pub lost: u32,

    /// Currently retransmitted segments (tcpi_retrans)
    /// Segments being retransmitted right now
    /// High: Active loss recovery
    /// Zero: No retransmissions
    /// Kernel: 3.10+ (RHEL 7+)
    pub retrans: u32,

    /// Total retransmissions since connection start (tcpi_total_retrans)
    /// Cumulative count (never decreases)
    /// Delta between samples: retransmissions in that window
    /// High delta: Packet loss detected
    /// Kernel: 3.10+ (RHEL 7+)
    pub total_retrans: u32,

    // === BYTE COUNTERS (kernel 5.5+) ===
    /// Total bytes sent (tcpi_bytes_sent)
    /// Cumulative since connection start
    /// 0 if unavailable (kernel < 5.5)
    /// Delta: bytes sent in sample window
    /// Kernel: 5.5+ (RHEL 9)
    pub bytes_sent: u64,

    /// Total bytes retransmitted (tcpi_bytes_retrans)
    /// Cumulative since connection start
    /// 0 if unavailable (kernel < 5.5)
    /// Delta: retransmitted bytes in window
    /// Used for loss_rate calculation: bytes_retrans / bytes_sent
    /// Kernel: 5.5+ (RHEL 9)
    pub bytes_retrans: u64,

    /// Total bytes acknowledged (tcpi_bytes_acked)
    /// Cumulative since connection start
    /// 0 if unavailable (kernel < 5.5)
    /// Delta: 0 indicates no forward progress (stale/half-open)
    /// Kernel: 5.5+ (RHEL 9)
    pub bytes_acked: u64,

    // === BOTTLENECK DETECTION ===
    /// Microseconds connection was "busy" (tcpi_busy_time)
    /// Time with data in flight (unacked > 0)
    /// Used as denominator for bottleneck percentages
    /// 0 if unavailable (kernel < 4.9)
    /// Kernel: 4.9+ (RHEL 8+)
    pub busy_time_us: u64,

    /// Microseconds limited by receiver window (tcpi_rwnd_limited)
    /// Time when sender wanted to send but receiver window was full
    /// High: Receiver is bottleneck (can't process data)
    /// Low/Zero: Receiver keeping up
    /// 0 if unavailable (kernel < 4.9)
    /// Kernel: 4.9+ (RHEL 8+)
    pub rwnd_limited_us: u64,

    /// Microseconds limited by send buffer (tcpi_sndbuf_limited)
    /// Time when TCP wanted to send but send buffer was empty
    /// High: Application is bottleneck (not writing)
    /// Low/Zero: Application feeding data normally
    /// 0 if unavailable (kernel < 4.9)
    /// Kernel: 4.9+ (RHEL 8+)
    pub sndbuf_limited_us: u64,

    // === DELIVERY RATE ===
    /// Current delivery rate in bytes/second (tcpi_delivery_rate)
    /// Kernel's estimate of achieved throughput
    /// 0 if unavailable (kernel < 4.6)
    /// Kernel: 4.6+ (RHEL 8+)
    pub delivery_rate_bps: u64,

    /// Pacing rate in bytes/second (tcpi_pacing_rate)
    /// Rate at which TCP is sending (may be less than delivery_rate)
    /// 0 if unavailable (kernel < 4.6)
    /// Kernel: 4.6+ (RHEL 8+)
    pub pacing_rate_bps: u64,

    // === ADDITIONAL TIMING ===
    /// Retransmission timeout in milliseconds (tcpi_rto / 1000)
    /// How long TCP waits before retransmitting unacknowledged data
    /// High: TCP expects packet loss (inflated by jitter/history)
    /// Low: Confident network is reliable
    /// Kernel: 3.10+ (RHEL 7+)
    pub rto_ms: u32,

    /// Zero-window probes sent (tcpi_probes)
    /// Number of probes sent when receiver window is 0
    /// High: Receiver completely stalled
    /// Zero: Receiver has capacity
    /// Kernel: 3.10+ (RHEL 7+)
    pub probes: u8,
}

impl TcpHealthSample {
    /// Create minimal sample with only queue sizes (for simple/testing use)
    ///
    /// === USAGE ===
    /// When you only have queue data, not full TCP_INFO.
    /// All TCP metrics will be zero/defaults.
    ///
    /// For production use with real connections, use from_tcp_info() instead.
    #[must_use]
    pub fn with_queues(send_queue_bytes: u32, recv_queue_bytes: u32) -> Self {
        Self {
            timestamp: Instant::now(),
            send_queue_bytes,
            recv_queue_bytes,
            tcp_state: TCP_ESTABLISHED,
            last_data_sent_ms: 0,
            last_ack_recv_ms: 0,
            last_data_recv_ms: 0,
            rtt_us: 0,
            rtt_var_us: 0,
            min_rtt_us: 0,
            snd_cwnd: 0,
            snd_ssthresh: 0,
            unacked: 0,
            lost: 0,
            retrans: 0,
            total_retrans: 0,
            bytes_sent: 0,
            bytes_retrans: 0,
            bytes_acked: 0,
            busy_time_us: 0,
            rwnd_limited_us: 0,
            sndbuf_limited_us: 0,
            delivery_rate_bps: 0,
            pacing_rate_bps: 0,
            rto_ms: 0,
            probes: 0,
        }
    }

    /// Get total queue size (both directions)
    #[must_use]
    pub fn total_queue(&self) -> u64 {
        (self.send_queue_bytes as u64) + (self.recv_queue_bytes as u64)
    }

    /// Check if connection is in ESTABLISHED state
    ///
    /// === USAGE ===
    /// Most health metrics only apply to ESTABLISHED connections.
    #[must_use]
    pub const fn is_established(&self) -> bool {
        self.tcp_state == TCP_ESTABLISHED
    }

    /// Get time since sample was taken
    #[must_use]
    pub fn age(&self) -> Duration {
        self.timestamp.elapsed()
    }

    /// Create TcpHealthSample from raw TCP_INFO data and queue sizes
    ///
    /// === PURPOSE ===
    /// Converts netlink query results into TcpHealthSample for storage.
    ///
    /// === PARAMETERS ===
    /// - tcp_info: Raw TCP_INFO from netlink inet_diag query
    /// - send_queue_bytes: From InetDiagMsg.idiag_wqueue
    /// - recv_queue_bytes: From InetDiagMsg.idiag_rqueue
    /// - tcp_state: From InetDiagMsg.idiag_state
    ///
    /// === KERNEL VERSION HANDLING ===
    /// Extended fields default to 0 if not available:
    /// - Basic fields (3.10+): Always populated
    /// - Extended fields (4.6+, 4.9+, 5.5+): Use 0 if missing
    ///
    /// Linux only - requires netlink support
    #[cfg(target_os = "linux")]
    pub fn from_tcp_info(
        tcp_info: &crate::netlink::tcp_info::TcpInfo,
        send_queue_bytes: u32,
        recv_queue_bytes: u32,
        tcp_state: u8,
    ) -> Self {
        let basic = &tcp_info.basic;

        // Extract extended fields (0 if not available)
        let (
            min_rtt_us,
            delivery_rate_bps,
            pacing_rate_bps,
            busy_time_us,
            rwnd_limited_us,
            sndbuf_limited_us,
        ) = tcp_info
            .extended
            .as_ref()
            .map_or((0, 0, 0, 0, 0, 0), |ext| {
                (
                    ext.tcpi_min_rtt,
                    ext.tcpi_delivery_rate,
                    ext.tcpi_pacing_rate,
                    ext.tcpi_busy_time,
                    ext.tcpi_rwnd_limited,
                    ext.tcpi_sndbuf_limited,
                )
            });

        // Byte counters (kernel 5.5+)
        let (bytes_sent, bytes_retrans, bytes_acked) =
            tcp_info.extended.as_ref().map_or((0, 0, 0), |ext| {
                (
                    ext.tcpi_bytes_sent,
                    ext.tcpi_bytes_retrans,
                    ext.tcpi_bytes_acked,
                )
            });

        TcpHealthSample {
            timestamp: Instant::now(),
            send_queue_bytes,
            recv_queue_bytes,
            tcp_state,
            last_data_sent_ms: basic.tcpi_last_data_sent,
            last_ack_recv_ms: basic.tcpi_last_ack_recv,
            last_data_recv_ms: basic.tcpi_last_data_recv,
            rtt_us: basic.tcpi_rtt,
            rtt_var_us: basic.tcpi_rttvar,
            min_rtt_us,
            snd_cwnd: basic.tcpi_snd_cwnd,
            snd_ssthresh: basic.tcpi_snd_ssthresh,
            unacked: basic.tcpi_unacked,
            lost: basic.tcpi_lost,
            retrans: basic.tcpi_retrans,
            total_retrans: basic.tcpi_total_retrans,
            bytes_sent,
            bytes_retrans,
            bytes_acked,
            busy_time_us,
            rwnd_limited_us,
            sndbuf_limited_us,
            delivery_rate_bps,
            pacing_rate_bps,
            rto_ms: basic.tcpi_rto / 1000,
            probes: basic.tcpi_probes,
        }
    }

    /// Create TcpHealthSample from TcpConnectionData (RECOMMENDED for netlink)
    ///
    /// === WHAT THIS DOES ===
    /// Convenience wrapper around from_tcp_info() that accepts TcpConnectionData directly.
    /// Avoids manual field extraction from netlink query results.
    ///
    /// === BENEFITS ===
    /// 1. Cleaner code (one function call instead of unpacking fields)
    /// 2. Single source of truth (TcpConnectionData has all data)
    /// 3. Type-safe (can't forget queue sizes or state)
    ///
    /// Linux only - requires netlink feature
    #[cfg(target_os = "linux")]
    pub fn from_tcp_connection_data(conn_data: &crate::netlink::TcpConnectionData) -> Self {
        Self::from_tcp_info(
            &conn_data.tcp_info,
            conn_data.send_queue_bytes,
            conn_data.recv_queue_bytes,
            conn_data.tcp_state,
        )
    }
}

/// Trend metrics derived from historical samples
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrendMetrics {
    // === QUEUE-BASED METRICS (legacy, now part of health detection) ===
    pub send_queue_velocity: f64,
    pub recv_queue_velocity: f64,
    pub send_queue_acceleration: f64,
    pub recv_queue_acceleration: f64,
    pub send_queue_variance: f64,
    pub recv_queue_variance: f64,
    pub send_queue_ma_short: f64,
    pub send_queue_ma_long: f64,
    pub send_queue_persistent: bool,
    pub send_queue_high_count: u32,
    pub queue_growing: bool,
    pub queue_shrinking: bool,
    pub high_volatility: bool,
    pub sample_count: usize,

    // === STALE/DEAD CONNECTION DETECTION ===
    /// Send-side stale (early): no data sent for >1.5 seconds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stale_suspect_send: Option<HealthFlag>,

    /// Recv-side stale (early): no ACK received for >1.5 seconds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stale_suspect_recv: Option<HealthFlag>,

    /// Send-side stale (confirmed): no data sent for >3 seconds - DEAD
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stale_confirmed_send: Option<HealthFlag>,

    /// Recv-side stale (confirmed): no ACK for >3 seconds - PEER DEAD
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stale_confirmed_recv: Option<HealthFlag>,

    // === HALF-OPEN DETECTION ===
    /// Sending data but no ACKs for >1 second (early warning)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub half_open_suspect: Option<HealthFlag>,

    /// Half-open + retransmissions/probes (high confidence)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub half_open_confirmed: Option<HealthFlag>,

    // === PACKET LOSS DETECTION ===
    /// ANY retransmission in sample window (critical for small messages)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub loss_detected: Option<HealthFlag>,

    /// Loss rate percentage (bytes_retrans / bytes_sent)
    /// Only calculated with kernel 5.5+ (RHEL 9+) byte counters
    #[serde(skip_serializing_if = "Option::is_none")]
    pub loss_rate_pct: OptionalHealthMetric<f64>,

    // === RTT AND JITTER ===
    /// RTT drift: current / min_rtt baseline (requires kernel 4.6+)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rtt_drift: OptionalHealthMetric<f64>,

    /// Jitter index: rttvar / rtt (available on all kernels 3.10+)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jitter_index: OptionalHealthMetric<f64>,

    // === BOTTLENECK DETECTION ===
    /// Receiver window limiting percentage (requires kernel 4.9+)
    /// High: Receiver cannot process data fast enough
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recv_limited_pct: OptionalHealthMetric<f64>,

    /// Send buffer limiting percentage (requires kernel 4.9+)
    /// High: Application not writing data fast enough
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender_limited_pct: OptionalHealthMetric<f64>,

    // === CONGESTION STATE ===
    /// Congestion suspected: cwnd decreased OR retransmissions
    /// (early warning, may have false positives)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub congestion_suspected: Option<HealthFlag>,

    /// Congestion confirmed: cwnd < ssthresh AND retransmissions
    /// (high confidence that packet loss occurred)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub congestion_confirmed: Option<HealthFlag>,

    /// Congestion recovering: cwnd growing AND no new retransmissions
    /// (problem is resolving)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub congestion_recovering: Option<HealthFlag>,

    // === RTO INFLATION ===
    /// RTO inflation ratio: rto / srtt (requires kernel 3.10+)
    /// High: TCP expects packet loss, connection near failure
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rto_inflation: OptionalHealthMetric<f64>,
}

impl Default for TrendMetrics {
    fn default() -> Self {
        Self {
            send_queue_velocity: 0.0,
            recv_queue_velocity: 0.0,
            send_queue_acceleration: 0.0,
            recv_queue_acceleration: 0.0,
            send_queue_variance: 0.0,
            recv_queue_variance: 0.0,
            send_queue_ma_short: 0.0,
            send_queue_ma_long: 0.0,
            send_queue_persistent: false,
            send_queue_high_count: 0,
            queue_growing: false,
            queue_shrinking: false,
            high_volatility: false,
            sample_count: 0,
            stale_suspect_send: None,
            stale_suspect_recv: None,
            stale_confirmed_send: None,
            stale_confirmed_recv: None,
            half_open_suspect: None,
            half_open_confirmed: None,
            loss_detected: None,
            loss_rate_pct: None,
            rtt_drift: None,
            jitter_index: None,
            recv_limited_pct: None,
            sender_limited_pct: None,
            congestion_suspected: None,
            congestion_confirmed: None,
            congestion_recovering: None,
            rto_inflation: None,
        }
    }
}

/// History of connection metrics for trend analysis
#[derive(Debug, Clone)]
pub struct ConnectionHistory {
    pub remote_ip: String,
    pub remote_port: u16,

    /// Circular buffer of last 10 TCP health samples
    /// Ring buffer provides O(1) add/remove operations
    pub samples: VecDeque<TcpHealthSample>,

    pub first_seen: Instant,
    pub last_updated: Instant,
    pub current_status: String,
    pub status_change_count: u32,
    pub last_status_change: Instant,

    /// Cached trend metrics (updated on each sample add)
    pub trend_metrics: TrendMetrics,

    // === INCREMENTAL CALCULATION STATE: O(1) updates ===
    // Running sums for variance calculation using O(1) formula:
    // Variance = E[X²] - (E[X])² (Welford's online algorithm variant)
    send_queue_sum: f64,
    send_queue_sum_squares: f64,
    recv_queue_sum: f64,
    recv_queue_sum_squares: f64,

    // Cached velocity for acceleration calculation
    prev_send_velocity: Option<f64>,
    prev_recv_velocity: Option<f64>,
    prev_velocity_time: Option<Instant>,

    // === HEALTH METRIC STATE ===
    prev_cwnd: Option<u32>,        // For congestion recovery detection
    was_congested: bool,           // For recovery detection tracking
}

impl ConnectionHistory {
    /// Create new connection history with incremental state initialized
    #[must_use]
    pub fn new(remote_ip: String, remote_port: u16) -> Self {
        let now = Instant::now();
        Self {
            remote_ip,
            remote_port,
            samples: VecDeque::with_capacity(MAX_HISTORY_SIZE),
            first_seen: now,
            last_updated: now,
            current_status: "UNKNOWN".to_string(),
            status_change_count: 0,
            last_status_change: now,
            trend_metrics: TrendMetrics::default(),
            send_queue_sum: 0.0,
            send_queue_sum_squares: 0.0,
            recv_queue_sum: 0.0,
            recv_queue_sum_squares: 0.0,
            prev_send_velocity: None,
            prev_recv_velocity: None,
            prev_velocity_time: None,
            prev_cwnd: None,
            was_congested: false,
        }
    }

    /// Add new sample and update trend metrics using O(1) incremental approach
    ///
    /// === PERFORMANCE OPTIMIZATION: INCREMENTAL CALCULATION ===
    /// NAIVE approach (O(n) - slow):
    /// - Add sample, loop through all samples to calculate metrics
    /// - With 10 samples, that's 10 operations per add
    ///
    /// OPTIMIZED approach (O(1) - fast):
    /// - Maintain running totals (sum, sum_of_squares)
    /// - Add: add new value to totals
    /// - Remove: subtract old value from totals
    /// - Calculate average/variance from totals (no loop!)
    ///
    /// IMPACT: With 100 connections sampled each second, this saves significant CPU.
    ///
    /// === PARAMETERS ===
    /// &mut self: Mutable borrow (we modify internal state)
    /// Only ONE mutable borrow allowed at a time (Rust's safety guarantee)
    pub fn add_sample(&mut self, sample: TcpHealthSample) {
        self.last_updated = Instant::now();

        let send = sample.send_queue_bytes as f64;
        let recv = sample.recv_queue_bytes as f64;

        // === CIRCULAR BUFFER LOGIC ===
        // Remove oldest sample's contribution if at capacity
        // Keeps memory usage constant (always max 10 samples)
        if self.samples.len() >= MAX_HISTORY_SIZE {
            let oldest = self.samples.pop_front().unwrap();
            // unwrap() is safe: we just checked len() >= MAX_HISTORY_SIZE

            let old_send = oldest.send_queue_bytes as f64;
            let old_recv = oldest.recv_queue_bytes as f64;

            // === INCREMENTAL UPDATE: SUBTRACT OLD VALUES ===
            // Instead of recalculating from scratch (loop through all samples),
            // just subtract what we're removing
            self.send_queue_sum -= old_send;
            self.send_queue_sum_squares -= old_send * old_send;
            self.recv_queue_sum -= old_recv;
            self.recv_queue_sum_squares -= old_recv * old_recv;
        }

        // === INCREMENTAL UPDATE: ADD NEW VALUES ===
        self.send_queue_sum += send;
        self.send_queue_sum_squares += send * send;
        self.recv_queue_sum += recv;
        self.recv_queue_sum_squares += recv * recv;

        self.samples.push_back(sample);

        // Update queue-based trend metrics
        self.update_trend_metrics_incremental();

        // Calculate TCP health metrics from samples
        self.calculate_health_metrics();
    }

    /// Update queue-based trend metrics using O(1) incremental calculations
    ///
    /// === WHAT THIS DOES ===
    /// Calculate all trend metrics using pre-calculated running sums
    /// (no loop needed for most metrics).
    ///
    /// === WHY O(1)? ===
    /// - Average: sum / count (constant time)
    /// - Variance: uses sum and sum_of_squares (constant time)
    /// - Velocity: first and last sample only (constant time)
    /// - Acceleration: cached previous velocity (constant time)
    fn update_trend_metrics_incremental(&mut self) {
        let sample_count = self.samples.len();

        if sample_count == 0 {
            self.trend_metrics = TrendMetrics::default();
            return;
        }

        let mut metrics = TrendMetrics {
            sample_count,
            ..Default::default()
        };

        // ========================================================================
        // VARIANCE CALCULATION: O(1) USING MATHEMATICAL FORMULA
        // ========================================================================
        //
        // === WHAT IS VARIANCE? ===
        // Measures how spread out the data is:
        // - Low: consistent queue size
        // - High: queue jumps around (volatile)
        //
        // === STANDARD FORMULA (O(n) - requires loop): ===
        // 1. Calculate mean
        // 2. For each value: (value - mean)²
        // 3. Average all squared differences
        //
        // === OPTIMIZED FORMULA (O(1) - no loop): ===
        // Variance = E[X²] - (E[X])²
        // Where: E[X] = mean, E[X²] = mean of squares
        //
        // EXAMPLE:
        // Data: [100, 200, 300]
        // Standard: (100-200)² + (200-200)² + (300-200)² = 20000
        //           Variance = 20000/3 ≈ 6666.67
        // Optimized: Mean=200, Mean_of_squares=46666.67
        //            Variance = 46666.67 - 200² = 6666.67 ✓ Same result!
        //
        // === SQUARE ROOT ===
        // Variance is in squared units (bytes²). Take sqrt() for standard deviation
        // in original units (bytes). Example: std_dev = 100 bytes means typical deviation.
        //
        // === .max(0.0) ===
        // Floating-point rounding may produce tiny negative numbers (impossible).
        // Clamp to zero.
        let mean_send = self.send_queue_sum / sample_count as f64;
        let mean_of_squares_send = self.send_queue_sum_squares / sample_count as f64;
        metrics.send_queue_variance = mean_send
            .mul_add(-mean_send, mean_of_squares_send)
            .max(0.0)
            .sqrt();

        let mean_recv = self.recv_queue_sum / sample_count as f64;
        let mean_of_squares_recv = self.recv_queue_sum_squares / sample_count as f64;
        metrics.recv_queue_variance = mean_recv
            .mul_add(-mean_recv, mean_of_squares_recv)
            .max(0.0)
            .sqrt();

        // === MOVING AVERAGES ===
        // Long MA: all samples (provides smooth baseline)
        metrics.send_queue_ma_long = mean_send;

        // Short MA: last 3 samples (responds to recent changes)
        if sample_count >= MA_SHORT_WINDOW {
            let sum: f64 = self
                .samples
                .iter()
                .rev()
                .take(MA_SHORT_WINDOW)
                .map(|s| s.send_queue_bytes as f64)
                .sum();
            metrics.send_queue_ma_short = sum / MA_SHORT_WINDOW as f64;
        } else {
            metrics.send_queue_ma_short = mean_send;
        }

        // === VELOCITY: O(1) USING FIRST AND LAST SAMPLE ONLY ===
        // Avoids loop by comparing oldest and newest samples
        if sample_count >= 2 {
            let oldest = self.samples.front().unwrap();
            let newest = self.samples.back().unwrap();
            let time_diff = newest
                .timestamp
                .duration_since(oldest.timestamp)
                .as_secs_f64()
                .max(0.001);

            let send_velocity =
                (newest.send_queue_bytes as f64 - oldest.send_queue_bytes as f64) / time_diff;
            let recv_velocity =
                (newest.recv_queue_bytes as f64 - oldest.recv_queue_bytes as f64) / time_diff;

            metrics.send_queue_velocity = send_velocity;
            metrics.recv_queue_velocity = recv_velocity;

            // === ACCELERATION: O(1) USING CACHED PREVIOUS VELOCITY ===
            // Compares velocity changes without looping
            if let (Some(prev_send_vel), Some(prev_time)) =
                (self.prev_send_velocity, self.prev_velocity_time)
            {
                let vel_time_diff = newest
                    .timestamp
                    .duration_since(prev_time)
                    .as_secs_f64()
                    .max(0.001);
                metrics.send_queue_acceleration = (send_velocity - prev_send_vel) / vel_time_diff;

                if let Some(prev_recv_vel) = self.prev_recv_velocity {
                    metrics.recv_queue_acceleration =
                        (recv_velocity - prev_recv_vel) / vel_time_diff;
                }
            }

            // Cache current velocity for next iteration
            self.prev_send_velocity = Some(send_velocity);
            self.prev_recv_velocity = Some(recv_velocity);
            self.prev_velocity_time = Some(newest.timestamp);
        }

        // === GROWTH/SHRINK DETECTION ===
        // Check if recent trend is growing or shrinking
        if sample_count >= 3 {
            let idx = sample_count - 1;
            let recent_newest = self.samples[idx].send_queue_bytes;
            let recent_oldest = self.samples[idx - 2].send_queue_bytes;
            let trend = (recent_newest as i32 - recent_oldest as i32) as f64 / 2.0;

            metrics.queue_growing = trend > 50.0;
            metrics.queue_shrinking = trend < -50.0;
        }

        // === VOLATILITY ===
        // High variance relative to mean = unstable conditions
        let mean_queue = metrics.send_queue_ma_long;
        let cv = if mean_queue > 0.0 {
            metrics.send_queue_variance / mean_queue
        } else {
            0.0
        };
        metrics.high_volatility = cv > 0.5;

        // === PERSISTENT HIGH QUEUE ===
        // Count consecutive recent samples with queue >= 4KB
        let high_threshold = 4096u32;
        metrics.send_queue_high_count = self
            .samples
            .iter()
            .rev()
            .take_while(|s| s.send_queue_bytes >= high_threshold)
            .count() as u32;
        metrics.send_queue_persistent = metrics.send_queue_high_count >= 3;

        self.trend_metrics = metrics;
    }

    /// Calculate TCP health metrics from samples
    ///
    /// === WHAT THIS DOES ===
    /// Computes all TCP health metrics (stale, half-open, loss, RTT, bottleneck, congestion)
    /// from the VecDeque samples using O(1) operations.
    ///
    /// === OPTIMIZATION ===
    /// Uses sliding window (latest 1-2 samples) instead of maintaining separate state.
    /// All metrics are O(1) constant time.
    fn calculate_health_metrics(&mut self) {
        let sample_count = self.samples.len();

        if sample_count == 0 {
            return;
        }

        // Copy latest sample (TcpHealthSample implements Copy - efficient)
        let current = *self.samples.back().unwrap();

        // Only calculate health metrics for ESTABLISHED connections
        if !current.is_established() {
            return;
        }

        // === STALE DETECTION: Latest sample only ===
        self.calculate_stale_metrics(&current);

        // === METRICS REQUIRING CONSECUTIVE SAMPLES ===
        if sample_count >= 2 {
            let prev = self.samples[sample_count - 2];

            self.calculate_half_open_metrics(&prev, &current);
            self.calculate_loss_metrics(&prev, &current);
            self.calculate_bottleneck_metrics(&prev, &current);
            self.calculate_congestion_metrics(&prev, &current);
        }

        // === RTT METRICS: Latest sample only ===
        self.calculate_rtt_metrics(&current);
    }

    /// Calculate stale connection detection metrics (send-side and recv-side)
    ///
    /// === STRATEGY ===
    /// Two independent checks:
    /// 1. Send-side: Are we frozen? (last_data_sent_ms high)
    /// 2. Recv-side: Is peer frozen? (last_ack_recv_ms high)
    ///
    /// Two thresholds each:
    /// 1. Suspect (1.5s): Early warning, may be normal idle
    /// 2. Confirmed (3s): Almost certainly broken, recommend reconnect
    fn calculate_stale_metrics(&mut self, current: &TcpHealthSample) {
        // === SEND-SIDE: ARE WE FROZEN? ===

        let stale_send_suspect = current.last_data_sent_ms > STALE_SUSPECT_SEND_MS;
        self.trend_metrics.stale_suspect_send = Some(HealthFlag::new(
            stale_send_suspect,
            if stale_send_suspect {
                format!(
                    "No data sent for {}ms (threshold: {}ms) - send-side may be frozen",
                    current.last_data_sent_ms, STALE_SUSPECT_SEND_MS
                )
            } else {
                format!(
                    "Send-side active ({}ms since last data sent)",
                    current.last_data_sent_ms
                )
            },
        ));

        let stale_send_confirmed = current.last_data_sent_ms > STALE_CONFIRMED_SEND_MS;
        self.trend_metrics.stale_confirmed_send = Some(HealthFlag::new(
            stale_send_confirmed,
            if stale_send_confirmed {
                format!(
                    "CRITICAL: No data sent for {}ms (threshold: {}ms) - connection is DEAD",
                    current.last_data_sent_ms, STALE_CONFIRMED_SEND_MS
                )
            } else {
                format!("Send-side OK ({}ms since last data)", current.last_data_sent_ms)
            },
        ));

        // === RECV-SIDE: IS PEER FROZEN? ===

        let stale_recv_suspect = current.last_ack_recv_ms > STALE_SUSPECT_RECV_MS;
        self.trend_metrics.stale_suspect_recv = Some(HealthFlag::new(
            stale_recv_suspect,
            if stale_recv_suspect {
                format!(
                    "No ACK received for {}ms (threshold: {}ms) - peer or return path may be broken",
                    current.last_ack_recv_ms, STALE_SUSPECT_RECV_MS
                )
            } else {
                format!(
                    "Recv-side active ({}ms since last ACK)",
                    current.last_ack_recv_ms
                )
            },
        ));

        let stale_recv_confirmed = current.last_ack_recv_ms > STALE_CONFIRMED_RECV_MS;
        self.trend_metrics.stale_confirmed_recv = Some(HealthFlag::new(
            stale_recv_confirmed,
            if stale_recv_confirmed {
                format!(
                    "CRITICAL: No ACK for {}ms (threshold: {}ms) - peer is DEAD",
                    current.last_ack_recv_ms, STALE_CONFIRMED_RECV_MS
                )
            } else {
                format!("Recv-side OK ({}ms since last ACK)", current.last_ack_recv_ms)
            },
        ));
    }

    /// Calculate half-open connection detection metrics
    ///
    /// === WHAT THIS DETECTS ===
    /// Half-open: Remote peer crashes silently (no RST sent).
    /// We keep sending data, unaware peer is gone.
    ///
    /// === DETECTION STRATEGY ===
    /// Suspect: No ACK for >1 second + unacked data exists
    /// Confirmed: Suspect + retransmissions or probes occurring
    fn calculate_half_open_metrics(&mut self, prev: &TcpHealthSample, current: &TcpHealthSample) {
        let delta_bytes_acked = current.bytes_acked.saturating_sub(prev.bytes_acked);
        let delta_retrans = current.total_retrans.saturating_sub(prev.total_retrans);
        let delta_probes = current.probes.saturating_sub(prev.probes);

        // === SUSPECT: FAST DETECTION ===
        let no_ack_for_long = current.last_ack_recv_ms > HALF_OPEN_NO_ACK_MS;
        let has_unacked_data = current.unacked > 0;
        let half_open_suspect = no_ack_for_long && has_unacked_data;

        self.trend_metrics.half_open_suspect = Some(HealthFlag::new(
            half_open_suspect,
            if half_open_suspect {
                format!(
                    "Half-open suspected: No ACK for {}ms, {} bytes unacked",
                    current.last_ack_recv_ms, current.unacked
                )
            } else {
                format!(
                    "Connection responsive (last ACK: {}ms ago)",
                    current.last_ack_recv_ms
                )
            },
        ));

        // === CONFIRMED: STRONG DETECTION ===
        let has_retrans_or_probes = delta_retrans > 0 || delta_probes > 0;
        let half_open_confirmed = half_open_suspect && has_retrans_or_probes;

        self.trend_metrics.half_open_confirmed = Some(HealthFlag::new(
            half_open_confirmed,
            if half_open_confirmed {
                format!(
                    "Half-open CONFIRMED: No ACK + {} retrans/probes in window",
                    delta_retrans + delta_probes as u32
                )
            } else if half_open_suspect {
                "Half-open suspected but not confirmed yet".to_string()
            } else {
                "Connection not half-open".to_string()
            },
        ));
    }

    /// Calculate packet loss detection metrics
    ///
    /// === FOR SMALL MESSAGE DELIVERY ===
    /// Your use case: ANY retransmission is critical (latency sensitive).
    /// Report both absolute loss (ANY retransmission) and loss rate (percentage).
    fn calculate_loss_metrics(&mut self, prev: &TcpHealthSample, current: &TcpHealthSample) {
        let delta_retrans = current.total_retrans.saturating_sub(prev.total_retrans);

        // === ABSOLUTE LOSS: ANY RETRANSMISSION ===
        self.trend_metrics.loss_detected = Some(HealthFlag::new(
            delta_retrans > 0,
            if delta_retrans > 0 {
                format!(
                    "CRITICAL: {delta_retrans} packet retransmission(s) detected - adds RTT delay"
                )
            } else {
                "No packet loss detected".to_string()
            },
        ));

        // === LOSS RATE: For bulk transfer monitoring (future use) ===
        // Only available with kernel 5.5+ (RHEL 9) byte-level counters
        if current.bytes_sent > 0 && prev.bytes_sent > 0 {
            let delta_bytes_sent = current.bytes_sent.saturating_sub(prev.bytes_sent);
            let delta_bytes_retrans = current.bytes_retrans.saturating_sub(prev.bytes_retrans);

            if delta_bytes_sent > 0 {
                let loss_rate = delta_bytes_retrans as f64 / delta_bytes_sent as f64;
                let loss_rate_pct = loss_rate * 100.0;
                let exceeds_threshold = loss_rate > LOSS_CRITICAL_RATE_THRESHOLD;

                self.trend_metrics.loss_rate_pct = Some(HealthMetric::new(
                    loss_rate_pct,
                    format!(
                        "Loss rate {:.2}% (threshold: {:.1}%)",
                        loss_rate_pct,
                        LOSS_CRITICAL_RATE_THRESHOLD * 100.0
                    ),
                ));
            }
        } else {
            self.trend_metrics.loss_rate_pct = None;
        }
    }

    /// Calculate RTT drift, jitter, and RTO inflation metrics
    ///
    /// === RTT DRIFT: CONGESTION INDICATOR ===
    /// Ratio of current RTT to minimum RTT baseline.
    /// High ratio = RTT inflated by queuing, routing, or link degradation.
    /// Requires kernel 4.6+
    ///
    /// === JITTER: STABILITY INDICATOR ===
    /// RTT variance as percentage of average RTT.
    /// High jitter = unpredictable latency (routing flap, interference).
    /// Available on all kernels (3.10+)
    ///
    /// === RTO INFLATION: FAILURE INDICATOR ===
    /// Retransmit timeout relative to smoothed RTT.
    /// High RTO = TCP expects packet loss, connection near timeout.
    fn calculate_rtt_metrics(&mut self, current: &TcpHealthSample) {
        // === RTT DRIFT ===
        if current.min_rtt_us > 0 && current.rtt_us > 0 {
            let rtt_ms = current.rtt_us as f64 / 1000.0;
            let min_rtt_ms = current.min_rtt_us as f64 / 1000.0;
            let drift_ratio = current.rtt_us as f64 / current.min_rtt_us as f64;
            let exceeds_threshold = drift_ratio > RTT_DRIFT_THRESHOLD;

            self.trend_metrics.rtt_drift = Some(HealthMetric::new(
                drift_ratio,
                format!(
                    "RTT drift {drift_ratio:.1}x ({rtt_ms:.1}ms current vs {min_rtt_ms:.1}ms baseline)",
                ),
            ));
        } else {
            self.trend_metrics.rtt_drift = None;
        }

        // === JITTER ===
        if current.rtt_us > 0 {
            let rtt_ms = current.rtt_us as f64 / 1000.0;
            let rtt_var_ms = current.rtt_var_us as f64 / 1000.0;
            let jitter_index = current.rtt_var_us as f64 / current.rtt_us as f64;
            let exceeds_threshold = jitter_index > JITTER_INDEX_THRESHOLD;

            self.trend_metrics.jitter_index = Some(HealthMetric::new(
                jitter_index,
                format!(
                    "Jitter {jitter_index:.2} ({rtt_var_ms:.1}ms variance / {rtt_ms:.1}ms RTT)",
                ),
            ));
        } else {
            self.trend_metrics.jitter_index = None;
        }

        // === RTO INFLATION ===
        if current.rtt_us > 0 && current.rto_ms > 0 {
            let rtt_ms = current.rtt_us as f64 / 1000.0;
            let rto_ms = current.rto_ms as f64;
            let rto_ratio = rto_ms / rtt_ms;

            self.trend_metrics.rto_inflation = Some(HealthMetric::new(
                rto_ratio,
                format!(
                    "RTO {rto_ratio:.1}x RTT ({rto_ms:.0}ms vs {rtt_ms:.1}ms)",
                ),
            ));
        } else {
            self.trend_metrics.rto_inflation = None;
        }
    }

    /// Calculate bottleneck identification metrics
    ///
    /// === WHAT THIS IDENTIFIES ===
    /// WHERE is the bottleneck:
    /// - High rwnd_limited: Receiver too slow (receiver bottleneck)
    /// - High sndbuf_limited: Application too slow (sender bottleneck)
    /// - Neither high: Network is bottleneck (congestion, limited BW)
    ///
    /// Requires kernel 4.9+ (RHEL 8+) for busy_time, rwnd_limited, sndbuf_limited
    fn calculate_bottleneck_metrics(&mut self, prev: &TcpHealthSample, current: &TcpHealthSample) {
        if current.busy_time_us > 0 && prev.busy_time_us > 0 {
            let delta_busy = current.busy_time_us.saturating_sub(prev.busy_time_us);

            if delta_busy > 0 {
                // === RECEIVER BOTTLENECK ===
                let delta_rwnd_limited =
                    current.rwnd_limited_us.saturating_sub(prev.rwnd_limited_us);
                let recv_limited_pct = delta_rwnd_limited as f64 / delta_busy as f64;

                self.trend_metrics.recv_limited_pct = Some(HealthMetric::new(
                    recv_limited_pct,
                    format!(
                        "Receiver window-limited: {:.1}% of time",
                        recv_limited_pct * 100.0
                    ),
                ));

                // === SENDER BOTTLENECK ===
                let delta_sndbuf_limited = current
                    .sndbuf_limited_us
                    .saturating_sub(prev.sndbuf_limited_us);
                let sender_limited_pct = delta_sndbuf_limited as f64 / delta_busy as f64;

                self.trend_metrics.sender_limited_pct = Some(HealthMetric::new(
                    sender_limited_pct,
                    format!(
                        "Send buffer-limited: {:.1}% of time",
                        sender_limited_pct * 100.0
                    ),
                ));
            } else {
                self.trend_metrics.recv_limited_pct = None;
                self.trend_metrics.sender_limited_pct = None;
            }
        } else {
            self.trend_metrics.recv_limited_pct = None;
            self.trend_metrics.sender_limited_pct = None;
        }
    }

    /// Calculate congestion state flags (suspected, confirmed, recovering)
    ///
    /// === THREE-LEVEL DETECTION ===
    /// Suspected: Early warning (cwnd decreased OR retransmissions)
    /// Confirmed: High confidence (cwnd < ssthresh AND retransmissions)
    /// Recovering: Problem resolving (cwnd growing AND no new retransmissions)
    fn calculate_congestion_metrics(&mut self, prev: &TcpHealthSample, current: &TcpHealthSample) {
        let delta_retrans = current.total_retrans.saturating_sub(prev.total_retrans);

        // === DETECT CWND DECREASE ===
        let cwnd_decreased = if current.snd_cwnd < prev.snd_cwnd {
            prev.snd_cwnd - current.snd_cwnd >= CWND_DECREASE_THRESHOLD
        } else {
            false
        };
        let cwnd_increased = current.snd_cwnd > prev.snd_cwnd;

        // === SUSPECTED ===
        let congestion_suspected = cwnd_decreased || delta_retrans > 0;
        self.trend_metrics.congestion_suspected = Some(HealthFlag::new(
            congestion_suspected,
            if congestion_suspected {
                "Congestion suspected: watch connection".to_string()
            } else {
                "No congestion signals".to_string()
            },
        ));

        // === CONFIRMED ===
        let in_congestion_avoidance = current.snd_cwnd < current.snd_ssthresh;
        let congestion_confirmed = in_congestion_avoidance && delta_retrans > 0;

        self.trend_metrics.congestion_confirmed = Some(HealthFlag::new(
            congestion_confirmed,
            if congestion_confirmed {
                "Congestion CONFIRMED: packet loss detected".to_string()
            } else {
                "Not congested".to_string()
            },
        ));

        if congestion_confirmed {
            self.was_congested = true;
        } else {
            self.was_congested = false;
        }

        // === RECOVERING ===
        if self.was_congested && cwnd_increased && delta_retrans == 0 {
            self.trend_metrics.congestion_recovering = Some(HealthFlag::new(
                true,
                "Congestion recovering: cwnd growing, no retrans".to_string(),
            ));
        } else if self.was_congested {
            self.trend_metrics.congestion_recovering = Some(HealthFlag::new(
                false,
                "Still congested".to_string(),
            ));
        } else {
            self.trend_metrics.congestion_recovering = None;
        }

        self.prev_cwnd = Some(current.snd_cwnd);
    }

    /// Check if connection should transition status
    /// Returns new status and whether transition occurred
    pub fn evaluate_status_transition(&mut self, new_status: &str) -> (String, bool) {
        let old_status = self.current_status.clone();

        if new_status == old_status {
            (old_status, false)
        } else {
            self.current_status = new_status.to_string();
            self.status_change_count += 1;
            self.last_status_change = Instant::now();
            (new_status.to_string(), true)
        }
    }

    /// Check for status flapping (>3 changes in 30 seconds)
    #[must_use]
    pub fn is_flapping(&self) -> bool {
        let recent_changes_window = Duration::from_secs(30);
        let changes_in_window = if self.last_status_change.elapsed() < recent_changes_window {
            self.status_change_count
        } else {
            0
        };

        changes_in_window > 3
    }

    /// Get time since last sample
    #[must_use]
    pub fn time_since_last_update(&self) -> Duration {
        self.last_updated.elapsed()
    }

    /// Check if connection data is stale (no updates for 5 minutes)
    #[must_use]
    pub fn is_stale_connection(&self) -> bool {
        self.time_since_last_update() > Duration::from_secs(300)
    }
}

/// Manager for all connection histories
#[derive(Debug)]
pub struct HistoryManager {
    /// Map from (local_ip, local_port, remote_ip, remote_port) 4-tuple to ConnectionHistory
    /// 4-tuple allows tracking same remote on different local sockets separately
    connections: HashMap<(String, u16, String, u16), ConnectionHistory>,

    last_cleanup: Instant,
}

impl HistoryManager {
    /// Create new history manager
    #[must_use]
    pub fn new() -> Self {
        Self {
            connections: HashMap::new(),
            last_cleanup: Instant::now(),
        }
    }

    /// Add sample with only queue sizes (legacy method)
    ///
    /// === WHEN TO USE ===
    /// When you only have queue data, not full TCP_INFO metrics.
    /// For production, use add_sample_from_netlink() which has full data.
    pub fn add_sample_with_local(
        &mut self,
        local_ip: &str,
        local_port: u16,
        remote_ip: &str,
        remote_port: u16,
        send_queue: u32,
        recv_queue: u32,
    ) {
        let key = (
            local_ip.to_string(),
            local_port,
            remote_ip.to_string(),
            remote_port,
        );
        let history = self
            .connections
            .entry(key)
            .or_insert_with(|| ConnectionHistory::new(remote_ip.to_string(), remote_port));
        let sample = TcpHealthSample::with_queues(send_queue, recv_queue);
        history.add_sample(sample);
    }

    /// Add sample with full TCP health data from netlink (RECOMMENDED)
    ///
    /// === WHAT THIS DOES ===
    /// Creates fully-populated TcpHealthSample with all TCP metrics from netlink query.
    /// Enables comprehensive health analysis (stale, half-open, loss, bottleneck, etc.).
    ///
    /// === VERSUS add_sample_with_local ===
    /// Old method: Only queue sizes → Health metrics don't work
    /// This method: Queue + RTT + congestion + loss metrics → Full analysis
    ///
    /// Linux only - requires netlink support
    #[cfg(target_os = "linux")]
    pub fn add_sample_from_netlink(
        &mut self,
        local_ip: &str,
        local_port: u16,
        remote_ip: &str,
        remote_port: u16,
        conn_data: &crate::netlink::TcpConnectionData,
    ) {
        let key = (
            local_ip.to_string(),
            local_port,
            remote_ip.to_string(),
            remote_port,
        );
        let history = self
            .connections
            .entry(key)
            .or_insert_with(|| ConnectionHistory::new(remote_ip.to_string(), remote_port));

        // Create fully-populated sample (all TCP metrics)
        let sample = TcpHealthSample::from_tcp_info(
            &conn_data.tcp_info,
            conn_data.send_queue_bytes,
            conn_data.recv_queue_bytes,
            conn_data.tcp_state,
        );

        history.add_sample(sample);
    }

    /// Get connection history using 4-tuple key
    #[must_use]
    pub fn get_with_local(
        &self,
        local_ip: &str,
        local_port: u16,
        remote_ip: &str,
        remote_port: u16,
    ) -> Option<&ConnectionHistory> {
        self.connections.get(&(
            local_ip.to_string(),
            local_port,
            remote_ip.to_string(),
            remote_port,
        ))
    }

    /// Get mutable connection history using 4-tuple key
    pub fn get_mut_with_local(
        &mut self,
        local_ip: &str,
        local_port: u16,
        remote_ip: &str,
        remote_port: u16,
    ) -> Option<&mut ConnectionHistory> {
        self.connections.get_mut(&(
            local_ip.to_string(),
            local_port,
            remote_ip.to_string(),
            remote_port,
        ))
    }

    /// Cleanup stale connection histories (not updated for 5 minutes)
    /// Should be called periodically
    pub fn cleanup_stale_connections(&mut self) {
        // Only cleanup every 60 seconds (avoid frequent HashMap iteration)
        if self.last_cleanup.elapsed() < Duration::from_secs(60) {
            return;
        }

        self.last_cleanup = Instant::now();
        self.connections
            .retain(|_, history| !history.is_stale_connection());
    }

    /// Get number of tracked connections
    #[must_use]
    pub fn connection_count(&self) -> usize {
        self.connections.len()
    }
}

impl Default for HistoryManager {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// UNIT TESTS
// ============================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_tcp_health_sample_creation() {
        let sample = TcpHealthSample::with_queues(1000, 2000);
        assert_eq!(sample.send_queue_bytes, 1000);
        assert_eq!(sample.recv_queue_bytes, 2000);
        assert_eq!(sample.total_queue(), 3000);
        assert_eq!(sample.tcp_state, TCP_ESTABLISHED);
    }

    #[test]
    fn test_connection_history_creation() {
        let history = ConnectionHistory::new("192.168.1.1".to_string(), 5000);
        assert_eq!(history.remote_ip, "192.168.1.1");
        assert_eq!(history.remote_port, 5000);
        assert_eq!(history.samples.len(), 0);
        assert_eq!(history.status_change_count, 0);
    }

    #[test]
    fn test_add_single_sample() {
        let mut history = ConnectionHistory::new("192.168.1.1".to_string(), 5000);
        history.add_sample(TcpHealthSample::with_queues(1000, 500));
        assert_eq!(history.samples.len(), 1);
        assert_eq!(history.samples[0].send_queue_bytes, 1000);
    }

    #[test]
    fn test_add_multiple_samples() {
        let mut history = ConnectionHistory::new("192.168.1.1".to_string(), 5000);
        for i in 0..15 {
            history.add_sample(TcpHealthSample::with_queues(1000 + i * 100, 500));
        }
        assert_eq!(history.samples.len(), 10);
    }

    #[test]
    fn test_velocity_calculation() {
        let mut history = ConnectionHistory::new("192.168.1.1".to_string(), 5000);
        history.add_sample(TcpHealthSample::with_queues(1000, 500));
        thread::sleep(Duration::from_millis(100));
        history.add_sample(TcpHealthSample::with_queues(1500, 500));

        assert!(history.trend_metrics.send_queue_velocity > 0.0);
        assert_eq!(history.trend_metrics.recv_queue_velocity, 0.0);
    }

    #[test]
    fn test_moving_average() {
        let mut history = ConnectionHistory::new("192.168.1.1".to_string(), 5000);
        for _i in 0..5 {
            history.add_sample(TcpHealthSample::with_queues(1000, 0));
        }

        assert!(history.trend_metrics.send_queue_ma_short > 0.0);
        assert_eq!(history.trend_metrics.send_queue_ma_short, 1000.0);
    }

    #[test]
    fn test_queue_growth_detection() {
        let mut history = ConnectionHistory::new("192.168.1.1".to_string(), 5000);
        history.add_sample(TcpHealthSample::with_queues(100, 0));
        thread::sleep(Duration::from_millis(10));
        history.add_sample(TcpHealthSample::with_queues(200, 0));
        thread::sleep(Duration::from_millis(10));
        history.add_sample(TcpHealthSample::with_queues(350, 0));

        assert!(history.trend_metrics.queue_growing);
        assert!(!history.trend_metrics.queue_shrinking);
    }

    #[test]
    fn test_status_transition() {
        let mut history = ConnectionHistory::new("192.168.1.1".to_string(), 5000);
        history.current_status = "HEALTHY".to_string();

        let (new_status, transitioned) = history.evaluate_status_transition("SUSPECT");
        assert_eq!(new_status, "SUSPECT");
        assert!(transitioned);
        assert_eq!(history.status_change_count, 1);

        let (new_status2, transitioned2) = history.evaluate_status_transition("SUSPECT");
        assert_eq!(new_status2, "SUSPECT");
        assert!(!transitioned2);
        assert_eq!(history.status_change_count, 1);
    }

    #[test]
    fn test_history_manager_creation() {
        let manager = HistoryManager::new();
        assert_eq!(manager.connection_count(), 0);
    }

    #[test]
    fn test_history_manager_add_with_local() {
        let mut manager = HistoryManager::new();
        manager.add_sample_with_local("10.0.1.5", 80, "192.168.1.1", 5000, 1000, 500);

        assert_eq!(manager.connection_count(), 1);
        let history = manager.get_with_local("10.0.1.5", 80, "192.168.1.1", 5000);
        assert!(history.is_some());
        assert_eq!(history.unwrap().samples.len(), 1);
    }

    #[test]
    fn test_history_manager_multiple_connections_4tuple() {
        let mut manager = HistoryManager::new();
        manager.add_sample_with_local("10.0.1.5", 80, "192.168.1.1", 5000, 1000, 500);
        manager.add_sample_with_local("10.0.1.6", 443, "192.168.1.2", 6000, 2000, 600);
        manager.add_sample_with_local("10.0.1.5", 80, "192.168.1.1", 5000, 1100, 500);

        assert_eq!(manager.connection_count(), 2);
        assert_eq!(
            manager
                .get_with_local("10.0.1.5", 80, "192.168.1.1", 5000)
                .unwrap()
                .samples
                .len(),
            2
        );
        assert_eq!(
            manager
                .get_with_local("10.0.1.6", 443, "192.168.1.2", 6000)
                .unwrap()
                .samples
                .len(),
            1
        );
    }

    #[test]
    fn test_history_manager_same_remote_different_local() {
        let mut manager = HistoryManager::new();

        manager.add_sample_with_local("10.0.1.5", 80, "8.8.8.8", 443, 1000, 0);
        manager.add_sample_with_local("10.0.1.6", 443, "8.8.8.8", 443, 2000, 0);

        assert_eq!(manager.connection_count(), 2);
        let hist1 = manager
            .get_with_local("10.0.1.5", 80, "8.8.8.8", 443)
            .unwrap();
        let hist2 = manager
            .get_with_local("10.0.1.6", 443, "8.8.8.8", 443)
            .unwrap();

        assert_eq!(hist1.samples[0].send_queue_bytes, 1000);
        assert_eq!(hist2.samples[0].send_queue_bytes, 2000);
    }
}
