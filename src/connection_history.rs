// TCP connection history tracking and health trend analysis.
//
// Maintains a sliding window (last 10 samples) of TCP metrics per connection.
// Detects problems by analyzing:
// - Queue velocity and acceleration (growing/shrinking trends)
// - Staleness (no activity for N milliseconds)
// - Half-open connections (sending but no ACKs)
// - Packet loss and retransmissions
// - RTT drift and jitter (latency instability)
// - Bottleneck identification (sender vs receiver vs network)
// - Congestion state transitions

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

// ============================================================================
// CONSTANTS: CONFIGURATION VALUES
// ============================================================================

/// Maximum number of historical samples to keep per connection (enough for trend analysis)
/// Each `TcpHealthSample` is ~160 bytes; 10 samples = ~1.6KB per connection.
const MAX_HISTORY_SIZE: usize = 10;

/// Time window for moving averages (samples)
///
/// === MOVING AVERAGES EXPLAINED ===
/// Moving average smooths out noise by averaging recent samples.
///
/// SHORT WINDOW (3 samples): Responds quickly to changes, but noisy
/// LONG WINDOW (10 samples): Smooth, but slow to respond
///
/// We use BOTH to detect trends:
/// - If short MA > long MA: queue is growing (recent values higher than average)
/// - If short MA < long MA: queue is shrinking (recent values lower than average)
const MA_SHORT_WINDOW: usize = 3;

// ============================================================================
// TCP CONNECTION HEALTH METRIC THRESHOLDS
// ============================================================================
// These constants define the sensitivity of TCP connection health detection.
// They are tuned for small message delivery (~1KB messages) where latency
// is critical and any packet loss or delay is significant.
//
// === TUNING GUIDANCE ===
// - Lower values = More sensitive (earlier detection, more false positives)
// - Higher values = Less sensitive (slower detection, fewer false positives)
//
// === TARGET DETECTION TIME ===
// Most thresholds are designed for 1-2 second detection of connection issues.
// This enables fast failover and rerouting for latency-sensitive applications.

/// Connection considered stale (suspect) after this many ms without send activity
///
/// === WHAT THIS DETECTS ===
/// Connection has not sent any new data for over 1.5 seconds.
/// This is an EARLY WARNING that the connection may be frozen or broken.
///
/// === WHY 1500 MS? ===
/// - Typical application keepalive: 2-5 seconds
/// - 1.5 seconds is fast enough to detect issues before keepalive timeout
/// - Avoids false positives from normal idle periods
///
/// === USE CASE ===
/// For request/response patterns with expected response time < 1 second,
/// this catches hung connections quickly.
const STALE_SUSPECT_SEND_MS: u32 = 1500;

/// Connection considered stale (suspect) after this many ms without receiving ACK
///
/// === WHAT THIS DETECTS ===
/// Remote peer has not acknowledged any data for over 1.5 seconds.
/// This indicates the receiver may be frozen or the return path is broken.
///
/// === WHY SEPARATE FROM SEND? ===
/// A connection can be stale in one direction but not the other:
/// - Send-side stale: We're not sending (application issue or local freeze)
/// - Recv-side stale: Peer not responding (network issue or remote freeze)
const STALE_SUSPECT_RECV_MS: u32 = 1500;

/// Connection considered stale (confirmed/dead) after this many ms without send activity
///
/// === WHAT THIS DETECTS ===
/// Connection has been completely frozen for 3+ seconds.
/// This is a CONFIRMED DEAD connection that should be closed and reconnected.
///
/// === WHY 3000 MS? ===
/// - 2x the suspect threshold (avoids flapping on borderline cases)
/// - Still faster than typical TCP keepalive (30-60 seconds)
/// - Provides clear separation between "suspect" and "dead" states
const STALE_CONFIRMED_SEND_MS: u32 = 3000;

/// Connection considered stale (confirmed/dead) after this many ms without receiving ACK
const STALE_CONFIRMED_RECV_MS: u32 = 3000;

/// Half-open detection: time since last ACK received (fast threshold)
///
/// === WHAT THIS DETECTS ===
/// We are sending new data segments, but the remote peer has not acknowledged
/// ANYTHING for over 1 second. This indicates a half-open or silently broken connection.
///
/// === HALF-OPEN CONNECTION EXPLAINED ===
/// A half-open connection occurs when:
/// 1. Remote peer crashes or loses connection
/// 2. Remote peer does not send RST (silent failure)
/// 3. Local side keeps sending data into the void
///
/// This is CRITICAL to detect because:
/// - Application thinks connection is alive
/// - Data is being lost silently
/// - No error is reported until timeout (can be 15+ minutes!)
///
/// === WHY 1000 MS? ===
/// - Typical ACK delay: 40-200 ms (delayed ACK timer)
/// - 1 second is 5-25x normal ACK delay
/// - Fast enough to detect issues before retransmit timeout (RTO ~1-3 seconds)
const HALF_OPEN_NO_ACK_MS: u32 = 1000;

/// Critical packet loss ratio for heavy connections (1% = 0.01)
///
/// === WHAT THIS DETECTS ===
/// Packet loss rate exceeds 1% over the sample window.
/// This indicates severe network congestion or link quality issues.
///
/// === WHY 1%? ===
/// - TCP targets ZERO loss (every loss triggers congestion control)
/// - 1% loss can reduce throughput by 50% or more
/// - Industry standard for "acceptable" loss is 0.1% (we use 1% as CRITICAL threshold)
///
/// === NOTE: NOT USED FOR SMALL MESSAGE DELIVERY ===
/// Your use case (1KB messages) uses absolute loss detection (ANY retrans = critical)
/// This threshold is kept for future use with bulk transfer monitoring.
const LOSS_CRITICAL_RATE_THRESHOLD: f64 = 0.01;

/// RTT drift multiplier threshold (`current_rtt` / `min_rtt`)
///
/// === WHAT THIS DETECTS ===
/// Round-trip time has increased to 3x or more of the baseline (minimum RTT).
/// This indicates:
/// - Network congestion (queuing delay)
/// - Routing changes (longer path)
/// - Degraded link quality
///
/// === RTT DRIFT EXPLAINED ===
/// Example:
/// - Baseline RTT (`min_rtt)`: 20 ms (clean path latency)
/// - Current RTT: 60 ms (3x baseline)
/// - Drift ratio: 60 / 20 = 3.0 → THRESHOLD EXCEEDED
///
/// === WHY 3.0? ===
/// - Normal RTT variation: 1.0-1.5x baseline (noise, delayed ACK)
/// - Moderate congestion: 1.5-2.5x baseline (growing queues)
/// - Severe congestion: 3.0x+ baseline (deep queues, packet drops imminent)
///
/// === REQUIRES KERNEL 4.6+ ===
/// Needs `tcpi_min_rtt` field (not available on RHEL 7)
const RTT_DRIFT_THRESHOLD: f64 = 3.0;

/// Jitter index threshold (rttvar / rtt)
///
/// === WHAT THIS DETECTS ===
/// RTT variance is 35% or more of the average RTT.
/// This indicates unstable network conditions:
/// - Fluctuating queuing delay
/// - Route flapping
/// - Wireless link issues
///
/// === JITTER EXPLAINED ===
/// Example:
/// - Average RTT: 50 ms
/// - RTT variance (rttvar): 20 ms (40% of average)
/// - Jitter index: 20 / 50 = 0.40 → THRESHOLD EXCEEDED (> 0.35)
///
/// High jitter causes:
/// - Retransmission timeouts (RTO inflation)
/// - Poor application performance (unpredictable latency)
/// - TCP throughput reduction
///
/// === WHY 0.35? ===
/// - Stable network: 0.05-0.15 (5-15% variation)
/// - Moderate instability: 0.15-0.30
/// - High instability: 0.35+ (action needed)
const JITTER_INDEX_THRESHOLD: f64 = 0.35;

/// Receiver window limitation percentage threshold (`rwnd_limited` / `busy_time`)
///
/// === WHAT THIS DETECTS ===
/// Connection is limited by receiver window (rwnd) for 40%+ of the time.
/// This means the RECEIVER is the bottleneck (cannot process data fast enough).
///
/// === BOTTLENECK EXPLAINED ===
/// TCP has two flow control mechanisms:
/// 1. Receiver window (rwnd): Receiver says "I can accept N bytes"
/// 2. Congestion window (cwnd): Sender estimates "Network can handle N bytes"
///
/// Sending rate = min(rwnd, cwnd)
///
/// If `rwnd_limited_time` / `busy_time` > 40%:
/// - Receiver is the bottleneck (slow application, full buffers)
/// - Sender could send faster, but receiver can't keep up
///
/// === WHY 0.4 (40%)? ===
/// - Occasional receiver limiting: 0-20% (normal)
/// - Moderate limiting: 20-40% (receiver under load)
/// - Severe limiting: 40%+ (receiver is the bottleneck)
///
/// === REQUIRES KERNEL 4.9+ ===
/// Needs `tcpi_rwnd_limited` and `tcpi_busy_time` fields
const RECV_LIMITED_PCT_THRESHOLD: f64 = 0.4;

/// Sender buffer limitation percentage threshold (`sndbuf_limited` / `busy_time`)
///
/// === WHAT THIS DETECTS ===
/// Connection is limited by send buffer (sndbuf) for 40%+ of the time.
/// This means the APPLICATION is the bottleneck (not sending data fast enough).
///
/// === SENDER BUFFER EXPLAINED ===
/// Send buffer (`SO_SNDBUF`) holds data waiting to be sent.
/// If application doesn't write data fast enough:
/// - Send buffer is empty
/// - TCP has nothing to send
/// - Link is underutilized
///
/// If `sndbuf_limited_time` / `busy_time` > 40%:
/// - Application is the bottleneck (slow writes, processing delay)
/// - Network could handle more, but application isn't feeding it
///
/// === WHY 0.4 (40%)? ===
/// Same reasoning as receiver limitation threshold.
///
/// === REQUIRES KERNEL 4.9+ ===
/// Needs `tcpi_sndbuf_limited` and `tcpi_busy_time` fields
const SENDER_LIMITED_PCT_THRESHOLD: f64 = 0.4;

/// RTO ratio threshold (rto / srtt) for excessive timeout
///
/// === WHAT THIS DETECTS ===
/// Retransmission timeout (RTO) is 4x or more of the smoothed RTT.
/// This indicates TCP expects very high probability of packet loss.
///
/// === RTO INFLATION EXPLAINED ===
/// RTO is the timeout before TCP retransmits unacknowledged data.
/// Normal: RTO = srtt + 4 * rttvar (typically 1-3x srtt)
/// Inflated: RTO = 4x+ srtt (TCP has seen high variance or loss)
///
/// High RTO causes:
/// - Long recovery time from packet loss (seconds instead of milliseconds)
/// - Poor application responsiveness
/// - Connection may be near timeout/reset
///
/// === WHY 4.0? ===
/// - Normal RTO: 1.0-2.0x srtt (healthy connection)
/// - Moderate inflation: 2.0-3.5x srtt (some packet loss seen)
/// - Severe inflation: 4.0x+ srtt (frequent loss, unstable connection)
///
/// === WARNING SIGN ===
/// RTO inflation is often a precursor to connection failure.
/// Consider closing and reconnecting before RTO fires.
const RTO_RATIO_THRESHOLD: f64 = 4.0;

/// TCP state value for ESTABLISHED connections
///
/// === TCP STATE VALUES (from Linux kernel) ===
/// 1 = `TCP_ESTABLISHED` (connection is active and data can flow)
/// 2 = `TCP_SYN_SENT` (connection attempt in progress)
/// 3 = `TCP_SYN_RECV` (connection being established)
/// ... (other states are closing/closed)
///
/// Most health metrics only make sense for ESTABLISHED connections.
const TCP_ESTABLISHED: u8 = 1;

/// Minimum congestion window reduction to trigger "cwnd decreased" flag
///
/// === WHAT THIS DETECTS ===
/// Congestion window (cwnd) has shrunk by 2 or more segments.
/// This indicates TCP detected congestion (packet loss or ECN mark).
///
/// === WHY 2 SEGMENTS? ===
/// - cwnd can fluctuate by 1 segment due to normal ACK processing
/// - Reduction by 2+ segments indicates congestion event
/// - Typical congestion response: cwnd reduced by 50%
const CWND_DECREASE_THRESHOLD: u32 = 2;

// ============================================================================
// HEALTH METRIC TYPES
// ============================================================================
// These types enable health metrics to include both calculated values AND
// human-readable explanations in the JSON response.
//
// === DESIGN RATIONALE ===
// Instead of just returning boolean flags or numeric values, we provide context:
// - What was measured
// - What threshold was used
// - Why it matters
//
// This makes the JSON output self-documenting and easier to understand for
// operators troubleshooting connection issues.
/// Health metric with calculated value and human-readable explanation
///
/// === GENERIC TYPE PARAMETER ===
/// <T> means this works with any type: bool, f64, u32, String, etc.
/// This is Rust's way of writing reusable code without sacrificing type safety.
///
/// === DERIVE TRAITS ===
/// - Debug: For printing during development (e.g., println!("{:?}", metric))
/// - Clone: For making copies (health metrics are small, copying is cheap)
/// - Serialize/Deserialize: For JSON conversion (serde handles this automatically)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthMetric<T> {
    /// The calculated metric value
    pub value: T,

    /// Human-readable explanation of what this value means
    ///
    /// SHOULD INCLUDE:
    /// - What was measured (e.g., "RTT drift ratio")
    /// - Current value (e.g., "2.3x baseline")
    /// - Threshold if applicable (e.g., "threshold: 3.0x")
    /// - Context (e.g., "46ms current vs 20ms baseline")
    pub explanation: String,
}

impl<T> HealthMetric<T> {
    /// Create new health metric with value and explanation
    pub const fn new(value: T, explanation: String) -> Self {
        Self { value, explanation }
    }
}

/// Boolean health flag (true = issue detected, false = normal)
///
/// === TYPE ALIAS ===
/// This is just a shorthand for `HealthMetric`<bool>
/// Makes the code more readable and self-documenting.
pub type HealthFlag = HealthMetric<bool>;

/// Numeric health value (for ratios, percentages, rates, etc.)
///
/// === TYPE ALIAS ===
/// Shorthand for `HealthMetric`<f64>
/// Used for continuous metrics like RTT drift, jitter index, loss rate.
pub type HealthValue = HealthMetric<f64>;

/// Optional health metric (None if cannot calculate due to missing data)
///
/// === TYPE ALIAS ===
/// Shorthand for Option<`HealthMetric`<T>>
///
/// === WHY OPTIONAL? ===
/// Some metrics require kernel features not available on all systems:
/// - RTT drift requires `min_rtt` (kernel 4.6+)
/// - Bottleneck detection requires `busy_time` (kernel 4.9+)
/// - Loss rate requires `bytes_sent` (kernel 5.5+)
///
/// If the required data is unavailable, the metric is None (omitted from JSON).
pub type OptionalHealthMetric<T> = Option<HealthMetric<T>>;

/// Queue sample: snapshot of queue sizes at specific time
///
/// === WHAT THIS STORES ===
/// A single measurement of TCP queue sizes at a specific moment in time.
/// By collecting multiple samples over time, we can detect trends.
///
/// === DERIVE TRAITS ===
/// - Debug: Print for debugging
/// - Clone: Make copies of the sample (common operation in statistics)
/// - Copy: Bitwise copy (`QueueSample` is small enough to copy cheaply)
///
/// === COPY VS CLONE ===
/// Copy trait means:
/// - Bitwise copy is safe (no pointers to heap data)
/// - Assignment creates copy automatically (no need for .`clone()`)
/// - Very efficient for small types like this (~24 bytes)
///
/// Compare to `ConnectionInfo` which has String fields (heap data):
/// - Can't be Copy (would duplicate heap data)
/// - Can only be Clone (explicit .`clone()` needed)
///
/// === INSTANT TYPE ===
/// Instant is a monotonic timestamp (doesn't go backwards, ignores clock changes)
/// Perfect for measuring time differences and elapsed time.
/// Note: Instant is NOT serializable (can't convert to JSON)
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
            timestamp: Instant::now(), // Capture current time
            send_queue_bytes,          // Shorthand for: send_queue_bytes: send_queue_bytes
            recv_queue_bytes,          // Shorthand for: recv_queue_bytes: recv_queue_bytes
        }
    }

    /// Get total queue size (both directions)
    ///
    /// === METHOD SYNTAX ===
    /// &self means "borrow self immutably" (read-only access)
    /// - We don't modify the sample, just read it
    /// - Caller retains ownership
    /// - Multiple callers can borrow simultaneously (Rust allows multiple immutable borrows)
    ///
    /// === TYPE CASTING ===
    /// We cast u32 to u64 before adding because:
    /// - u32 + u32 could overflow (max u32 = 4,294,967,295)
    /// - Two full queues: 4GB + 4GB = 8GB, won't fit in u32
    /// - u64 can hold this (max = 18 quintillion)
    ///
    /// 'as u64' performs a safe widening cast (no data loss)
    #[must_use]
    pub const fn total_queue(&self) -> u64 {
        (self.send_queue_bytes as u64) + (self.recv_queue_bytes as u64)
    }
}

// ============================================================================
// TCP HEALTH SAMPLE: COMPREHENSIVE TCP_INFO DATA
// ============================================================================

/// Comprehensive TCP connection health sample
///
/// === PURPOSE ===
/// This structure stores all `TCP_INFO` fields needed for health metrics calculation.
/// It replaces `QueueSample` to enable advanced connection health detection:
/// - Stale/dead connection detection
/// - Half-open connection detection
/// - Packet loss and retransmission tracking
/// - RTT drift and jitter analysis
/// - Bottleneck identification (sender vs receiver vs network)
/// - Congestion state tracking
///
/// === MEMORY FOOTPRINT ===
/// - Structure size: ~160 bytes per sample
/// - 10 samples (`MAX_HISTORY_SIZE)`: ~1.6 KB per connection
/// - 100 connections: ~160 KB total (very reasonable)
/// - 1,000 connections: ~1.6 MB total (still acceptable)
///
/// Compare to full `TcpInfo` storage (~250 bytes): This is optimized to store
/// only fields needed for health calculations (36% smaller).
///
/// === VERSION COMPATIBILITY ===
/// Fields use 0 instead of Option<T> for unavailable data:
/// - Kernel 3.10+ (RHEL 7+): All basic fields available
/// - Kernel 4.6+ (RHEL 8+): Extended fields (`min_rtt`, `delivery_rate`) available
/// - Kernel 4.9+ (RHEL 8+): Bottleneck fields (`busy_time`, `rwnd_limited`) available
/// - Kernel 5.5+ (RHEL 9): Byte counters (`bytes_sent`, `bytes_retrans`) available
///
/// If a field is unavailable, it will be 0, and dependent metrics will be None.
///
/// === DERIVE TRAITS ===
/// - Debug: For printing during development
/// - Clone: For making copies (needed for `VecDeque` operations)
/// - Copy: Enables efficient bitwise copying (all fields are primitive types)
///
/// === WHY COPY TRAIT? ===
/// All fields are primitive types (no heap allocations), so Copy is safe:
/// - u8, u16, u32, u64: All are Copy
/// - Instant: Is Copy (just a timestamp)
/// - Assignment creates copy automatically (no .`clone()` needed)
/// - Very efficient for operations like: let prev = samples[i];
#[derive(Debug, Clone, Copy)]
pub struct TcpHealthSample {
    // === TIMESTAMP (16 bytes) ===
    /// When this sample was captured
    ///
    /// Monotonic timestamp (doesn't go backwards, ignores system clock changes).
    /// Used to calculate time deltas between samples for velocity/acceleration.
    pub timestamp: Instant,

    // === QUEUE SIZES (8 bytes) ===
    /// Bytes waiting in send queue (data waiting to be sent)
    ///
    /// High send queue indicates:
    /// - Application writing faster than network can send
    /// - Network congestion (slow sending)
    /// - Receiver window limiting (receiver can't keep up)
    pub send_queue_bytes: u32,

    /// Bytes waiting in receive queue (data waiting to be read by application)
    ///
    /// High receive queue indicates:
    /// - Application reading slower than data arriving
    /// - Application is the bottleneck
    pub recv_queue_bytes: u32,

    // === TCP STATE AND TIMING (16 bytes) ===
    /// TCP connection state (1 = ESTABLISHED, 2 = `SYN_SENT`, etc.)
    ///
    /// From Linux kernel `tcp_states.h`:
    /// - 1 = `TCP_ESTABLISHED`: Active connection
    /// - Other values: Connection in transition or closing
    ///
    /// Most health metrics only apply to ESTABLISHED connections.
    /// Available: kernel 3.10+ (RHEL 7+)
    pub tcp_state: u8,

    // Padding: 3 bytes for alignment (compiler adds automatically)
    /// Milliseconds since last data sent (`tcpi_last_data_sent`)
    ///
    /// Used for stale connection detection (send-side).
    /// If this value is high (>1500ms) and no data being sent, connection may be frozen.
    /// Available: kernel 3.10+ (RHEL 7+)
    pub last_data_sent_ms: u32,

    /// Milliseconds since last ACK received (`tcpi_last_ack_recv`)
    ///
    /// Used for:
    /// - Stale connection detection (receive-side)
    /// - Half-open connection detection
    ///   If high (>1000ms) while sending data, peer may be dead.
    ///   Available: kernel 3.10+ (RHEL 7+)
    pub last_ack_recv_ms: u32,

    /// Milliseconds since last data received (`tcpi_last_data_recv`)
    ///
    /// Used for stale connection detection (receive-side).
    /// Available: kernel 3.10+ (RHEL 7+)
    pub last_data_recv_ms: u32,

    // === RTT METRICS (12 bytes) ===
    /// Smoothed round-trip time in microseconds (`tcpi_rtt`)
    ///
    /// Average RTT over recent samples.
    /// Used for:
    /// - RTT drift detection (comparing to `min_rtt` baseline)
    /// - Jitter calculation (rttvar / rtt)
    /// - Latency monitoring
    ///   Available: kernel 3.10+ (RHEL 7+)
    pub rtt_us: u32,

    /// RTT variance in microseconds (`tcpi_rttvar`)
    ///
    /// Measures RTT stability. High variance = unstable latency (jitter).
    /// Used for jitter index calculation: rttvar / rtt
    /// Available: kernel 3.10+ (RHEL 7+)
    pub rtt_var_us: u32,

    /// Minimum RTT observed in microseconds (`tcpi_min_rtt`)
    ///
    /// Baseline RTT (clean path latency, no congestion).
    /// Used for RTT drift calculation: `current_rtt` / `min_rtt`
    /// 0 if unavailable (kernel < 4.6)
    /// Available: kernel 4.6+ (RHEL 8+)
    pub min_rtt_us: u32,

    // === CONGESTION AND PACKET COUNTS (24 bytes) ===
    /// Congestion window size in segments (`tcpi_snd_cwnd`)
    ///
    /// TCP's estimate of network capacity (how many segments can be in flight).
    /// Used for congestion detection:
    /// - cwnd decreasing = congestion detected
    /// - cwnd < ssthresh = in congestion avoidance mode
    ///   Available: kernel 3.10+ (RHEL 7+)
    pub snd_cwnd: u32,

    /// Slow start threshold in segments (`tcpi_snd_ssthresh`)
    ///
    /// When cwnd < ssthresh, connection is in congestion avoidance.
    /// Used for congestion confirmed detection.
    /// Available: kernel 3.10+ (RHEL 7+)
    pub snd_ssthresh: u32,

    /// Unacknowledged packets in flight (`tcpi_unacked`)
    ///
    /// Data sent but not yet `ACKed` by receiver.
    /// Used for half-open detection (sending data but no ACKs coming back).
    /// Available: kernel 3.10+ (RHEL 7+)
    pub unacked: u32,

    /// Lost packets (`tcpi_lost`)
    ///
    /// Current estimate of lost packets (not yet recovered).
    /// Available: kernel 3.10+ (RHEL 7+)
    pub lost: u32,

    /// Retransmitted packets (`tcpi_retrans`)
    ///
    /// Currently retransmitted segments (not yet `ACKed`).
    /// Available: kernel 3.10+ (RHEL 7+)
    pub retrans: u32,

    /// Total retransmissions since connection start (`tcpi_total_retrans`)
    ///
    /// Cumulative retransmission count.
    /// Delta calculation (current - previous) gives retransmissions in window.
    /// Used for loss detection: ANY increase = packet loss occurred.
    /// Available: kernel 3.10+ (RHEL 7+)
    pub total_retrans: u32,

    // === BYTE COUNTERS (24 bytes) ===
    /// Total bytes sent (`tcpi_bytes_sent`)
    ///
    /// Cumulative bytes transmitted since connection start.
    /// Delta calculation gives bytes sent in sample window.
    /// 0 if unavailable (kernel < 5.5)
    /// Available: kernel 5.5+ (RHEL 9)
    pub bytes_sent: u64,

    /// Total bytes retransmitted (`tcpi_bytes_retrans`)
    ///
    /// Cumulative retransmitted bytes.
    /// Used for loss rate calculation: `bytes_retrans` / `bytes_sent`
    /// 0 if unavailable (kernel < 5.5)
    /// Available: kernel 5.5+ (RHEL 9)
    pub bytes_retrans: u64,

    /// Total bytes acknowledged by receiver (`tcpi_bytes_acked`)
    ///
    /// Cumulative `ACKed` bytes. Delta = 0 indicates no forward progress (stale/half-open).
    /// 0 if unavailable (kernel < 5.5)
    /// Available: kernel 5.5+ (RHEL 9)
    pub bytes_acked: u64,

    // === BOTTLENECK DETECTION (24 bytes) ===
    /// Microseconds connection was "busy" (`tcpi_busy_time`)
    ///
    /// Time with data in flight (unacked data > 0).
    /// Used as denominator for bottleneck percentages.
    /// 0 if unavailable (kernel < 4.9)
    /// Available: kernel 4.9+ (RHEL 8+)
    pub busy_time_us: u64,

    /// Microseconds limited by receiver window (`tcpi_rwnd_limited`)
    ///
    /// Time when sender wanted to send more but receiver window was full.
    /// `recv_limited_pct` = `rwnd_limited` / `busy_time`
    /// High percentage = receiver is bottleneck.
    /// 0 if unavailable (kernel < 4.9)
    /// Available: kernel 4.9+ (RHEL 8+)
    pub rwnd_limited_us: u64,

    /// Microseconds limited by send buffer (`tcpi_sndbuf_limited`)
    ///
    /// Time when TCP wanted to send but send buffer was empty.
    /// `sender_limited_pct` = `sndbuf_limited` / `busy_time`
    /// High percentage = application is bottleneck (not writing fast enough).
    /// 0 if unavailable (kernel < 4.9)
    /// Available: kernel 4.9+ (RHEL 8+)
    pub sndbuf_limited_us: u64,

    // === DELIVERY RATE (16 bytes) ===
    /// Current delivery rate in bytes/second (`tcpi_delivery_rate`)
    ///
    /// Kernel's estimate of achieved throughput.
    /// 0 if unavailable (kernel < 4.6)
    /// Available: kernel 4.6+ (RHEL 8+)
    pub delivery_rate_bps: u64,

    /// Pacing rate in bytes/second (`tcpi_pacing_rate`)
    ///
    /// Rate at which TCP is sending (may be less than `delivery_rate` due to pacing).
    /// 0 if unavailable (kernel < 4.6)
    /// Available: kernel 4.6+ (RHEL 8+)
    pub pacing_rate_bps: u64,

    // === ADDITIONAL TIMING ===
    /// Retransmission timeout in milliseconds (`tcpi_rto`)
    ///
    /// How long TCP waits before retransmitting unacked data.
    /// High RTO = TCP expects packet loss (inflated due to jitter or previous loss).
    /// Used for RTO inflation detection: rto / srtt > 4.0
    /// Available: kernel 3.10+ (RHEL 7+)
    pub rto_ms: u32,

    /// Number of zero-window probes sent (`tcpi_probes`)
    ///
    /// Indicates receiver window was 0 (receiver completely stalled).
    /// High probe count = severe receiver-side bottleneck.
    /// Available: kernel 3.10+ (RHEL 7+)
    pub probes: u8,
}

// Total size: ~160 bytes (with padding for alignment)

impl TcpHealthSample {
    /// Create minimal `TcpHealthSample` with only queue sizes (for testing/simple cases)
    #[must_use]
    pub fn with_queues(send_queue_bytes: u32, recv_queue_bytes: u32) -> Self {
        Self {
            timestamp: Instant::now(),
            send_queue_bytes,
            recv_queue_bytes,
            tcp_state: TCP_ESTABLISHED, // Default to ESTABLISHED
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
    ///
    /// === COMPATIBILITY ===
    /// Maintains compatibility with `QueueSample` API for queue-based metrics.
    #[must_use]
    pub const fn total_queue(&self) -> u64 {
        (self.send_queue_bytes as u64) + (self.recv_queue_bytes as u64)
    }

    /// Check if connection is in ESTABLISHED state
    #[must_use]
    pub const fn is_established(&self) -> bool {
        self.tcp_state == TCP_ESTABLISHED
    }

    /// Get time since sample was taken
    /// Useful for checking if sample is stale.
    #[must_use]
    pub fn age(&self) -> Duration {
        self.timestamp.elapsed()
    }

    /// Create `TcpHealthSample` from `TcpInfo` (netlink) + queue sizes
    ///
    /// Converts raw `TCP_INFO` data from netlink query into `TcpHealthSample`
    /// for storage in `ConnectionHistory`.
    ///
    /// === PARAMETERS ===
    /// - `tcp_info`: Raw `TCP_INFO` from netlink `inet_diag` query
    /// - `send_queue_bytes`: From `InetDiagMsg.idiag_wqueue` (write queue)
    /// - `recv_queue_bytes`: From `InetDiagMsg.idiag_rqueue` (read queue)
    /// - `tcp_state`: From `InetDiagMsg.idiag_state` (TCP state)
    ///
    /// === KERNEL VERSION COMPATIBILITY ===
    /// - Basic fields: Always available (kernel 3.10+, RHEL 7+)
    /// - Extended fields: Use 0 if not available (kernel < 4.6/4.9/5.5)
    ///
    /// This function handles the Option<TcpInfoExtended> by using
    /// .`unwrap_or(0)` or checking if `Some()` before accessing.
    ///
    /// === LINUX ONLY ===
    /// Only available on Linux (requires netlink `tcp_info` module)
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

        // Byte-level counters (kernel 5.5+, only in TcpInfoExtended)
        // Note: These fields might not exist in extended on older kernels
        // These fields were added in later kernel versions
        // If they're 0, it could mean either:
        // 1. No data sent/acked yet, OR
        // 2. Kernel doesn't support these fields
        // We can't distinguish, so we just use the values as-is
        let (bytes_sent, bytes_retrans, bytes_acked) =
            tcp_info.extended.as_ref().map_or((0, 0, 0), |ext| {
                (
                    ext.tcpi_bytes_sent,
                    ext.tcpi_bytes_retrans,
                    ext.tcpi_bytes_acked,
                )
            });

        TcpHealthSample {
            // Timestamp
            timestamp: Instant::now(),

            // Queue sizes (from InetDiagMsg, not tcp_info)
            send_queue_bytes,
            recv_queue_bytes,

            // TCP state (from InetDiagMsg.idiag_state)
            tcp_state,

            // Timing (basic - kernel 3.10+)
            last_data_sent_ms: basic.tcpi_last_data_sent,
            last_ack_recv_ms: basic.tcpi_last_ack_recv,
            last_data_recv_ms: basic.tcpi_last_data_recv,

            // RTT metrics (basic - kernel 3.10+)
            rtt_us: basic.tcpi_rtt,
            rtt_var_us: basic.tcpi_rttvar,
            min_rtt_us, // Extended (kernel 4.6+), 0 if unavailable

            // Congestion and packet counts (basic - kernel 3.10+)
            snd_cwnd: basic.tcpi_snd_cwnd,
            snd_ssthresh: basic.tcpi_snd_ssthresh,
            unacked: basic.tcpi_unacked,
            lost: basic.tcpi_lost,
            retrans: basic.tcpi_retrans,
            total_retrans: basic.tcpi_total_retrans,

            // Byte counters (extended - kernel 5.5+)
            bytes_sent,
            bytes_retrans,
            bytes_acked,

            // Bottleneck detection (extended - kernel 4.9+)
            busy_time_us,
            rwnd_limited_us,
            sndbuf_limited_us,

            // Delivery rate (extended - kernel 4.6+)
            delivery_rate_bps,
            pacing_rate_bps,

            // Additional timing (basic - kernel 3.10+)
            rto_ms: basic.tcpi_rto / 1000, // Convert microseconds to milliseconds
            probes: basic.tcpi_probes,
        }
    }

    /// Create `TcpHealthSample` from `TcpConnectionData` (RECOMMENDED for Netlink path)
    ///
    /// This is a convenience wrapper around `from_tcp_info()` that accepts
    /// `TcpConnectionData` directly, which is the structure returned by
    /// Netlink query functions.
    ///
    /// # Rationale
    ///
    /// This method eliminates the need to manually extract fields from
    /// `TcpConnectionData` when creating health samples. It provides:
    /// 1. Cleaner calling code (one function call instead of unpacking fields)
    /// 2. Single source of truth (`TcpConnectionData` contains all data)
    /// 3. Type safety (can't forget queue sizes or state)
    ///
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

/// Trend metrics derived from historical data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrendMetrics {
    /// Change in send queue (bytes/second) - positive = growing
    pub send_queue_velocity: f64,

    /// Change in receive queue (bytes/second) - positive = growing
    pub recv_queue_velocity: f64,

    /// Acceleration of send queue (bytes/second²) - positive = worsening
    pub send_queue_acceleration: f64,

    /// Acceleration of recv queue (bytes/second²) - positive = worsening
    pub recv_queue_acceleration: f64,

    /// Standard deviation of send queue over window
    pub send_queue_variance: f64,

    /// Standard deviation of recv queue over window
    pub recv_queue_variance: f64,

    /// Moving average of send queue (short window - 3 samples)
    pub send_queue_ma_short: f64,

    /// Moving average of send queue (full window - 10 samples)
    pub send_queue_ma_long: f64,

    /// Is send queue persistently high (>2KB for 3+ consecutive samples)?
    pub send_queue_persistent: bool,

    /// Number of consecutive samples with high send queue
    pub send_queue_high_count: u32,

    /// Indicates queue is growing trend
    pub queue_growing: bool,

    /// Indicates queue is shrinking trend
    pub queue_shrinking: bool,

    /// Indicates high volatility/instability
    pub high_volatility: bool,

    /// Sample count available
    pub sample_count: usize,

    // ========================================================================
    // NEW METRICS: CONNECTION STALENESS (kernel 3.10+)
    // ========================================================================
    /// Connection stale suspect (send-side): no data sent for >1.5 seconds
    ///
    /// EARLY WARNING that connection may be frozen.
    /// Triggers when `last_data_sent_ms` > `STALE_SUSPECT_SEND_MS`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stale_suspect_send: Option<HealthFlag>,

    /// Connection stale suspect (recv-side): no ACK received for >1.5 seconds
    ///
    /// EARLY WARNING that peer may be frozen or return path broken.
    /// Triggers when `last_ack_recv_ms` > `STALE_SUSPECT_RECV_MS`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stale_suspect_recv: Option<HealthFlag>,

    /// Connection stale confirmed (send-side): no data sent for >3 seconds
    ///
    /// CONFIRMED DEAD connection (send-side frozen).
    /// Should close and reconnect.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stale_confirmed_send: Option<HealthFlag>,

    /// Connection stale confirmed (recv-side): no ACK received for >3 seconds
    ///
    /// CONFIRMED DEAD connection (peer not responding).
    /// Should close and reconnect.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stale_confirmed_recv: Option<HealthFlag>,

    // ========================================================================
    // NEW METRICS: HALF-OPEN DETECTION (kernel 3.10+)
    // ========================================================================
    /// Half-open suspect (fast): sending data but no ACK for >1 second
    ///
    /// Detects silently broken connections where:
    /// - We're sending new data (`delta_data_segs_out` > 0)
    /// - No ACKs coming back (`last_ack_recv_ms` > 1000)
    /// - Nothing received (`delta_bytes_recv` == 0)
    ///
    /// This is CRITICAL for ~1KB message use case (data loss into void).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub half_open_suspect: Option<HealthFlag>,

    /// Half-open strong: `half_open_suspect` + retransmissions/probes
    ///
    /// High confidence half-open detection:
    /// - `half_open_suspect` is true
    /// - AND (retransmissions occurring OR zero-window probes sent)
    ///
    /// Very strong indicator connection is broken.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub half_open_confirmed: Option<HealthFlag>,

    // ========================================================================
    // NEW METRICS: PACKET LOSS (kernel 3.10+, enhanced with 5.5+)
    // ========================================================================
    /// ANY packet loss detected in sample window
    ///
    /// CRITICAL for small message delivery (~1KB messages).
    /// ANY retransmission indicates:
    /// - Message delayed (retransmit adds RTT delay)
    /// - Potential connection issues
    /// - User-visible latency increase
    ///
    /// `delta_total_retrans` >= 1 triggers this flag.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub loss_detected: Option<HealthFlag>,

    /// Packet loss RATE (percentage) for throughput monitoring
    ///
    /// `bytes_retrans` / `bytes_sent` ratio.
    /// Useful for bulk transfer monitoring (future use).
    /// Requires kernel 5.5+ (RHEL 9) for `bytes_sent/bytes_retrans` fields.
    ///
    /// Only calculated if `bytes_sent` > 0 (data actually sent in window).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub loss_rate_pct: OptionalHealthMetric<f64>,

    // ========================================================================
    // NEW METRICS: RTT AND JITTER (kernel 3.10+, drift requires 4.6+)
    // ========================================================================
    /// RTT drift ratio (current RTT / minimum RTT baseline)
    ///
    /// Detects RTT inflation due to:
    /// - Network congestion (queuing delay)
    /// - Routing changes (longer path)
    /// - Degraded link quality
    ///
    /// Ratio > 3.0 = severe (RTT is 3x baseline).
    /// Requires kernel 4.6+ for `tcpi_min_rtt`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rtt_drift: OptionalHealthMetric<f64>,

    /// Jitter index (RTT variance / average RTT)
    ///
    /// Measures RTT stability. High jitter (>0.35) indicates:
    /// - Fluctuating network delay
    /// - Route flapping
    /// - Wireless link issues
    ///
    /// Available on all kernels (3.10+).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jitter_index: OptionalHealthMetric<f64>,

    // ========================================================================
    // NEW METRICS: BOTTLENECK DETECTION (kernel 4.9+)
    // ========================================================================
    /// Receiver window limitation percentage (`rwnd_limited` / `busy_time`)
    ///
    /// Percentage of time limited by receiver window.
    /// > 40% = receiver is the bottleneck (can't process data fast enough).
    ///
    /// Requires kernel 4.9+ for `rwnd_limited` and `busy_time` fields.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recv_limited_pct: OptionalHealthMetric<f64>,

    /// Sender buffer limitation percentage (`sndbuf_limited` / `busy_time`)
    ///
    /// Percentage of time limited by send buffer.
    /// > 40% = application is bottleneck (not writing data fast enough).
    ///
    /// Requires kernel 4.9+ for `sndbuf_limited` and `busy_time` fields.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender_limited_pct: OptionalHealthMetric<f64>,

    // ========================================================================
    // NEW METRICS: CONGESTION STATE (kernel 3.10+)
    // ========================================================================
    /// Congestion suspected (early warning)
    ///
    /// Detects congestion signals:
    /// - cwnd decreased by 2+ segments, OR
    /// - Retransmissions occurring (`delta_retrans` > 0)
    ///
    /// Fast detection (1-2 seconds), may have false positives.
    /// Use as EARLY WARNING to watch connection.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub congestion_suspected: Option<HealthFlag>,

    /// Congestion confirmed (high confidence)
    ///
    /// TCP definitively in congestion avoidance:
    /// - cwnd < ssthresh (TCP reduced window due to loss/ECN)
    /// - AND retransmissions in window (`delta_retrans` > 0)
    ///
    /// Industry standard congestion indicator (very reliable).
    /// Take action: connection is experiencing packet loss.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub congestion_confirmed: Option<HealthFlag>,

    /// Congestion recovering (trend tracking)
    ///
    /// Connection recovering from congestion:
    /// - cwnd growing (increasing capacity)
    /// - AND no new retransmissions (`delta_retrans` == 0)
    ///
    /// Indicates problem is resolving. Informational metric.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub congestion_recovering: Option<HealthFlag>,

    // ========================================================================
    // NEW METRICS: RTO INFLATION (kernel 3.10+)
    // ========================================================================
    /// RTO inflation ratio (rto / srtt)
    ///
    /// Retransmission timeout is 4x+ smoothed RTT.
    /// This indicates:
    /// - TCP expects high packet loss probability
    /// - Previous loss or high jitter seen
    /// - Connection near timeout/failure
    ///
    /// Ratio > 4.0 = warning sign (consider reconnecting).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rto_inflation: OptionalHealthMetric<f64>,
}

impl Default for TrendMetrics {
    fn default() -> Self {
        Self {
            // Existing queue-based metrics
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

            // New health metrics (all default to None)
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
    ///
    /// === UPDATED FOR HEALTH METRICS ===
    /// Changed from `VecDeque`<QueueSample> to `VecDeque`<TcpHealthSample>
    /// to support comprehensive TCP connection health detection.
    ///
    /// Memory impact: 1.6 KB per connection (160 bytes × 10 samples)
    pub samples: VecDeque<TcpHealthSample>,

    /// Time when this connection was first seen
    pub first_seen: Instant,

    /// Time of last update
    pub last_updated: Instant,

    /// Current status: HEALTHY, CAUTION, SUSPECT, DEGRADED, STALE
    pub current_status: String,

    /// Count of status changes (flapping detection)
    pub status_change_count: u32,

    /// Time when last status transition occurred
    pub last_status_change: Instant,

    /// Cached trend metrics (updated on each sample add)
    pub trend_metrics: TrendMetrics,

    // ========================================================================
    // INCREMENTAL CALCULATION STATE: O(1) updates for queue-based metrics
    // ========================================================================
    /// Running sum of `send_queue` values (for mean calculation)
    send_queue_sum: f64,
    /// Running sum of squared `send_queue` values (for variance calculation)
    send_queue_sum_squares: f64,
    /// Running sum of `recv_queue` values
    recv_queue_sum: f64,
    /// Running sum of squared `recv_queue` values
    recv_queue_sum_squares: f64,

    /// Previous velocity for acceleration calculation (queue metrics)
    prev_send_velocity: Option<f64>,
    prev_recv_velocity: Option<f64>,
    prev_velocity_time: Option<Instant>,

    // ========================================================================
    // NEW: Cached state for health metric calculations
    // ========================================================================
    /// Previous cwnd value for congestion detection
    ///
    /// Cached to detect cwnd decreases:
    /// - If `current_cwnd` < `prev_cwnd` - `CWND_DECREASE_THRESHOLD`: congestion suspected
    ///
    /// Updated on each sample add.
    prev_cwnd: Option<u32>,

    /// Was connection congested in previous sample?
    ///
    /// Used for congestion recovery detection:
    /// - If `was_congested` && `cwnd_growing` && `no_retrans`: recovering
    ///
    /// This avoids need to search historical samples.
    was_congested: bool,
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
            // Initialize incremental state to zero
            send_queue_sum: 0.0,
            send_queue_sum_squares: 0.0,
            recv_queue_sum: 0.0,
            recv_queue_sum_squares: 0.0,
            prev_send_velocity: None,
            prev_recv_velocity: None,
            prev_velocity_time: None,
            // Initialize health metric state
            prev_cwnd: None,
            was_congested: false,
        }
    }

    /// Add new sample and update trend metrics using O(1) incremental approach
    ///
    /// === PERFORMANCE OPTIMIZATION: INCREMENTAL CALCULATION ===
    /// This is a KEY optimization that makes this code efficient.
    ///
    /// NAIVE APPROACH (O(n) - slow):
    /// - Add new sample to list
    /// - Loop through all samples to calculate sum, average, variance
    /// - With 10 samples, this means 10 operations per add
    ///
    /// OPTIMIZED APPROACH (O(1) - fast):
    /// - Maintain running totals (sum, `sum_of_squares`)
    /// - When adding: add new value to totals
    /// - When removing: subtract old value from totals
    /// - Calculate average/variance from totals (no loop needed!)
    ///
    /// PERFORMANCE IMPACT:
    /// - O(1) means constant time - same speed regardless of history size
    /// - O(n) means linear time - slower with more samples
    /// - With 100 connections sampled every second, this saves significant CPU
    ///
    /// === PARAMETERS ===
    /// &mut self - Mutable borrow of self
    /// - &mut means we can modify self
    /// - Only ONE mutable borrow allowed at a time (Rust's safety rule)
    /// - This prevents data races - impossible to have simultaneous modifications
    ///
    /// === BIG O NOTATION ===
    /// O(1) = constant time (doesn't depend on data size)
    /// O(n) = linear time (proportional to data size)
    /// O(n²) = quadratic time (very slow for large data)
    ///
    /// OPTIMIZED: Instead of recalculating from scratch, update running totals incrementally
    ///
    /// === UPDATED FOR TCP HEALTH METRICS ===
    /// Now accepts `TcpHealthSample` instead of `QueueSample`.
    /// Calculates both queue-based metrics AND TCP health metrics.
    pub fn add_sample(&mut self, sample: TcpHealthSample) {
        // Update last modification timestamp
        self.last_updated = Instant::now();

        // Convert to f64 (floating point) for calculations
        // Why f64? We need decimals for averages and variance
        let send = sample.send_queue_bytes as f64;
        let recv = sample.recv_queue_bytes as f64;

        // === CIRCULAR BUFFER LOGIC ===
        // If at capacity, remove oldest sample's contribution from running totals
        // This keeps memory usage constant (always max 10 samples)
        //
        // VecDeque is a double-ended queue - efficient for:
        // - pop_front(): Remove from beginning (O(1))
        // - push_back(): Add to end (O(1))
        //
        // This makes it perfect for circular buffers
        if self.samples.len() >= MAX_HISTORY_SIZE {
            // Remove oldest sample (FIFO - First In, First Out)
            let oldest = self.samples.pop_front().unwrap();
            // .unwrap() is safe here because we just checked len() >= MAX_HISTORY_SIZE
            // This means we KNOW there's at least one element
            //
            // ALTERNATIVE: Could use .expect("message") for better error message
            // But unwrap() is fine when we're certain it won't panic

            let old_send = oldest.send_queue_bytes as f64;
            let old_recv = oldest.recv_queue_bytes as f64;

            // === INCREMENTAL UPDATE: SUBTRACT OLD VALUES ===
            // This is the KEY to O(1) performance
            // Instead of recalculating sum from scratch (loop through all samples),
            // we just subtract what we're removing
            //
            // Example:
            // Old sum: 100 + 200 + 300 = 600
            // Remove 100: 600 - 100 = 500 (O(1))
            // vs. recalculate: 200 + 300 = 500 (O(n))
            self.send_queue_sum -= old_send;
            self.send_queue_sum_squares -= old_send * old_send; // For variance calculation
            self.recv_queue_sum -= old_recv;
            self.recv_queue_sum_squares -= old_recv * old_recv;
        }

        // === INCREMENTAL UPDATE: ADD NEW VALUES ===
        // Add new sample's contribution to running totals (O(1))
        // Same concept: instead of recalculating, just add the new value
        self.send_queue_sum += send;
        self.send_queue_sum_squares += send * send; // sum of X² (for variance formula)
        self.recv_queue_sum += recv;
        self.recv_queue_sum_squares += recv * recv;

        // Add sample to buffer
        // push_back() adds to end of VecDeque (newest sample)
        // This maintains chronological order: oldest at front, newest at back
        self.samples.push_back(sample);

        // Update queue-based trend metrics using the running totals
        // This is O(1) for most metrics because we use the pre-calculated sums
        // Only a few metrics (like checking last 3 samples) are O(1) small loops
        self.update_trend_metrics_incremental();

        // NEW: Calculate TCP health metrics from samples
        // Uses VecDeque indexing to access latest and consecutive samples
        self.calculate_health_metrics();
    }

    /// OPTIMIZED: O(1) incremental trend update using pre-calculated running sums
    ///
    /// === WHAT THIS DOES ===
    /// Calculate all trend metrics (velocity, acceleration, variance, etc.)
    /// using the running totals we maintain, instead of looping through samples.
    ///
    /// === WHY O(1)? ===
    /// Most calculations use pre-calculated sums:
    /// - Average: sum / count (O(1), no loop)
    /// - Variance: uses sum and `sum_of_squares` (O(1), no loop)
    /// - Velocity: uses first and last sample only (O(1), no loop)
    ///
    /// This replaces the O(n) `update_trend_metrics()` method
    fn update_trend_metrics_incremental(&mut self) {
        let sample_count = self.samples.len();

        // Early return if no samples
        // This avoids division by zero and unnecessary work
        if sample_count == 0 {
            self.trend_metrics = TrendMetrics::default(); // Reset to zeros
            return; // Exit function early
        }

        // === STRUCT UPDATE SYNTAX ===
        // Create TrendMetrics with sample_count set explicitly
        // ..Default::default() fills remaining fields with default values (zeros, false)
        //
        // This is Rust's "struct update syntax" - very convenient for partial initialization
        let mut metrics = TrendMetrics {
            sample_count,
            ..Default::default()
        };

        // ========================================================================
        // VARIANCE CALCULATION: O(1) USING MATHEMATICAL FORMULA
        // ========================================================================
        //
        // === WHAT IS VARIANCE? ===
        // Variance measures how spread out the data is (variability/volatility)
        // - Low variance: data is consistent (e.g., queue always ~100 bytes)
        // - High variance: data is volatile (e.g., queue jumps 0 → 1000 → 0)
        //
        // === STANDARD FORMULA (requires loop - O(n)): ===
        // 1. Calculate mean: μ = (sum of all values) / count
        // 2. For each value: calculate (value - μ)²
        // 3. Sum all squared differences
        // 4. Divide by count
        // This requires TWO passes through data: one for mean, one for squared diffs
        //
        // === OPTIMIZED FORMULA (no loop - O(1)): ===
        // Variance = E[X²] - (E[X])²
        // Where:
        // - E[X] = expected value (mean) = sum / count
        // - E[X²] = expected value of squares = sum_of_squares / count
        //
        // EXAMPLE:
        // Data: [100, 200, 300]
        // Mean = 200
        // Standard formula:
        //   (100-200)² + (200-200)² + (300-200)² = 10000 + 0 + 10000 = 20000
        //   Variance = 20000 / 3 ≈ 6666.67
        //   Std dev = sqrt(6666.67) ≈ 81.65
        //
        // Optimized formula:
        //   Sum = 600, Sum² = 140000
        //   Mean = 600/3 = 200
        //   Mean_of_squares = 140000/3 ≈ 46666.67
        //   Variance = 46666.67 - 200² = 46666.67 - 40000 = 6666.67
        //   Std dev = sqrt(6666.67) ≈ 81.65
        // Same result, but calculated in O(1) using pre-calculated sums!
        //
        // === SQUARE ROOT FOR STANDARD DEVIATION ===
        // Variance is in squared units (bytes²), which is hard to interpret
        // Standard deviation (sqrt of variance) is in original units (bytes)
        // Example: if std dev = 100 bytes, it means typical deviation is 100 bytes
        //
        // === .max(0.0) - WHY? ===
        // Due to floating-point rounding errors, the formula might produce
        // very small negative numbers (like -0.0000001) which are mathematically
        // impossible for variance. .max(0.0) clamps to zero.
        //
        // OPTIMIZATION: Variance in O(1) using Welford's online algorithm variant
        // Variance = E[X²] - (E[X])²
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

        // OPTIMIZATION: Moving averages in O(1) using running sums
        metrics.send_queue_ma_long = mean_send; // Long window = all samples

        // Short MA: calculate from last 3 samples only
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

        // OPTIMIZATION: Velocity in O(1) using first and last sample only
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

            // OPTIMIZATION: Acceleration in O(1) using cached previous velocity
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

        // Growth/shrink detection: O(1) using last 3 samples
        if sample_count >= 3 {
            let idx = sample_count - 1;
            let recent_newest = self.samples[idx].send_queue_bytes;
            let recent_oldest = self.samples[idx - 2].send_queue_bytes;
            let trend = (recent_newest as i32 - recent_oldest as i32) as f64 / 2.0;

            metrics.queue_growing = trend > 50.0;
            metrics.queue_shrinking = trend < -50.0;
        }

        // Volatility: O(1) using coefficient of variation
        let mean_queue = metrics.send_queue_ma_long;
        let cv = if mean_queue > 0.0 {
            metrics.send_queue_variance / mean_queue
        } else {
            0.0
        };
        metrics.high_volatility = cv > 0.5;

        // Persistent high queue: Count backwards from newest (early exit on first low)
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
    /// Calculates all TCP connection health metrics using the `VecDeque` samples.
    /// Uses the approach suggested by user: leverage existing sliding window
    /// instead of maintaining separate previous sample cache.
    ///
    /// === PERFORMANCE ===
    /// - Stale detection: O(1) - just read latest sample
    /// - Half-open detection: O(1) - latest sample + simple check
    /// - Loss detection: O(1) - delta between consecutive samples
    /// - RTT metrics: O(1) - latest sample calculations
    /// - Bottleneck: O(1) - delta between consecutive samples
    /// - Congestion: O(1) - compare consecutive samples + cached state
    ///
    /// Total: O(1) constant time regardless of history size.
    fn calculate_health_metrics(&mut self) {
        let sample_count = self.samples.len();

        // Early return if no samples
        if sample_count == 0 {
            return;
        }

        // COPY latest sample from VecDeque (TcpHealthSample implements Copy)
        // unwrap() is safe because we checked sample_count > 0
        //
        // === WHY COPY? ===
        // Rust borrow checker doesn't allow holding a reference to samples
        // while calling &mut self methods. Since TcpHealthSample is Copy,
        // copying is efficient (just copies stack memory, ~160 bytes).
        let current = *self.samples.back().unwrap();

        // Only calculate health metrics for ESTABLISHED connections
        // Other states (SYN_SENT, CLOSE_WAIT, etc.) don't have meaningful health metrics
        if !current.is_established() {
            return;
        }

        // ====================================================================
        // STALE DETECTION: Latest sample only (O(1))
        // ====================================================================

        self.calculate_stale_metrics(&current);

        // ====================================================================
        // METRICS REQUIRING CONSECUTIVE SAMPLES (need at least 2 samples)
        // ====================================================================

        if sample_count >= 2 {
            // COPY second-newest sample (previous)
            let prev_idx = sample_count - 2;
            let prev = self.samples[prev_idx];

            // Half-open detection (requires deltas)
            self.calculate_half_open_metrics(&prev, &current);

            // Loss detection (requires delta_retrans)
            self.calculate_loss_metrics(&prev, &current);

            // Bottleneck detection (requires delta busy_time, rwnd_limited, etc.)
            self.calculate_bottleneck_metrics(&prev, &current);

            // Congestion detection (requires cwnd comparison)
            self.calculate_congestion_metrics(&prev, &current);
        }

        // ====================================================================
        // RTT METRICS: Latest sample only (O(1))
        // ====================================================================

        self.calculate_rtt_metrics(&current);
    }

    /// Calculate stale connection metrics (send-side and recv-side)
    ///
    /// === STALE DETECTION STRATEGY ===
    /// Two separate checks:
    /// 1. Send-side: `last_data_sent_ms` (are WE frozen?)
    /// 2. Recv-side: `last_ack_recv_ms` (is PEER frozen?)
    ///
    /// This distinguishes between:
    /// - Application freeze (we're not sending)
    /// - Network/peer freeze (peer not responding)
    fn calculate_stale_metrics(&mut self, current: &TcpHealthSample) {
        // === SEND-SIDE STALE DETECTION ===

        // Suspect: no data sent for >1.5 seconds
        let stale_send_suspect = current.last_data_sent_ms > STALE_SUSPECT_SEND_MS;
        if stale_send_suspect {
            self.trend_metrics.stale_suspect_send = Some(HealthFlag::new(
                true,
                format!(
                    "No data sent for {}ms (threshold: {}ms) - send-side may be frozen",
                    current.last_data_sent_ms, STALE_SUSPECT_SEND_MS
                ),
            ));
        } else {
            self.trend_metrics.stale_suspect_send = Some(HealthFlag::new(
                false,
                format!(
                    "Send-side active ({}ms since last data sent, threshold: {}ms)",
                    current.last_data_sent_ms, STALE_SUSPECT_SEND_MS
                ),
            ));
        }

        // Confirmed: no data sent for >3 seconds
        let stale_send_confirmed = current.last_data_sent_ms > STALE_CONFIRMED_SEND_MS;
        if stale_send_confirmed {
            self.trend_metrics.stale_confirmed_send = Some(HealthFlag::new(
                true,
                format!(
                    "CRITICAL: No data sent for {}ms (threshold: {}ms) - connection is DEAD (send-side frozen). Recommend close/reconnect.",
                    current.last_data_sent_ms, STALE_CONFIRMED_SEND_MS
                ),
            ));
        } else {
            self.trend_metrics.stale_confirmed_send = Some(HealthFlag::new(
                false,
                format!(
                    "Send-side OK ({}ms since last data sent, threshold: {}ms)",
                    current.last_data_sent_ms, STALE_CONFIRMED_SEND_MS
                ),
            ));
        }

        // === RECV-SIDE STALE DETECTION ===

        // Suspect: no ACK received for >1.5 seconds
        let stale_recv_suspect = current.last_ack_recv_ms > STALE_SUSPECT_RECV_MS;
        if stale_recv_suspect {
            self.trend_metrics.stale_suspect_recv = Some(HealthFlag::new(
                true,
                format!(
                    "No ACK received for {}ms (threshold: {}ms) - peer or return path may be broken",
                    current.last_ack_recv_ms, STALE_SUSPECT_RECV_MS
                ),
            ));
        } else {
            self.trend_metrics.stale_suspect_recv = Some(HealthFlag::new(
                false,
                format!(
                    "Recv-side active ({}ms since last ACK, threshold: {}ms)",
                    current.last_ack_recv_ms, STALE_SUSPECT_RECV_MS
                ),
            ));
        }

        // Confirmed: no ACK received for >3 seconds
        let stale_recv_confirmed = current.last_ack_recv_ms > STALE_CONFIRMED_RECV_MS;
        if stale_recv_confirmed {
            self.trend_metrics.stale_confirmed_recv = Some(HealthFlag::new(
                true,
                format!(
                    "CRITICAL: No ACK for {}ms (threshold: {}ms) - peer is DEAD or return path broken. Recommend close/reconnect.",
                    current.last_ack_recv_ms, STALE_CONFIRMED_RECV_MS
                ),
            ));
        } else {
            self.trend_metrics.stale_confirmed_recv = Some(HealthFlag::new(
                false,
                format!(
                    "Recv-side OK ({}ms since last ACK, threshold: {}ms)",
                    current.last_ack_recv_ms, STALE_CONFIRMED_RECV_MS
                ),
            ));
        }
    }

    /// Calculate half-open connection detection metrics
    ///
    /// === HALF-OPEN CONNECTION ===
    /// A half-open connection occurs when the peer dies silently (no RST sent).
    /// We keep sending data into the void, unaware the peer is gone.
    ///
    /// === DETECTION STRATEGY ===
    /// Combined approach (user requested):
    /// 1. No ACK received for >1 second (basic detection)
    /// 2. Unacked data exists (we're actually sending)
    /// 3. Retransmissions or probes occurring (strong confirmation)
    fn calculate_half_open_metrics(&mut self, prev: &TcpHealthSample, current: &TcpHealthSample) {
        // Calculate deltas (how much activity in sample window)
        let delta_bytes_acked = current.bytes_acked.saturating_sub(prev.bytes_acked);

        // === HALF-OPEN SUSPECT (FAST DETECTION) ===
        // Criteria:
        // - No ACK for >1 second
        // - Unacked data exists (we're sending but peer not acknowledging)
        // - No forward progress (bytes_acked not increasing, if available)

        let no_ack_for_long = current.last_ack_recv_ms > HALF_OPEN_NO_ACK_MS;
        let has_unacked_data = current.unacked > 0;

        // If bytes_acked available (kernel 5.5+), check for forward progress
        // If not available, we can't use this check (assume possible issue)
        let no_forward_progress = if current.bytes_acked > 0 || prev.bytes_acked > 0 {
            delta_bytes_acked == 0
        } else {
            // bytes_acked not available (kernel < 5.5), can't check this criterion
            false // Don't trigger on unavailable data
        };

        let half_open_suspect = no_ack_for_long && has_unacked_data;

        if half_open_suspect {
            let mut explanation = format!(
                "Half-open suspected: No ACK for {}ms (threshold: {}ms), {} bytes unacked",
                current.last_ack_recv_ms, HALF_OPEN_NO_ACK_MS, current.unacked
            );
            if no_forward_progress {
                explanation.push_str(", no forward progress (0 bytes ACKed in window)");
            }
            self.trend_metrics.half_open_suspect = Some(HealthFlag::new(true, explanation));
        } else {
            self.trend_metrics.half_open_suspect = Some(HealthFlag::new(
                false,
                format!(
                    "Connection responsive (last ACK: {}ms ago, {} unacked bytes)",
                    current.last_ack_recv_ms, current.unacked
                ),
            ));
        }

        // === HALF-OPEN CONFIRMED (STRONG DETECTION) ===
        // Same as suspect, BUT with retransmissions or zero-window probes
        // This provides high confidence the connection is truly broken

        let delta_retrans = current.total_retrans.saturating_sub(prev.total_retrans);
        let delta_probes = current.probes.saturating_sub(prev.probes);
        let has_retrans_or_probes = delta_retrans > 0 || delta_probes > 0;

        let half_open_confirmed = half_open_suspect && has_retrans_or_probes;

        if half_open_confirmed {
            self.trend_metrics.half_open_confirmed = Some(HealthFlag::new(
                true,
                format!(
                    "Half-open CONFIRMED: No ACK for {}ms + {} retrans + {} probes in window. Connection is broken - recommend close/reconnect.",
                    current.last_ack_recv_ms, delta_retrans, delta_probes
                ),
            ));
        } else if half_open_suspect {
            self.trend_metrics.half_open_confirmed = Some(HealthFlag::new(
                false,
                "Half-open suspected but not confirmed (no retrans/probes in window)".to_string(),
            ));
        } else {
            self.trend_metrics.half_open_confirmed = Some(HealthFlag::new(
                false,
                "Connection not half-open (ACKs being received normally)".to_string(),
            ));
        }
    }

    /// Calculate packet loss detection metrics
    ///
    /// === LOSS DETECTION FOR SMALL MESSAGES (~1KB) ===
    /// User's use case: ANY retransmission is critical (latency-sensitive).
    /// We report BOTH:
    /// 1. Absolute loss: ANY retransmission in window
    /// 2. Loss rate: Percentage (for future bulk transfer monitoring)
    fn calculate_loss_metrics(&mut self, prev: &TcpHealthSample, current: &TcpHealthSample) {
        // Calculate retransmission delta
        let delta_retrans = current.total_retrans.saturating_sub(prev.total_retrans);

        // === ABSOLUTE LOSS DETECTION (CRITICAL FOR SMALL MESSAGES) ===
        // ANY retransmission triggers this flag

        if delta_retrans > 0 {
            self.trend_metrics.loss_detected = Some(HealthFlag::new(
                true,
                format!(
                    "CRITICAL: {delta_retrans} packet retransmission(s) detected in window. For ~1KB messages, this adds RTT delay and indicates connection issues."
                ),
            ));
        } else {
            self.trend_metrics.loss_detected = Some(HealthFlag::new(
                false,
                "No packet loss detected in sample window (0 retransmissions)".to_string(),
            ));
        }

        // === LOSS RATE CALCULATION (FOR BULK TRANSFER MONITORING) ===
        // Only available if kernel supports bytes_sent/bytes_retrans (5.5+)

        if current.bytes_sent > 0 && prev.bytes_sent > 0 {
            // Kernel 5.5+ (RHEL 9) - we have byte-level counters
            let delta_bytes_sent = current.bytes_sent.saturating_sub(prev.bytes_sent);
            let delta_bytes_retrans = current.bytes_retrans.saturating_sub(prev.bytes_retrans);

            if delta_bytes_sent > 0 {
                // Data was actually sent in this window
                let loss_rate = delta_bytes_retrans as f64 / delta_bytes_sent as f64;
                let loss_rate_pct = loss_rate * 100.0;

                let exceeds_threshold = loss_rate > LOSS_CRITICAL_RATE_THRESHOLD;

                self.trend_metrics.loss_rate_pct = Some(HealthMetric::new(
                    loss_rate_pct,
                    if exceeds_threshold {
                        format!(
                            "CRITICAL: {:.2}% loss rate (threshold: {:.1}%), {} bytes lost of {} sent",
                            loss_rate_pct,
                            LOSS_CRITICAL_RATE_THRESHOLD * 100.0,
                            delta_bytes_retrans,
                            delta_bytes_sent
                        )
                    } else {
                        format!(
                            "Loss rate {:.2}% ({} bytes lost of {} sent, threshold: {:.1}%)",
                            loss_rate_pct,
                            delta_bytes_retrans,
                            delta_bytes_sent,
                            LOSS_CRITICAL_RATE_THRESHOLD * 100.0
                        )
                    },
                ));
            } else {
                // No data sent in window, loss rate not meaningful
                self.trend_metrics.loss_rate_pct = None;
            }
        } else {
            // Kernel < 5.5 - bytes_sent/bytes_retrans not available
            self.trend_metrics.loss_rate_pct = None;
        }
    }

    /// Calculate RTT drift and jitter metrics
    ///
    /// === RTT METRICS ===
    /// 1. RTT drift: `current_rtt` / `min_rtt` (how much worse than baseline?)
    /// 2. Jitter: rttvar / rtt (how stable is the latency?)
    fn calculate_rtt_metrics(&mut self, current: &TcpHealthSample) {
        // === RTT DRIFT (requires min_rtt - kernel 4.6+) ===

        if current.min_rtt_us > 0 && current.rtt_us > 0 {
            // Convert microseconds to milliseconds for human-readable output
            let rtt_ms = current.rtt_us as f64 / 1000.0;
            let min_rtt_ms = current.min_rtt_us as f64 / 1000.0;

            let drift_ratio = current.rtt_us as f64 / current.min_rtt_us as f64;

            let exceeds_threshold = drift_ratio > RTT_DRIFT_THRESHOLD;

            self.trend_metrics.rtt_drift = Some(HealthMetric::new(
                drift_ratio,
                if exceeds_threshold {
                    format!(
                        "CRITICAL: RTT drift {drift_ratio:.1}x baseline ({rtt_ms:.2}ms current vs {min_rtt_ms:.2}ms min, threshold: {RTT_DRIFT_THRESHOLD:.1}x). Indicates congestion or routing issues."
                    )
                } else {
                    format!(
                        "RTT drift {drift_ratio:.1}x baseline ({rtt_ms:.2}ms current vs {min_rtt_ms:.2}ms min, threshold: {RTT_DRIFT_THRESHOLD:.1}x)"
                    )
                },
            ));
        } else {
            // min_rtt not available (kernel < 4.6) or rtt is 0
            self.trend_metrics.rtt_drift = None;
        }

        // === JITTER INDEX (available on all kernels 3.10+) ===

        if current.rtt_us > 0 {
            let rtt_ms = current.rtt_us as f64 / 1000.0;
            let rtt_var_ms = current.rtt_var_us as f64 / 1000.0;

            let jitter_index = current.rtt_var_us as f64 / current.rtt_us as f64;

            let exceeds_threshold = jitter_index > JITTER_INDEX_THRESHOLD;

            self.trend_metrics.jitter_index = Some(HealthMetric::new(
                jitter_index,
                if exceeds_threshold {
                    format!(
                        "HIGH JITTER: {jitter_index:.2} ({rtt_var_ms:.2}ms variance / {rtt_ms:.2}ms RTT, threshold: {JITTER_INDEX_THRESHOLD:.2}). Indicates unstable latency."
                    )
                } else {
                    format!(
                        "Jitter {jitter_index:.2} ({rtt_var_ms:.2}ms variance / {rtt_ms:.2}ms RTT, threshold: {JITTER_INDEX_THRESHOLD:.2})"
                    )
                },
            ));
        } else {
            // RTT is 0 (no data to calculate)
            self.trend_metrics.jitter_index = None;
        }

        // === RTO INFLATION ===

        if current.rtt_us > 0 && current.rto_ms > 0 {
            let rtt_ms = current.rtt_us as f64 / 1000.0;
            let rto_ms = current.rto_ms as f64;

            let rto_ratio = rto_ms / rtt_ms;

            let exceeds_threshold = rto_ratio > RTO_RATIO_THRESHOLD;

            self.trend_metrics.rto_inflation = Some(HealthMetric::new(
                rto_ratio,
                if exceeds_threshold {
                    format!(
                        "RTO INFLATED: {rto_ratio:.1}x RTT ({rto_ms:.0}ms RTO vs {rtt_ms:.2}ms RTT, threshold: {RTO_RATIO_THRESHOLD:.1}x). TCP expects packet loss - connection near failure."
                    )
                } else {
                    format!(
                        "RTO normal: {rto_ratio:.1}x RTT ({rto_ms:.0}ms RTO vs {rtt_ms:.2}ms RTT, threshold: {RTO_RATIO_THRESHOLD:.1}x)"
                    )
                },
            ));
        } else {
            self.trend_metrics.rto_inflation = None;
        }
    }

    /// Calculate bottleneck detection metrics (receiver vs sender vs network)
    ///
    /// === BOTTLENECK IDENTIFICATION ===
    /// Uses kernel 4.9+ metrics to determine WHERE the bottleneck is:
    /// - High `rwnd_limited_pct`: Receiver is slow (can't process data fast enough)
    /// - High `sndbuf_limited_pct`: Sender is slow (application not writing fast enough)
    /// - Neither: Network is the bottleneck (congestion, limited bandwidth)
    fn calculate_bottleneck_metrics(&mut self, prev: &TcpHealthSample, current: &TcpHealthSample) {
        // Only available on kernel 4.9+ (RHEL 8+)
        if current.busy_time_us > 0 && prev.busy_time_us > 0 {
            let delta_busy = current.busy_time_us.saturating_sub(prev.busy_time_us);

            if delta_busy > 0 {
                // Connection was busy in this window

                // === RECEIVER BOTTLENECK ===
                let delta_rwnd_limited =
                    current.rwnd_limited_us.saturating_sub(prev.rwnd_limited_us);
                let recv_limited_pct = delta_rwnd_limited as f64 / delta_busy as f64;

                let recv_exceeds_threshold = recv_limited_pct > RECV_LIMITED_PCT_THRESHOLD;

                self.trend_metrics.recv_limited_pct = Some(HealthMetric::new(
                    recv_limited_pct,
                    if recv_exceeds_threshold {
                        format!(
                            "RECEIVER BOTTLENECK: {:.1}% of time limited by receiver window (threshold: {:.0}%). Receiver cannot process data fast enough.",
                            recv_limited_pct * 100.0,
                            RECV_LIMITED_PCT_THRESHOLD * 100.0
                        )
                    } else {
                        format!(
                            "Receiver OK: {:.1}% rwnd-limited (threshold: {:.0}%)",
                            recv_limited_pct * 100.0,
                            RECV_LIMITED_PCT_THRESHOLD * 100.0
                        )
                    },
                ));

                // === SENDER BOTTLENECK ===
                let delta_sndbuf_limited = current
                    .sndbuf_limited_us
                    .saturating_sub(prev.sndbuf_limited_us);
                let sender_limited_pct = delta_sndbuf_limited as f64 / delta_busy as f64;

                let sender_exceeds_threshold = sender_limited_pct > SENDER_LIMITED_PCT_THRESHOLD;

                self.trend_metrics.sender_limited_pct = Some(HealthMetric::new(
                    sender_limited_pct,
                    if sender_exceeds_threshold {
                        format!(
                            "SENDER BOTTLENECK: {:.1}% of time limited by send buffer (threshold: {:.0}%). Application not writing data fast enough.",
                            sender_limited_pct * 100.0,
                            SENDER_LIMITED_PCT_THRESHOLD * 100.0
                        )
                    } else {
                        format!(
                            "Sender OK: {:.1}% sndbuf-limited (threshold: {:.0}%)",
                            sender_limited_pct * 100.0,
                            SENDER_LIMITED_PCT_THRESHOLD * 100.0
                        )
                    },
                ));
            } else {
                // Connection not busy in window (no unacked data)
                self.trend_metrics.recv_limited_pct = None;
                self.trend_metrics.sender_limited_pct = None;
            }
        } else {
            // Kernel < 4.9 or connection never busy
            self.trend_metrics.recv_limited_pct = None;
            self.trend_metrics.sender_limited_pct = None;
        }
    }

    /// Calculate congestion state flags (suspected, confirmed, recovering)
    ///
    /// === TIERED CONGESTION DETECTION ===
    /// Three-level system (user requested all three):
    /// 1. Suspected: Early warning (cwnd decreased OR retrans occurring)
    /// 2. Confirmed: High confidence (cwnd < ssthresh AND retrans occurring)
    /// 3. Recovering: Problem resolving (cwnd growing AND no new retrans)
    fn calculate_congestion_metrics(&mut self, prev: &TcpHealthSample, current: &TcpHealthSample) {
        let delta_retrans = current.total_retrans.saturating_sub(prev.total_retrans);

        // === DETECT CWND DECREASE ===
        // saturating_sub returns 0 if current < prev (prevents underflow)
        // So we need to explicitly check if cwnd decreased
        let cwnd_decreased = if current.snd_cwnd < prev.snd_cwnd {
            prev.snd_cwnd - current.snd_cwnd >= CWND_DECREASE_THRESHOLD
        } else {
            false
        };

        let cwnd_increased = current.snd_cwnd > prev.snd_cwnd;

        // === CONGESTION SUSPECTED (EARLY WARNING) ===
        // Trigger on EITHER:
        // - cwnd decreased significantly, OR
        // - Retransmissions occurring

        let congestion_suspected = cwnd_decreased || delta_retrans > 0;

        if congestion_suspected {
            let mut reasons = Vec::new();
            if cwnd_decreased {
                reasons.push(format!(
                    "cwnd decreased from {} to {} segments",
                    prev.snd_cwnd, current.snd_cwnd
                ));
            }
            if delta_retrans > 0 {
                reasons.push(format!("{delta_retrans} retransmissions in window"));
            }

            self.trend_metrics.congestion_suspected = Some(HealthFlag::new(
                true,
                format!(
                    "Congestion suspected (early warning): {}. Watch connection closely.",
                    reasons.join(", ")
                ),
            ));
        } else {
            self.trend_metrics.congestion_suspected = Some(HealthFlag::new(
                false,
                format!(
                    "No congestion signals (cwnd: {} segments, 0 retrans in window)",
                    current.snd_cwnd
                ),
            ));
        }

        // === CONGESTION CONFIRMED (HIGH CONFIDENCE) ===
        // Requires BOTH:
        // - cwnd < ssthresh (TCP in congestion avoidance mode), AND
        // - Retransmissions occurring (actual packet loss)

        let in_congestion_avoidance = current.snd_cwnd < current.snd_ssthresh;
        let has_retrans = delta_retrans > 0;

        let congestion_confirmed = in_congestion_avoidance && has_retrans;

        if congestion_confirmed {
            self.trend_metrics.congestion_confirmed = Some(HealthFlag::new(
                true,
                format!(
                    "Congestion CONFIRMED: cwnd ({}) < ssthresh ({}), {} retransmissions. Connection experiencing packet loss.",
                    current.snd_cwnd, current.snd_ssthresh, delta_retrans
                ),
            ));

            // Update cached state: connection IS congested
            self.was_congested = true;
        } else if in_congestion_avoidance {
            self.trend_metrics.congestion_confirmed = Some(HealthFlag::new(
                false,
                format!(
                    "In congestion avoidance (cwnd {} < ssthresh {}) but no retrans in window",
                    current.snd_cwnd, current.snd_ssthresh
                ),
            ));
        } else {
            self.trend_metrics.congestion_confirmed = Some(HealthFlag::new(
                false,
                format!(
                    "Not congested (cwnd {} >= ssthresh {})",
                    current.snd_cwnd, current.snd_ssthresh
                ),
            ));

            // Update cached state: connection NOT congested
            self.was_congested = false;
        }

        // === CONGESTION RECOVERING ===
        // Only meaningful if connection WAS previously congested
        // Indicates recovery: cwnd growing AND no new retransmissions

        if self.was_congested && cwnd_increased && delta_retrans == 0 {
            self.trend_metrics.congestion_recovering = Some(HealthFlag::new(
                true,
                format!(
                    "Congestion recovering: cwnd growing ({} -> {} segments), no retrans in window. Problem resolving.",
                    prev.snd_cwnd, current.snd_cwnd
                ),
            ));
        } else if self.was_congested {
            self.trend_metrics.congestion_recovering = Some(HealthFlag::new(
                false,
                "Still congested (cwnd not growing or retrans still occurring)".to_string(),
            ));
        } else {
            // Never was congested, recovery doesn't apply
            self.trend_metrics.congestion_recovering = None;
        }

        // Cache cwnd for next iteration
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

    /// Check for status flapping (rapid status changes)
    /// Returns true if flapping detected (>3 changes in 30 seconds)
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
    /// Map from (`local_ip`, `local_port`, `remote_ip`, `remote_port`) 4-tuple to `ConnectionHistory`
    /// This allows tracking the same remote connection on different local sockets separately
    connections: HashMap<(String, u16, String, u16), ConnectionHistory>,

    /// Last cleanup time
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

    /// Add sample to connection history using 4-tuple key (`local_ip`, `local_port`, `remote_ip`, `remote_port`)
    ///
    /// === UPDATED FOR TCP HEALTH METRICS ===
    /// Now creates `TcpHealthSample` instead of `QueueSample`.
    /// For queue-only data (without full `TCP_INFO`), uses `TcpHealthSample::with_queues()`.
    ///
    /// OPTIMIZED: Accepts &str to avoid unnecessary clones from callers
    pub fn add_sample_with_local(
        &mut self,
        local_ip: &str,
        local_port: u16,
        remote_ip: &str,
        remote_port: u16,
        send_queue: u32,
        recv_queue: u32,
    ) {
        // Only allocate when creating new connection entry
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

    #[cfg(target_os = "linux")]
    pub fn add_sample_from_netlink(
        &mut self,
        local_ip: &str,
        local_port: u16,
        remote_ip: &str,
        remote_port: u16,
        conn_data: &crate::netlink::TcpConnectionData,
    ) {
        // Create key for connection lookup
        let key = (
            local_ip.to_string(),
            local_port,
            remote_ip.to_string(),
            remote_port,
        );

        // Get or create connection history
        let history = self
            .connections
            .entry(key)
            .or_insert_with(|| ConnectionHistory::new(remote_ip.to_string(), remote_port));

        let sample = TcpHealthSample::from_tcp_info(
            &conn_data.tcp_info,
            conn_data.send_queue_bytes,
            conn_data.recv_queue_bytes,
            conn_data.tcp_state,
        );

        // Add sample to history
        // This triggers calculate_health_metrics() which can now properly
        // detect stale connections, half-open, packet loss, etc.
        history.add_sample(sample);
    }

    /// Get connection history using 4-tuple key (`local_ip`, `local_port`, `remote_ip`, `remote_port`)
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

    /// Get mutable connection history using 4-tuple key (`local_ip`, `local_port`, `remote_ip`, `remote_port`)
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
        // Only cleanup every 60 seconds
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
        assert_eq!(sample.tcp_state, TCP_ESTABLISHED); // Should default to ESTABLISHED
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
        // Should keep only last 10
        assert_eq!(history.samples.len(), 10);
    }

    #[test]
    fn test_velocity_calculation() {
        let mut history = ConnectionHistory::new("192.168.1.1".to_string(), 5000);
        history.add_sample(TcpHealthSample::with_queues(1000, 500));
        thread::sleep(Duration::from_millis(100));
        history.add_sample(TcpHealthSample::with_queues(1500, 500));

        // Velocity should be positive (queue growing)
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
        // Add increasing samples
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
        assert!(!transitioned2); // No transition, same status
        assert_eq!(history.status_change_count, 1); // Count didn't increase
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
        // First local socket with remote 1
        manager.add_sample_with_local("10.0.1.5", 80, "192.168.1.1", 5000, 1000, 500);
        // Different local socket with different remote
        manager.add_sample_with_local("10.0.1.6", 443, "192.168.1.2", 6000, 2000, 600);
        // Same first local socket with another sample
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
        // This test demonstrates the key benefit of 4-tuple keying:
        // Same remote IP:port on different local sockets are tracked separately
        let mut manager = HistoryManager::new();

        // Same remote connection from two different local sockets
        manager.add_sample_with_local("10.0.1.5", 80, "8.8.8.8", 443, 1000, 0);
        manager.add_sample_with_local("10.0.1.6", 443, "8.8.8.8", 443, 2000, 0);

        assert_eq!(manager.connection_count(), 2); // Two separate entries
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
