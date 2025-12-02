//! TCP info parsing with kernel version compatibility
//!
//! This module handles parsing the `tcp_info` structure from INET_DIAG responses.
//! The key challenge: tcp_info size varies across kernel versions!
//!
//! # Educational Notes
//!
//! ## The tcp_info Structure
//!
//! `tcp_info` is a kernel structure containing detailed TCP metrics:
//! - Round-trip time (RTT)
//! - Congestion window size
//! - Retransmission counts
//! - Bytes sent/received
//! - And 50+ other metrics!
//!
//! This is what we currently get from the `ss` command. But with Netlink,
//! we get it directly from the kernel (much faster!).
//!
//! ## Kernel Version Challenge
//!
//! The tcp_info structure has grown over time:
//! - Kernel 3.10 (RHEL 7): ~192 bytes, basic metrics
//! - Kernel 4.2 (RHEL 8): ~232 bytes, added bytes_sent/bytes_retrans
//! - Kernel 4.6+: Added more fields (min_rtt, delivery_rate)
//! - Kernel 5.5+: Added even more (bytes_sent moved to kernel 5.5)
//!
//! **Problem:** If we define a struct sized for kernel 5.5, it won't work on kernel 3.10!
//!
//! **Solution:** Flexible parsing based on actual buffer size.
//!
//! ## Our Approach
//!
//! 1. Define "basic" structure with fields present in ALL kernels (3.10+)
//! 2. Define "extended" structure with newer fields (4.2+)
//! 3. Parse based on actual byte count we receive
//! 4. Gracefully handle missing fields (Option type)
//!
//! This ensures:
//! - Works on RHEL 7 (kernel 3.10) - basic metrics only
//! - Leverages RHEL 8+ (kernel 4.18+) - extended metrics
//! - No crashes from buffer overruns
//! - Clear API showing what's available
//!
//! ## Memory Layout (repr(C))
//!
//! The #[repr(C)] attribute makes Rust lay out struct fields exactly like C:
//! - No reordering of fields
//! - Predictable padding between fields
//! - Matches kernel structure layout byte-for-byte
//!
//! This is essential for binary protocol parsing!

// #![cfg(target_os = "linux")]

use crate::TcpMetrics; // From lib.rs

// ============================================================================
// ERROR TYPES
// ============================================================================

/// Errors that can occur during tcp_info parsing
#[derive(Debug)]
pub struct TcpInfoError {
    message: String,
}

impl TcpInfoError {
    fn new(message: String) -> Self {
        Self { message }
    }
}

impl std::fmt::Display for TcpInfoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for TcpInfoError {}

// ============================================================================
// TCP INFO STRUCTURES
// ============================================================================

/// Basic tcp_info fields (kernel 3.10+, RHEL 7+)
///
/// This structure contains fields guaranteed to be present in all kernel versions
/// we support. Size: 232 bytes (up to and including tcpi_total_retrans).
///
/// # Memory Layout
///
/// This structure uses #[repr(C)] to match kernel layout exactly.
/// Fields are in the same order as kernel's tcp_info structure.
///
/// # Compatibility
///
/// - RHEL 7 (kernel 3.10): Has these fields
/// - RHEL 8 (kernel 4.18): Has these fields + more
/// - RHEL 9 (kernel 5.14): Has these fields + even more
///
/// # Key Metrics
///
/// - `tcpi_rtt`: Round-trip time in microseconds (divide by 1000 for milliseconds)
/// - `tcpi_rttvar`: RTT variance in microseconds
/// - `tcpi_snd_cwnd`: Congestion window size in packets
/// - `tcpi_unacked`: Unacknowledged packets
/// - `tcpi_retrans`: Retransmitted packets
/// - `tcpi_total_retrans`: Total retransmits (all time)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TcpInfoBasic {
    // === State and options (8 bytes) ===
    pub tcpi_state: u8,       // TCP state (1=ESTABLISHED, 6=TIME_WAIT, etc.)
    pub tcpi_ca_state: u8,    // Congestion avoidance state
    pub tcpi_retransmits: u8, // Number of retransmits
    pub tcpi_probes: u8,      // Zero-window probes sent
    pub tcpi_backoff: u8,     // Backoff multiplier
    pub tcpi_options: u8,     // TCP options enabled (timestamps, SACK, etc.)
    pub tcpi_snd_wscale: u8,  // Send window scale (bits 0-3) + rcv_wscale (bits 4-7)
    pub tcpi_delivery_rate_app_limited: u8, // Bitfield flags

    // === Timeouts (8 bytes) ===
    pub tcpi_rto: u32, // Retransmit timeout (microseconds)
    pub tcpi_ato: u32, // Ack timeout (microseconds)

    // === MSS (8 bytes) ===
    pub tcpi_snd_mss: u32, // Send maximum segment size
    pub tcpi_rcv_mss: u32, // Receive maximum segment size

    // === Packet counts (20 bytes) ===
    pub tcpi_unacked: u32, // Unacknowledged packets
    pub tcpi_sacked: u32,  // SACKed packets
    pub tcpi_lost: u32,    // Lost packets
    pub tcpi_retrans: u32, // Retransmitted packets
    pub tcpi_fackets: u32, // Forward ack packets

    // === Times (16 bytes) ===
    pub tcpi_last_data_sent: u32, // Time since last data sent (ms)
    pub tcpi_last_ack_sent: u32,  // Time since last ACK sent (ms)
    pub tcpi_last_data_recv: u32, // Time since last data received (ms)
    pub tcpi_last_ack_recv: u32,  // Time since last ACK received (ms)

    // === Core metrics (40 bytes) ===
    pub tcpi_pmtu: u32,         // Path MTU
    pub tcpi_rcv_ssthresh: u32, // Receive slow start threshold
    pub tcpi_rtt: u32,          // *** KEY: Round trip time (microseconds) ***
    pub tcpi_rttvar: u32,       // *** KEY: RTT variance (microseconds) ***
    pub tcpi_snd_ssthresh: u32, // Send slow start threshold
    pub tcpi_snd_cwnd: u32,     // *** KEY: Send congestion window (packets) ***
    pub tcpi_advmss: u32,       // Advertised MSS
    pub tcpi_reordering: u32,   // Packet reordering metric
    pub tcpi_rcv_rtt: u32,      // Receiver RTT estimate (microseconds)
    pub tcpi_rcv_space: u32,    // Receive buffer space

    // === Total retransmits (4 bytes) ===
    pub tcpi_total_retrans: u32, // *** KEY: Total retransmit count (all time) ***

                                 // === Extended metrics start here (kernel 4.2+) ===
                                 //
                                 // We don't include them in this structure because older kernels don't have them.
                                 // Instead, we parse them separately if the buffer is large enough.
                                 //
                                 // Total size up to here: 8 + 8 + 8 + 20 + 16 + 40 + 4 = 104 bytes
}

/// Extended tcp_info fields (kernel 4.2+, RHEL 8+)
///
/// These fields are present in newer kernels. Not all may be available
/// depending on exact kernel version.
///
/// # Availability
///
/// - Kernel 4.2+: bytes_acked, bytes_received
/// - Kernel 4.6+: min_rtt, delivery_rate
/// - Kernel 5.5+: bytes_sent, bytes_retrans (critical for us!)
///
/// # Usage
///
/// This struct is wrapped in Option<TcpInfoExtended>.
/// - Some(extended): Newer kernel, extended metrics available
/// - None: Older kernel (RHEL 7), basic metrics only
#[derive(Debug, Clone, Copy, Default)]
pub struct TcpInfoExtended {
    // === Pacing (16 bytes) ===
    pub tcpi_pacing_rate: u64,     // Pacing rate (bytes/sec)
    pub tcpi_max_pacing_rate: u64, // Max pacing rate

    // === Byte counters (24 bytes) ===
    pub tcpi_bytes_acked: u64,    // RFC4898 bytes acknowledged
    pub tcpi_bytes_received: u64, // RFC4898 bytes received
    pub tcpi_segs_out: u32,       // RFC4898 segments out
    pub tcpi_segs_in: u32,        // RFC4898 segments in

    // === Additional metrics (24 bytes) ===
    pub tcpi_notsent_bytes: u32, // Bytes in send queue not sent yet
    pub tcpi_min_rtt: u32,       // *** KEY: Minimum RTT seen (microseconds) ***
    pub tcpi_data_segs_in: u32,  // Data segments received
    pub tcpi_data_segs_out: u32, // Data segments sent
    pub tcpi_delivery_rate: u64, // *** KEY: Delivery rate (bytes/sec) ***

    // === Time limited (24 bytes) ===
    pub tcpi_busy_time: u64,      // Time with outstanding data (usec)
    pub tcpi_rwnd_limited: u64,   // Time limited by receive window (usec)
    pub tcpi_sndbuf_limited: u64, // Time limited by send buffer (usec)

    // === More counters (32 bytes) ===
    pub tcpi_delivered: u32,     // Data packets delivered
    pub tcpi_delivered_ce: u32,  // ECN marked packets delivered
    pub tcpi_bytes_sent: u64,    // *** KEY: Total bytes sent (RFC4898) ***
    pub tcpi_bytes_retrans: u64, // *** KEY: Bytes retransmitted (RFC4898) ***
    pub tcpi_dsack_dups: u32,    // DSACK packets received
    pub tcpi_reord_seen: u32,    // Reordering events seen

    // === Even more (8 bytes) ===
    pub tcpi_rcv_ooopack: u32, // Out-of-order packets received
    pub tcpi_snd_wnd: u32,     // Advertised send window
}

/// Complete tcp_info with flexible parsing
///
/// This combines basic metrics (always present) with extended metrics
/// (available on newer kernels).
///
/// # Example
///
/// ```no_run
/// # use cerberus::netlink::tcp_info::*;
/// # let tcp_info_bytes = vec![0u8; 200];
/// let tcp_info = parse_tcp_info(&tcp_info_bytes)?;
///
/// println!("RTT: {} μs", tcp_info.basic.tcpi_rtt);
/// println!("Congestion window: {} packets", tcp_info.basic.tcpi_snd_cwnd);
///
/// if let Some(ext) = tcp_info.extended {
///     println!("Bytes sent: {}", ext.tcpi_bytes_sent);
///     println!("Bytes retransmitted: {}", ext.tcpi_bytes_retrans);
/// } else {
///     println!("Running on older kernel - extended metrics not available");
/// }
/// # Ok::<(), TcpInfoError>(())
/// ```
#[derive(Debug, Clone)]
pub struct TcpInfo {
    /// Basic metrics (guaranteed present on all supported kernels)
    pub basic: TcpInfoBasic,

    /// Extended metrics (available on kernel 4.2+, RHEL 8+)
    pub extended: Option<TcpInfoExtended>,
}

// ============================================================================
// PARSING FUNCTIONS
// ============================================================================

/// Parse tcp_info from attribute bytes
///
/// This function handles variable structure size across kernel versions.
/// It parses the basic fields (always present) and extended fields if
/// the buffer is large enough.
///
/// # Strategy
///
/// 1. Check buffer has minimum size for basic fields (~104 bytes)
/// 2. Parse basic fields by casting bytes to TcpInfoBasic structure
/// 3. Check if buffer has extended fields (size > basic size)
/// 4. If yes, parse extended fields
/// 5. Return TcpInfo with basic + optional extended
///
/// # Parameters
///
/// * `data` - Raw tcp_info bytes from INET_DIAG_INFO attribute
///
/// # Returns
///
/// * `Ok(TcpInfo)` - Successfully parsed tcp_info
/// * `Err(TcpInfoError)` - Buffer too small or parse error
///
/// # Kernel Compatibility
///
/// - RHEL 7 (kernel 3.10): ~192 byte buffer → basic only
/// - RHEL 8 (kernel 4.18): ~232 byte buffer → basic + extended
/// - RHEL 9 (kernel 5.14): ~240+ byte buffer → basic + extended (all fields)
///
/// # Example
///
/// ```no_run
/// # use cerberus::netlink::tcp_info::parse_tcp_info;
/// # use cerberus::netlink::structures::INET_DIAG_INFO;
/// # use std::collections::HashMap;
/// # let attributes: HashMap<u16, Vec<u8>> = HashMap::new();
/// if let Some(tcp_info_bytes) = attributes.get(&INET_DIAG_INFO) {
///     let tcp_info = parse_tcp_info(tcp_info_bytes)?;
///     println!("RTT: {:.2} ms", tcp_info.basic.tcpi_rtt as f64 / 1000.0);
/// }
/// # Ok::<(), cerberus::netlink::tcp_info::TcpInfoError>(())
/// ```
pub fn parse_tcp_info(data: &[u8]) -> Result<TcpInfo, TcpInfoError> {
    // === STEP 1: Validate minimum buffer size ===
    //
    // We need at least enough bytes for TcpInfoBasic.
    // This is the size up to and including tcpi_total_retrans.
    let basic_size = std::mem::size_of::<TcpInfoBasic>();

    if data.len() < basic_size {
        return Err(TcpInfoError::new(format!(
            "tcp_info buffer too small: {} bytes (minimum {} for basic fields)",
            data.len(),
            basic_size
        )));
    }

    // === STEP 2: Parse basic fields ===
    //
    // SAFETY: This unsafe block casts raw bytes to TcpInfoBasic structure.
    //
    // Why is this safe?
    // 1. We verified buffer has at least basic_size bytes (check above)
    // 2. TcpInfoBasic is #[repr(C)] - memory layout matches kernel
    // 3. All fields are primitive types (u8, u32) - no invalid bit patterns
    // 4. Data is properly aligned (kernel guarantees alignment)
    // 5. We immediately copy the structure (not holding long-lived reference)
    //
    // This is the standard way to deserialize binary protocol data in Rust.
    let basic = unsafe {
        let ptr = data.as_ptr() as *const TcpInfoBasic;
        *ptr // Copy structure
    };

    // === STEP 3: Determine if extended fields are present ===
    //
    // Extended fields start after basic fields.
    // If buffer is larger than basic size, we have extended fields.
    //
    // We parse as many extended fields as the buffer contains.
    // This handles partial extended structures gracefully.
    let extended = if data.len() > basic_size {
        // Try to parse extended fields
        Some(parse_extended_fields(&data[basic_size..]))
    } else {
        // No extended fields (older kernel)
        None
    };

    Ok(TcpInfo { basic, extended })
}

/// Parse extended tcp_info fields from remaining buffer
///
/// This function extracts extended fields field-by-field, handling
/// partial structures gracefully. If buffer is too small for a field,
/// we use default value (0).
///
/// # Why Not Cast to TcpInfoExtended?
///
/// We can't safely cast because:
/// 1. Buffer might be partial (not all fields present)
/// 2. Field order might vary slightly across kernel versions
/// 3. We want graceful degradation, not crashes
///
/// # Parameters
///
/// * `data` - Bytes after TcpInfoBasic (extended field region)
///
/// # Returns
///
/// TcpInfoExtended with as many fields as buffer contains
fn parse_extended_fields(data: &[u8]) -> TcpInfoExtended {
    let mut ext = TcpInfoExtended::default();
    let mut offset: usize = 0;

    // === Helper macro to parse u32 field ===
    //
    // This macro extracts a u32 from the buffer at current offset.
    // If buffer doesn't have enough bytes, uses 0 (default).
    //
    // Note: The last use of this macro will trigger an unused_assignments warning
    // because offset is incremented but never read again. This is expected behavior.
    macro_rules! parse_u32 {
        ($field:expr) => {
            #[allow(unused_assignments)]
            if offset + 4 <= data.len() {
                $field = u32::from_ne_bytes([
                    data[offset],
                    data[offset + 1],
                    data[offset + 2],
                    data[offset + 3],
                ]);
                offset += 4;
            }
        };
    }

    // === Helper macro to parse u64 field ===
    //
    // Note: The last use of this macro will trigger an unused_assignments warning
    // because offset is incremented but never read again. This is expected behavior.
    macro_rules! parse_u64 {
        ($field:expr) => {
            #[allow(unused_assignments)]
            if offset + 8 <= data.len() {
                $field = u64::from_ne_bytes([
                    data[offset],
                    data[offset + 1],
                    data[offset + 2],
                    data[offset + 3],
                    data[offset + 4],
                    data[offset + 5],
                    data[offset + 6],
                    data[offset + 7],
                ]);
                offset += 8;
            }
        };
    }

    // === Parse fields in order (matching kernel structure) ===
    //
    // These are in the order they appear in kernel's tcp_info structure.
    // Kernel 4.2+ additions:
    parse_u64!(ext.tcpi_pacing_rate);
    parse_u64!(ext.tcpi_max_pacing_rate);
    parse_u64!(ext.tcpi_bytes_acked);
    parse_u64!(ext.tcpi_bytes_received);
    parse_u32!(ext.tcpi_segs_out);
    parse_u32!(ext.tcpi_segs_in);

    // Kernel 4.6+ additions:
    parse_u32!(ext.tcpi_notsent_bytes);
    parse_u32!(ext.tcpi_min_rtt);
    parse_u32!(ext.tcpi_data_segs_in);
    parse_u32!(ext.tcpi_data_segs_out);
    parse_u64!(ext.tcpi_delivery_rate);

    // Kernel 4.9+ additions:
    parse_u64!(ext.tcpi_busy_time);
    parse_u64!(ext.tcpi_rwnd_limited);
    parse_u64!(ext.tcpi_sndbuf_limited);

    // Kernel 5.5+ additions (the ones we really want!):
    parse_u32!(ext.tcpi_delivered);
    parse_u32!(ext.tcpi_delivered_ce);
    parse_u64!(ext.tcpi_bytes_sent); // *** KEY METRIC ***
    parse_u64!(ext.tcpi_bytes_retrans); // *** KEY METRIC ***
    parse_u32!(ext.tcpi_dsack_dups);
    parse_u32!(ext.tcpi_reord_seen);

    // Kernel 5.8+ additions:
    parse_u32!(ext.tcpi_rcv_ooopack);
    parse_u32!(ext.tcpi_snd_wnd);

    ext
}

/// Convert TcpInfo to TcpMetrics (our application structure)
///
/// This maps the kernel's tcp_info structure to our application's
/// TcpMetrics structure (defined in lib.rs).
///
/// # Conversions
///
/// - RTT: microseconds → milliseconds (÷ 1000)
/// - Bytes: Use extended fields if available, else 0
/// - Counts: Direct copy
/// - Extended metrics: Wrapped in Option (Some if available, None otherwise)
///
/// # Kernel Compatibility
///
/// - **Kernel 3.10+ (RHEL 7+)**: Basic metrics + some extended (lost, total_retrans, ssthresh, pmtu, last_data_sent)
/// - **Kernel 4.6+ (RHEL 8+)**: Adds min_rtt, delivery_rate
/// - **Kernel 4.9+ (RHEL 8+)**: Adds busy_time, rwnd_limited, sndbuf_limited
///
/// # Parameters
///
/// * `info` - Parsed tcp_info from kernel
///
/// # Returns
///
/// TcpMetrics ready for health assessment
///
/// # Example
///
/// ```no_run
/// # use cerberus::netlink::tcp_info::*;
/// # let tcp_info_bytes = vec![0u8; 200];
/// let tcp_info = parse_tcp_info(&tcp_info_bytes)?;
/// let metrics = tcp_info_to_metrics(&tcp_info);
///
/// println!("RTT: {:.2} ms", metrics.rtt_ms);
/// println!("Congestion window: {} packets", metrics.congestion_window);
///
/// // Check extended metrics
/// if let Some(min_rtt) = metrics.min_rtt_ms {
///     println!("Min RTT: {:.2} ms (baseline latency)", min_rtt);
/// }
/// # Ok::<(), TcpInfoError>(())
/// ```
pub fn tcp_info_to_metrics(info: &TcpInfo) -> TcpMetrics {
    TcpMetrics {
        // ========================================================================
        // ORIGINAL 7 METRICS (always present, kernel 3.10+)
        // ========================================================================

        // === RTT metrics (convert microseconds to milliseconds) ===
        //
        // Kernel provides RTT in microseconds.
        // We want milliseconds for display.
        // Example: 45000 μs → 45.0 ms
        rtt_ms: info.basic.tcpi_rtt as f64 / 1000.0,
        rtt_var_ms: info.basic.tcpi_rttvar as f64 / 1000.0,

        // === Byte counters (from extended fields if available) ===
        //
        // These are critical metrics but only available on kernel 5.5+.
        // On older kernels, we'll have 0 (which is technically correct -
        // the field doesn't exist, so we don't have the data).
        bytes_sent: info
            .extended
            .as_ref()
            .map(|e| e.tcpi_bytes_sent)
            .unwrap_or(0),

        bytes_retrans: info
            .extended
            .as_ref()
            .map(|e| e.tcpi_bytes_retrans)
            .unwrap_or(0),

        // === Congestion and packet metrics (from basic fields) ===
        //
        // These are always available (kernel 3.10+)
        congestion_window: info.basic.tcpi_snd_cwnd,
        unacked_packets: info.basic.tcpi_unacked,
        retrans_events: info.basic.tcpi_retrans,

        // ========================================================================
        // EXTENDED 10 METRICS (Optional, kernel version dependent)
        // ========================================================================

        // === 1. MIN_RTT_MS (kernel 4.6+) ===
        //
        // Minimum RTT observed - baseline latency for this connection.
        // Convert from microseconds to milliseconds.
        // Only available if extended fields are present AND min_rtt is non-zero.
        min_rtt_ms: info.extended.as_ref().and_then(|e| {
            if e.tcpi_min_rtt > 0 {
                Some(e.tcpi_min_rtt as f64 / 1000.0)
            } else {
                None // Zero min_rtt means field not populated (older kernel)
            }
        }),

        // === 2. DELIVERY_RATE_BPS (kernel 4.6+) ===
        //
        // Current throughput in bytes per second.
        // This is actual achievable rate, not link capacity.
        delivery_rate_bps: info.extended.as_ref().and_then(|e| {
            if e.tcpi_delivery_rate > 0 {
                Some(e.tcpi_delivery_rate)
            } else {
                None // Zero means not available or connection inactive
            }
        }),

        // === 3. LOST_PACKETS (kernel 3.10+) ===
        //
        // Total packets lost - available even on RHEL 7.
        // This is from basic structure fields.
        lost_packets: if info.basic.tcpi_lost > 0 {
            Some(info.basic.tcpi_lost)
        } else {
            None // Zero losses or field not available
        },

        // === 4. RWND_LIMITED_US (kernel 4.9+) ===
        //
        // Time blocked waiting on receiver window (receiver bottleneck).
        // Microseconds - keep as-is (don't convert to ms to preserve precision).
        rwnd_limited_us: info.extended.as_ref().and_then(|e| {
            if e.tcpi_rwnd_limited > 0 {
                Some(e.tcpi_rwnd_limited)
            } else {
                None
            }
        }),

        // === 5. SNDBUF_LIMITED_US (kernel 4.9+) ===
        //
        // Time blocked waiting on send buffer (sender application bottleneck).
        // Microseconds - keep as-is.
        sndbuf_limited_us: info.extended.as_ref().and_then(|e| {
            if e.tcpi_sndbuf_limited > 0 {
                Some(e.tcpi_sndbuf_limited)
            } else {
                None
            }
        }),

        // === 6. BUSY_TIME_US (kernel 4.9+) ===
        //
        // Time connection was actively transmitting data.
        // Useful for calculating utilization.
        // Microseconds - keep as-is.
        busy_time_us: info.extended.as_ref().and_then(|e| {
            if e.tcpi_busy_time > 0 {
                Some(e.tcpi_busy_time)
            } else {
                None
            }
        }),

        // === 7. TOTAL_RETRANS (kernel 3.10+) ===
        //
        // Lifetime retransmission count.
        // Available even on RHEL 7 (from basic structure).
        total_retrans: if info.basic.tcpi_total_retrans > 0 {
            Some(info.basic.tcpi_total_retrans)
        } else {
            None
        },

        // === 8. SND_SSTHRESH (kernel 3.10+) ===
        //
        // Slow start threshold - congestion control parameter.
        // Available even on RHEL 7 (from basic structure).
        snd_ssthresh: if info.basic.tcpi_snd_ssthresh > 0 {
            Some(info.basic.tcpi_snd_ssthresh)
        } else {
            None
        },

        // === 9. LAST_DATA_SENT_MS (kernel 3.10+) ===
        //
        // Time since last data sent.
        // Already in milliseconds in kernel structure.
        // Available even on RHEL 7 (from basic structure).
        last_data_sent_ms: if info.basic.tcpi_last_data_sent > 0 {
            Some(info.basic.tcpi_last_data_sent)
        } else {
            None // Zero means data was just sent or field not available
        },

        // === 10. PMTU (kernel 3.10+) ===
        //
        // Path MTU (maximum transmission unit).
        // Available even on RHEL 7 (from basic structure).
        pmtu: if info.basic.tcpi_pmtu > 0 {
            Some(info.basic.tcpi_pmtu)
        } else {
            None
        },
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_tcp_info_too_small() {
        // Buffer too small (only 50 bytes)
        let data = vec![0u8; 50];
        let result = parse_tcp_info(&data);
        assert!(result.is_err(), "Should fail with small buffer");
    }

    #[test]
    fn test_parse_tcp_info_basic_only() {
        // Create a buffer with basic fields only (104 bytes minimum)
        // This simulates RHEL 7 / kernel 3.10
        let mut data = vec![0u8; 104];

        // Set some recognizable values in basic fields
        // tcpi_rtt is at offset 60 (after many fields)
        // For simplicity, just verify parsing doesn't crash
        let result = parse_tcp_info(&data);
        assert!(result.is_ok(), "Should parse basic fields successfully");

        let tcp_info = result.unwrap();
        assert!(
            tcp_info.extended.is_none(),
            "Should not have extended fields"
        );
    }

    #[test]
    fn test_parse_tcp_info_with_extended() {
        // Create a buffer with basic + extended fields (200+ bytes)
        // This simulates RHEL 8+ / kernel 4.18+
        let mut data = vec![0u8; 250];

        // Set some test values
        // RTT at offset 60: 45000 μs (45 ms)
        data[60..64].copy_from_slice(&45000u32.to_ne_bytes());

        // Congestion window at offset 72: 10 packets
        data[72..76].copy_from_slice(&10u32.to_ne_bytes());

        let result = parse_tcp_info(&data);
        assert!(result.is_ok(), "Should parse extended fields successfully");

        let tcp_info = result.unwrap();
        assert!(tcp_info.extended.is_some(), "Should have extended fields");
        assert_eq!(tcp_info.basic.tcpi_rtt, 45000);
        assert_eq!(tcp_info.basic.tcpi_snd_cwnd, 10);
    }

    #[test]
    fn test_tcp_info_to_metrics() {
        // Create a TcpInfo with known values
        let mut basic = unsafe { std::mem::zeroed::<TcpInfoBasic>() };
        basic.tcpi_rtt = 50000; // 50 ms in microseconds
        basic.tcpi_rttvar = 5000; // 5 ms in microseconds
        basic.tcpi_snd_cwnd = 20;
        basic.tcpi_unacked = 5;
        basic.tcpi_retrans = 2;
        basic.tcpi_lost = 3; // Extended metric from basic fields
        basic.tcpi_total_retrans = 10;
        basic.tcpi_snd_ssthresh = 100;
        basic.tcpi_last_data_sent = 50; // 50 ms
        basic.tcpi_pmtu = 1500; // Standard Ethernet MTU

        let mut extended = TcpInfoExtended::default();
        extended.tcpi_bytes_sent = 1000000;
        extended.tcpi_bytes_retrans = 5000;
        extended.tcpi_min_rtt = 5000; // 5 ms in microseconds
        extended.tcpi_delivery_rate = 1250000; // 10 Mbps in bytes/sec
        extended.tcpi_rwnd_limited = 100000; // 100ms in microseconds
        extended.tcpi_sndbuf_limited = 50000; // 50ms in microseconds
        extended.tcpi_busy_time = 500000; // 500ms in microseconds

        let tcp_info = TcpInfo {
            basic,
            extended: Some(extended),
        };

        let metrics = tcp_info_to_metrics(&tcp_info);

        // Verify original 7 metrics
        assert_eq!(metrics.rtt_ms, 50.0);
        assert_eq!(metrics.rtt_var_ms, 5.0);
        assert_eq!(metrics.bytes_sent, 1000000);
        assert_eq!(metrics.bytes_retrans, 5000);
        assert_eq!(metrics.congestion_window, 20);
        assert_eq!(metrics.unacked_packets, 5);
        assert_eq!(metrics.retrans_events, 2);

        // Verify extended 10 metrics
        assert_eq!(metrics.min_rtt_ms, Some(5.0));
        assert_eq!(metrics.delivery_rate_bps, Some(1250000));
        assert_eq!(metrics.lost_packets, Some(3));
        assert_eq!(metrics.rwnd_limited_us, Some(100000));
        assert_eq!(metrics.sndbuf_limited_us, Some(50000));
        assert_eq!(metrics.busy_time_us, Some(500000));
        assert_eq!(metrics.total_retrans, Some(10));
        assert_eq!(metrics.snd_ssthresh, Some(100));
        assert_eq!(metrics.last_data_sent_ms, Some(50));
        assert_eq!(metrics.pmtu, Some(1500));
    }

    #[test]
    fn test_tcp_info_to_metrics_no_extended() {
        // Test with basic fields only (simulates RHEL 7)
        let mut basic = unsafe { std::mem::zeroed::<TcpInfoBasic>() };
        basic.tcpi_rtt = 30000; // 30 ms
        basic.tcpi_rttvar = 3000; // 3 ms
        basic.tcpi_snd_cwnd = 15;
        basic.tcpi_unacked = 3;
        basic.tcpi_retrans = 1;
        basic.tcpi_lost = 2;
        basic.tcpi_total_retrans = 5;
        basic.tcpi_snd_ssthresh = 50;
        basic.tcpi_last_data_sent = 100;
        basic.tcpi_pmtu = 1500;

        let tcp_info = TcpInfo {
            basic,
            extended: None, // No extended fields
        };

        let metrics = tcp_info_to_metrics(&tcp_info);

        // Verify basic conversions
        assert_eq!(metrics.rtt_ms, 30.0);
        assert_eq!(metrics.rtt_var_ms, 3.0);
        assert_eq!(metrics.congestion_window, 15);
        assert_eq!(metrics.unacked_packets, 3);
        assert_eq!(metrics.retrans_events, 1);

        // Original extended fields should be 0 (no extended structure)
        assert_eq!(metrics.bytes_sent, 0);
        assert_eq!(metrics.bytes_retrans, 0);

        // Basic structure extended metrics should be Some (RHEL 7 has these)
        assert_eq!(metrics.lost_packets, Some(2));
        assert_eq!(metrics.total_retrans, Some(5));
        assert_eq!(metrics.snd_ssthresh, Some(50));
        assert_eq!(metrics.last_data_sent_ms, Some(100));
        assert_eq!(metrics.pmtu, Some(1500));

        // Extended structure metrics should be None (RHEL 7 doesn't have these)
        assert_eq!(metrics.min_rtt_ms, None);
        assert_eq!(metrics.delivery_rate_bps, None);
        assert_eq!(metrics.rwnd_limited_us, None);
        assert_eq!(metrics.sndbuf_limited_us, None);
        assert_eq!(metrics.busy_time_us, None);
    }

    #[test]
    fn test_parse_extended_fields_partial() {
        // Test parsing partial extended fields (buffer doesn't have all fields)
        // This simulates kernel 4.2 which has some but not all extended fields

        let mut data = vec![0u8; 40]; // Only enough for first few fields

        // Set tcpi_pacing_rate (first u64)
        data[0..8].copy_from_slice(&123456u64.to_ne_bytes());

        let ext = parse_extended_fields(&data);

        // First field should be parsed
        assert_eq!(ext.tcpi_pacing_rate, 123456);

        // Later fields should be 0 (default)
        assert_eq!(ext.tcpi_bytes_sent, 0);
        assert_eq!(ext.tcpi_bytes_retrans, 0);
    }
}
