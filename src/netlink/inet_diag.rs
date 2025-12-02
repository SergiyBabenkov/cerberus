//! High-level INET_DIAG query API
//!
//! This module provides easy-to-use functions for querying TCP connection information
//! using Linux's INET_DIAG protocol via Netlink.
//!
//! # Educational Notes
//!
//! ## What This Module Does
//!
//! This is the "glue code" that ties everything together:
//! 1. Takes simple inputs (IP addresses, ports)
//! 2. Builds Netlink request messages
//! 3. Sends them to kernel via socket
//! 4. Receives and parses responses
//! 5. Extracts tcp_info from attributes
//! 6. Returns easy-to-use TcpInfo structures
//!
//! ## API Design
//!
//! We provide two main functions:
//!
//! **Single Connection Query:**
//! - `query_tcp_connection()` - Query one specific connection by 4-tuple
//! - Fast: kernel returns only the matching connection
//! - Returns: TcpInfo or NotFound error
//!
//! **Batch Query:**
//! - `query_tcp_connections_batch()` - Query multiple connections at once
//! - Efficient: one kernel query, filter results
//! - Returns: HashMap of connection → TcpInfo
//!
//! ## Error Handling Strategy
//!
//! We use enum-based errors to distinguish different failure modes:
//! - Socket errors (can't open socket, permission denied)
//! - Message errors (malformed responses)
//! - TcpInfo errors (can't parse tcp_info)
//! - NotFound (connection doesn't exist)
//! - PermissionDenied (need root on RHEL 7)
//!
//! This allows callers to handle each case appropriately.
//!
//! ## Performance Considerations
//!
//! - Single query: Direct kernel lookup (~0.1-0.5 ms)
//! - Batch query: One kernel dump, filter in userspace (~0.5-2 ms for 100 connections)
//! - Much faster than subprocess `ss` command (5-15 ms per call)

// #![cfg(target_os = "linux")]

use crate::netlink::message::{
    MessageError, ParsedMessage, build_inet_diag_request, parse_netlink_messages,
};
use crate::netlink::socket::{NetlinkSocket, SocketError};
use crate::netlink::structures::*;
use crate::netlink::tcp_info::{TcpInfo, TcpInfoError, parse_tcp_info};
use std::collections::HashMap;
use std::net::Ipv4Addr;

// ============================================================================
// ERROR TYPES
// ============================================================================

/// Errors that can occur during INET_DIAG queries
///
/// This enum covers all possible error cases, allowing callers to
/// handle each situation appropriately.
///
/// # Error Categories
///
/// - **Socket errors**: Can't open socket, permission denied
/// - **Message errors**: Malformed response, parse failures
/// - **TcpInfo errors**: Can't parse tcp_info structure
/// - **NotFound**: Connection doesn't exist (not an error, just no data)
/// - **PermissionDenied**: Need root/CAP_NET_ADMIN (RHEL 7)
///
/// # Example
///
/// ```no_run
/// # use cerberus::netlink::inet_diag::*;
/// match query_tcp_connection("192.168.1.5", 8080, "10.0.1.1", 5000) {
///     Ok(tcp_info) => println!("RTT: {} μs", tcp_info.basic.tcpi_rtt),
///     Err(InetDiagError::NotFound) => println!("Connection not found"),
///     Err(InetDiagError::PermissionDenied) => println!("Need root privileges"),
///     Err(e) => eprintln!("Error: {}", e),
/// }
/// ```
#[derive(Debug)]
pub enum InetDiagError {
    /// Socket operation failed
    Socket(SocketError),

    /// Message parsing failed
    Message(MessageError),

    /// tcp_info parsing failed
    TcpInfo(TcpInfoError),

    /// Connection not found (not an error, just no match)
    NotFound,

    /// Permission denied (need root on RHEL 7)
    PermissionDenied,

    /// Other error with message
    Other(String),
}

/// Implement Display for nice error messages
impl std::fmt::Display for InetDiagError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InetDiagError::Socket(e) => write!(f, "Socket error: {}", e),
            InetDiagError::Message(e) => write!(f, "Message error: {}", e),
            InetDiagError::TcpInfo(e) => write!(f, "TcpInfo error: {}", e),
            InetDiagError::NotFound => write!(f, "Connection not found"),
            InetDiagError::PermissionDenied => {
                write!(f, "Permission denied (need root/CAP_NET_ADMIN)")
            }
            InetDiagError::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for InetDiagError {}

/// Convert SocketError to InetDiagError
impl From<SocketError> for InetDiagError {
    fn from(e: SocketError) -> Self {
        InetDiagError::Socket(e)
    }
}

/// Convert MessageError to InetDiagError
impl From<MessageError> for InetDiagError {
    fn from(e: MessageError) -> Self {
        InetDiagError::Message(e)
    }
}

/// Convert TcpInfoError to InetDiagError
impl From<TcpInfoError> for InetDiagError {
    fn from(e: TcpInfoError) -> Self {
        InetDiagError::TcpInfo(e)
    }
}

// ============================================================================
// DATA STRUCTURES
// ============================================================================

/// Complete TCP connection data from INET_DIAG query
///
/// This structure combines data from multiple sources in the Netlink response:
/// - InetDiagMsg: Queue sizes and TCP state
/// - INET_DIAG_INFO attribute: Full tcp_info structure
///
/// # Why This Exists
///
/// The Netlink INET_DIAG response provides two pieces of information:
/// 1. **InetDiagMsg**: Basic connection info (queue sizes, state)
/// 2. **Attributes**: Extended data like tcp_info (RTT, retransmits, etc.)
///
/// Previously, we only returned tcp_info and threw away the queue sizes.
/// This struct captures ALL data so nothing is lost.
///
/// # Usage
///
/// This is returned by `query_tcp_connection()` and `query_tcp_connections_batch()`.
/// It can be converted to `TcpHealthSample` for connection health tracking.
///
/// # Example
///
/// ```no_run
/// # use cerberus::netlink::inet_diag::*;
/// let conn_data = query_tcp_connection("192.168.1.5", 8080, "10.0.1.1", 5000)?;
///
/// println!("Send queue: {} bytes", conn_data.send_queue_bytes);
/// println!("RTT: {} μs", conn_data.tcp_info.basic.tcpi_rtt);
/// println!("State: {}", conn_data.tcp_state);
/// # Ok::<(), InetDiagError>(())
/// ```
#[derive(Debug, Clone)]
pub struct TcpConnectionData {
    /// Full TCP_INFO structure from kernel
    ///
    /// Contains all TCP metrics: RTT, retransmissions, congestion window, etc.
    /// Available on all supported kernels (3.10+).
    pub tcp_info: TcpInfo,

    /// Bytes waiting in send queue (data waiting to be sent)
    ///
    /// From InetDiagMsg.idiag_wqueue.
    /// High values indicate:
    /// - Application writing faster than network can send
    /// - Network congestion
    /// - Receiver window limiting
    pub send_queue_bytes: u32,

    /// Bytes waiting in receive queue (data waiting to be read by application)
    ///
    /// From InetDiagMsg.idiag_rqueue.
    /// High values indicate:
    /// - Application reading slower than data arriving
    /// - Application is the bottleneck
    pub recv_queue_bytes: u32,

    /// TCP connection state
    ///
    /// From InetDiagMsg.idiag_state.
    /// Values (from Linux kernel tcp_states.h):
    /// - 1 = TCP_ESTABLISHED (connection is active)
    /// - 2 = TCP_SYN_SENT (connection attempt in progress)
    /// - 3 = TCP_SYN_RECV (connection being established)
    /// - 4 = TCP_FIN_WAIT1 (closing)
    /// - ... (other closing states)
    ///
    /// Most health metrics only make sense for ESTABLISHED connections.
    pub tcp_state: u8,
}

impl TcpConnectionData {
    // ========================================================================
    // CONVENIENCE METHODS
    // ========================================================================
    //
    // These methods provide easy access to commonly used TCP metrics
    // without needing to navigate the nested tcp_info structure.
    //
    // ## Design Rationale
    //
    // The raw tcp_info structure has fields in kernel units (microseconds)
    // and nested in basic/extended. These helpers:
    // 1. Convert to application units (milliseconds)
    // 2. Provide simple field access
    // 3. Handle Option<extended> gracefully
    // 4. Enable clean health assessment code

    /// Get RTT (Round Trip Time) in milliseconds
    ///
    /// Converts from kernel microseconds to milliseconds for easier use.
    ///
    /// # Returns
    ///
    /// RTT in milliseconds, or 0.0 if no RTT available
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use cerberus::netlink::inet_diag::*;
    /// let conn_data = query_tcp_connection("192.168.1.5", 8080, "10.0.1.1", 5000)?;
    /// println!("RTT: {:.2} ms", conn_data.rtt_ms());
    /// # Ok::<(), InetDiagError>(())
    /// ```
    #[inline]
    pub fn rtt_ms(&self) -> f64 {
        self.tcp_info.basic.tcpi_rtt as f64 / 1000.0
    }

    /// Get RTT variance in milliseconds
    ///
    /// Higher variance indicates unstable network conditions.
    ///
    /// # Returns
    ///
    /// RTT variance in milliseconds, or 0.0 if not available
    #[inline]
    pub fn rtt_var_ms(&self) -> f64 {
        self.tcp_info.basic.tcpi_rttvar as f64 / 1000.0
    }

    /// Get minimum RTT seen in milliseconds
    ///
    /// Represents best-case network latency without congestion.
    /// Available on kernel 4.2+ (RHEL 8+).
    ///
    /// # Returns
    ///
    /// Minimum RTT in milliseconds, or None if not available
    #[inline]
    pub fn min_rtt_ms(&self) -> Option<f64> {
        self.tcp_info
            .extended
            .as_ref()
            .map(|ext| ext.tcpi_min_rtt as f64 / 1000.0)
    }

    /// Get current congestion window size
    ///
    /// Number of packets that can be in-flight (sent but not ACKed).
    /// Lower values indicate congestion or packet loss.
    ///
    /// # Returns
    ///
    /// Congestion window in packets
    #[inline]
    pub fn congestion_window(&self) -> u32 {
        self.tcp_info.basic.tcpi_snd_cwnd
    }

    /// Get slow start threshold
    ///
    /// When cwnd exceeds ssthresh, TCP switches from slow start to
    /// congestion avoidance. Low ssthresh indicates past packet loss.
    ///
    /// # Returns
    ///
    /// Slow start threshold in packets
    #[inline]
    pub fn slow_start_threshold(&self) -> u32 {
        self.tcp_info.basic.tcpi_snd_ssthresh
    }

    /// Check if connection has experienced packet loss
    ///
    /// Returns true if any retransmissions have occurred.
    ///
    /// # Returns
    ///
    /// true if packet loss detected, false otherwise
    pub fn has_packet_loss(&self) -> bool {
        // Check basic retransmissions (always available)
        if self.tcp_info.basic.tcpi_retrans > 0 {
            return true;
        }

        // Check extended metrics if available (more accurate)
        // Note: tcpi_lost is in basic structure, not extended
        if let Some(ext) = &self.tcp_info.extended
            && (ext.tcpi_bytes_retrans > 0 || self.tcp_info.basic.tcpi_lost > 0)
        {
            return true;
        }

        false
    }

    /// Check if send queue has significant buildup
    ///
    /// High send queue indicates data is being produced faster than
    /// the network can transmit, or network congestion.
    ///
    /// # Thresholds
    ///
    /// - Warning: >= 2KB (typical MSS * cwnd)
    /// - Critical: >= 4KB (sustained backlog)
    ///
    /// # Returns
    ///
    /// true if send queue >= 2KB
    pub fn has_queue_buildup(&self) -> bool {
        self.send_queue_bytes >= 2048
    }

    /// Check if connection is in ESTABLISHED state
    ///
    /// Most TCP health metrics only make sense for ESTABLISHED connections.
    ///
    /// # Returns
    ///
    /// true if state is TCP_ESTABLISHED (1)
    #[inline]
    pub fn is_established(&self) -> bool {
        self.tcp_state == 1 // TCP_ESTABLISHED
    }

    /// Get total bytes sent
    ///
    /// Available on kernel 4.2+ (RHEL 8+).
    ///
    /// # Returns
    ///
    /// Total bytes sent, or None if not available
    #[inline]
    pub fn bytes_sent(&self) -> Option<u64> {
        self.tcp_info
            .extended
            .as_ref()
            .map(|ext| ext.tcpi_bytes_sent)
    }

    /// Get total bytes retransmitted
    ///
    /// Available on kernel 4.2+ (RHEL 8+).
    ///
    /// # Returns
    ///
    /// Total bytes retransmitted, or None if not available
    #[inline]
    pub fn bytes_retransmitted(&self) -> Option<u64> {
        self.tcp_info
            .extended
            .as_ref()
            .map(|ext| ext.tcpi_bytes_retrans)
    }

    /// Calculate retransmission rate
    ///
    /// Percentage of bytes that had to be retransmitted.
    /// Available on kernel 4.2+ (RHEL 8+).
    ///
    /// # Returns
    ///
    /// Retransmission rate as percentage (0.0-100.0), or None if not available
    pub fn retransmission_rate(&self) -> Option<f64> {
        if let Some(ext) = &self.tcp_info.extended
            && ext.tcpi_bytes_sent > 0
        {
            let rate = (ext.tcpi_bytes_retrans as f64 / ext.tcpi_bytes_sent as f64) * 100.0;
            return Some(rate);
        }
        None
    }

    /// Get delivery rate in bits per second
    ///
    /// Estimated throughput of the connection.
    /// Available on kernel 4.2+ (RHEL 8+).
    ///
    /// # Returns
    ///
    /// Delivery rate in bps, or None if not available
    #[inline]
    pub fn delivery_rate_bps(&self) -> Option<u64> {
        self.tcp_info
            .extended
            .as_ref()
            .map(|ext| ext.tcpi_delivery_rate)
    }

    /// Create TcpConnectionData from legacy ConnectionInfo and TcpMetrics (for compatibility)
    ///
    /// This constructor enables legacy code paths (like ss parsing) to create
    /// TcpConnectionData for use with modern APIs like assess_connection_health_v2().
    ///
    /// # Limitations
    ///
    /// This creates a "synthetic" TcpInfo structure by reverse-engineering from
    /// TcpMetrics. Some data loss occurs because:
    /// - TcpMetrics stores RTT in milliseconds, TcpInfo uses microseconds (precision loss)
    /// - Many TcpInfo fields not present in TcpMetrics (set to 0)
    /// - Extended metrics may be missing (depends on TcpMetrics optional fields)
    ///
    /// # Why This Exists
    ///
    /// Allows gradual migration from old API to new API:
    /// 1. Legacy ss path continues to parse into TcpMetrics
    /// 2. Convert TcpMetrics → TcpConnectionData using this function
    /// 3. Use new assess_connection_health_v2() with unified API
    ///
    /// # Recommended Migration Path
    ///
    /// - **Short term**: Use this for legacy_ss compatibility
    /// - **Long term**: Parse ss output directly into TcpConnectionData (skip TcpMetrics)
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use cerberus::{ConnectionInfo, TcpMetrics};
    /// # use cerberus::netlink::TcpConnectionData;
    /// // Legacy code that parses ss output
    /// let metrics = cerberus::output_parsing(&ss_output)?;
    /// let conn_info = ConnectionInfo { /* ... */ };
    ///
    /// // Convert to TcpConnectionData for new API
    /// let conn_data = TcpConnectionData::from_connection_info_and_metrics(&conn_info, &metrics);
    ///
    /// // Now can use modern health assessment
    /// let health = cerberus::assess_connection_health_v2(&conn_data, &remote_addr, None);
    /// # Ok::<(), String>(())
    /// ```
    pub fn from_connection_info_and_metrics(
        conn_info: &crate::ConnectionInfo,
        metrics: &crate::TcpMetrics,
    ) -> Self {
        use crate::netlink::tcp_info::{TcpInfo, TcpInfoBasic, TcpInfoExtended};

        // Build TcpInfoBasic from TcpMetrics
        // Note: ms → μs conversion (multiply by 1000)
        let basic = TcpInfoBasic {
            // === State and options (8 bytes) ===
            tcpi_state: conn_info.state_code, // Already a u8
            tcpi_ca_state: 0,                 // Unknown
            tcpi_retransmits: 0,
            tcpi_probes: 0,
            tcpi_backoff: 0,
            tcpi_options: 0,
            tcpi_snd_wscale: 0, // Combined snd/rcv scale in low/high bits
            tcpi_delivery_rate_app_limited: 0,

            // === Timeouts (8 bytes) ===
            tcpi_rto: 0,
            tcpi_ato: 0,

            // === MSS (8 bytes) ===
            tcpi_snd_mss: 0,
            tcpi_rcv_mss: 0,

            // === Packet counts (20 bytes) ===
            tcpi_unacked: metrics.unacked_packets,
            tcpi_sacked: 0, // SACK packets - not available in TcpMetrics, default to 0
            tcpi_lost: metrics.lost_packets.unwrap_or(0), // Lost packets count
            tcpi_retrans: metrics.retrans_events,
            tcpi_fackets: 0,

            // === Times (16 bytes) ===
            tcpi_last_data_sent: metrics.last_data_sent_ms.unwrap_or(0),
            tcpi_last_ack_sent: 0, // Time since last ACK sent - not available, default to 0
            tcpi_last_data_recv: 0,
            tcpi_last_ack_recv: 0,

            // === Core metrics (40 bytes) ===
            tcpi_pmtu: metrics.pmtu.unwrap_or(0),
            tcpi_rcv_ssthresh: 0,
            tcpi_rtt: (metrics.rtt_ms * 1000.0) as u32, // Convert ms → μs
            tcpi_rttvar: (metrics.rtt_var_ms * 1000.0) as u32, // Convert ms → μs
            tcpi_snd_ssthresh: metrics
                .snd_ssthresh
                .unwrap_or(metrics.congestion_window * 2),
            tcpi_snd_cwnd: metrics.congestion_window,
            tcpi_advmss: 0,
            tcpi_reordering: 0,
            tcpi_rcv_rtt: 0,
            tcpi_rcv_space: 0,

            // === Total retransmits (4 bytes) ===
            tcpi_total_retrans: metrics.total_retrans.unwrap_or(0),
        };

        // Build TcpInfoExtended if we have extended metrics
        let extended = if metrics.min_rtt_ms.is_some()
            || metrics.delivery_rate_bps.is_some()
            || metrics.lost_packets.is_some()
        {
            Some(TcpInfoExtended {
                // RTT metrics
                tcpi_min_rtt: metrics
                    .min_rtt_ms
                    .map(|ms| (ms * 1000.0) as u32)
                    .unwrap_or(0),

                // Rate metrics (convert to  correct units if needed)
                tcpi_delivery_rate: metrics.delivery_rate_bps.unwrap_or(0),
                tcpi_pacing_rate: 0,     // Not in TcpMetrics
                tcpi_max_pacing_rate: 0, // Not in TcpMetrics

                // Byte counters
                tcpi_bytes_sent: metrics.bytes_sent,
                tcpi_bytes_retrans: metrics.bytes_retrans,
                tcpi_bytes_acked: 0,    // Not in TcpMetrics
                tcpi_bytes_received: 0, // Not in TcpMetrics

                // Bottleneck detection
                // Note: tcpi_lost and tcpi_retrans are in TcpInfoBasic, not extended
                tcpi_busy_time: metrics.busy_time_us.unwrap_or(0),
                tcpi_rwnd_limited: metrics.rwnd_limited_us.unwrap_or(0),
                tcpi_sndbuf_limited: metrics.sndbuf_limited_us.unwrap_or(0),

                // Delivery metrics
                tcpi_delivered: 0,
                tcpi_delivered_ce: 0,

                // SegsIn / SegsOut
                tcpi_segs_out: 0,
                tcpi_segs_in: 0,

                // Additional metrics
                tcpi_notsent_bytes: 0,
                tcpi_data_segs_in: 0,
                tcpi_data_segs_out: 0,

                // DSack metrics (not in TcpMetrics)
                tcpi_dsack_dups: 0,
                tcpi_reord_seen: 0,
                tcpi_rcv_ooopack: 0,
                tcpi_snd_wnd: 0,
            })
        } else {
            None
        };

        let tcp_info = TcpInfo { basic, extended };

        TcpConnectionData {
            tcp_info,
            send_queue_bytes: conn_info.send_queue_bytes,
            recv_queue_bytes: conn_info.recv_queue_bytes,
            tcp_state: conn_info.state_code, // Already a u8 (1 = ESTABLISHED)
        }
    }
}

// ============================================================================
// QUERY FUNCTIONS
// ============================================================================

/// Query single TCP connection by 4-tuple (local IP:port, remote IP:port)
///
/// This performs a fast, direct kernel lookup for a specific connection.
/// The kernel returns only the matching connection (not all connections).
///
/// # Performance
///
/// - Typical latency: 0.1-0.5 ms
/// - Much faster than `ss` command subprocess (5-15 ms)
/// - No intermediate parsing or filtering needed
///
/// # Parameters
///
/// * `local_ip` - Local IP address (e.g., "192.168.1.5")
/// * `local_port` - Local port number (e.g., 8080)
/// * `remote_ip` - Remote IP address (e.g., "10.0.1.1")
/// * `remote_port` - Remote port number (e.g., 5000)
///
/// # Returns
///
/// * `Ok(TcpInfo)` - Connection found, tcp_info returned
/// * `Err(InetDiagError::NotFound)` - Connection doesn't exist
/// * `Err(InetDiagError::PermissionDenied)` - Need root (RHEL 7)
/// * `Err(...)` - Other errors
///
/// # Example
///
/// ```no_run
/// # use cerberus::netlink::inet_diag::query_tcp_connection;
/// let tcp_info = query_tcp_connection("192.168.1.5", 8080, "10.0.1.1", 5000)?;
///
/// println!("Connection found!");
/// println!("RTT: {:.2} ms", tcp_info.basic.tcpi_rtt as f64 / 1000.0);
/// println!("Congestion window: {} packets", tcp_info.basic.tcpi_snd_cwnd);
///
/// if let Some(ext) = tcp_info.extended {
///     println!("Bytes sent: {}", ext.tcpi_bytes_sent);
/// }
/// # Ok::<(), cerberus::netlink::inet_diag::InetDiagError>(())
/// ```
///
/// # Platform Support
///
/// - RHEL 7: Requires root or CAP_NET_ADMIN capability
/// - RHEL 8/9: Works without root
pub fn query_tcp_connection(
    local_ip: &str,
    local_port: u16,
    remote_ip: &str,
    remote_port: u16,
) -> Result<TcpConnectionData, InetDiagError> {
    // === STEP 1: Parse IP addresses ===
    //
    // Convert string IP addresses to Ipv4Addr structures.
    // This validates the IP format and converts to binary representation.
    let local_addr: Ipv4Addr = local_ip.parse().map_err(|e| {
        InetDiagError::Other(format!("Invalid local IP address '{}': {}", local_ip, e))
    })?;

    let remote_addr: Ipv4Addr = remote_ip.parse().map_err(|e| {
        InetDiagError::Other(format!("Invalid remote IP address '{}': {}", remote_ip, e))
    })?;

    // === STEP 2: Create Netlink socket ===
    //
    // This opens AF_NETLINK socket, binds to kernel, sets options.
    // May fail if:
    // - No permission (RHEL 7 needs root)
    // - System resources exhausted
    let socket = NetlinkSocket::new()?;

    // === STEP 3: Build socket ID for exact match ===
    //
    // This creates InetDiagSockId with all 4 tuple values filled in.
    // Kernel will match EXACTLY this connection (not similar ones).
    let sock_id = build_exact_socket_id(local_addr, local_port, remote_addr, remote_port);

    // === STEP 4: Build INET_DIAG request ===
    //
    // Request parameters:
    // - sdiag_family: AF_INET (IPv4)
    // - sdiag_protocol: IPPROTO_TCP (TCP)
    // - idiag_ext: Request tcp_info attribute (bit 1 set)
    // - idiag_states: Only ESTABLISHED connections (bit 1 set)
    // - id: Exact socket to match
    let req = InetDiagReqV2 {
        sdiag_family: AF_INET,
        sdiag_protocol: IPPROTO_TCP,
        idiag_ext: (1 << (INET_DIAG_INFO - 1)), // Request INET_DIAG_INFO attribute
        pad: 0,
        idiag_states: 1 << TCP_ESTABLISHED, // Only ESTABLISHED state
        id: sock_id,
    };

    // Build message bytes
    let request = build_inet_diag_request(&req, 1);

    // === STEP 5: Send request to kernel ===
    //
    // This performs sendto() syscall to Netlink socket.
    // May fail if:
    // - Socket closed
    // - Kernel not responding
    socket.send(&request)?;

    // === STEP 6: Receive response ===
    //
    // This performs recv() syscall(s) to get all response messages.
    // Handles multi-part responses (though single query typically returns 1-2 messages).
    let response = socket.recv_all()?;

    // === STEP 7: Parse response messages ===
    //
    // Converts raw bytes to ParsedMessage enum.
    // Response can contain:
    // - InetDiag message (connection found)
    // - Done message (end of multi-part)
    // - Error message (not found, permission denied, etc.)
    let messages = parse_netlink_messages(&response)?;

    // === STEP 8: Find connection in response ===
    //
    // Iterate through messages looking for InetDiag with our connection.
    for msg in messages {
        match msg {
            ParsedMessage::InetDiag { msg, attributes } => {
                // Found a connection! Extract tcp_info from attributes.
                //
                // Attributes is HashMap<u16, Vec<u8>> where:
                // - Key: INET_DIAG_INFO (2)
                // - Value: tcp_info bytes
                if let Some(tcp_info) = extract_tcp_info_from_attributes(&attributes)? {
                    // === CAPTURE QUEUE SIZES AND STATE ===
                    // The InetDiagMsg contains queue sizes and TCP state
                    // that were previously thrown away. Now we capture them!
                    //
                    // msg.idiag_wqueue: Write queue (bytes waiting to be sent)
                    // msg.idiag_rqueue: Read queue (bytes waiting to be read)
                    // msg.idiag_state: TCP connection state (1=ESTABLISHED, etc.)
                    return Ok(TcpConnectionData {
                        tcp_info,
                        send_queue_bytes: msg.idiag_wqueue,
                        recv_queue_bytes: msg.idiag_rqueue,
                        tcp_state: msg.idiag_state,
                    });
                }
            }

            ParsedMessage::Error(errno) => {
                // Kernel returned error
                //
                // Common errno values:
                // - ENOENT (2): Connection not found
                // - EACCES (13): Permission denied
                match errno {
                    2 => return Err(InetDiagError::NotFound),          // ENOENT
                    13 => return Err(InetDiagError::PermissionDenied), // EACCES
                    0 => {}                                            // ACK, not an error
                    _ => {
                        return Err(InetDiagError::Other(format!(
                            "Kernel returned error: errno {}",
                            errno
                        )));
                    }
                }
            }

            ParsedMessage::Done => {
                // End of messages, no match found
                break;
            }
        }
    }

    // No connection found in response
    Err(InetDiagError::NotFound)
}

/// Query multiple TCP connections efficiently in batch
///
/// This queries all connections from a local socket and filters to the
/// requested remote addresses. More efficient than calling query_tcp_connection()
/// multiple times.
///
/// # Strategy
///
/// 1. Build request with local IP:port, wildcard remote (dump all from local socket)
/// 2. Send one request to kernel
/// 3. Kernel returns all connections from that local socket
/// 4. Filter results to match requested remote addresses
/// 5. Return HashMap of matching connections
///
/// # Performance
///
/// - One kernel query instead of N queries
/// - Typical latency: 0.5-2 ms for 100 connections
/// - 10-20x faster than multiple subprocess `ss` calls
///
/// # Parameters
///
/// * `connections` - Slice of (local_ip, local_port, remote_ip, remote_port) tuples
///
/// # Returns
///
/// HashMap mapping connection tuple → TcpInfo
///
/// # Example
///
/// ```no_run
/// # use cerberus::netlink::inet_diag::query_tcp_connections_batch;
/// let connections = vec![
///     ("192.168.1.5".to_string(), 8080, "10.0.1.1".to_string(), 5000),
///     ("192.168.1.5".to_string(), 8080, "10.0.1.2".to_string(), 5001),
///     ("192.168.1.5".to_string(), 8080, "10.0.1.3".to_string(), 5002),
/// ];
///
/// let results = query_tcp_connections_batch(&connections)?;
///
/// for (conn, tcp_info) in results {
///     println!("{}:{} -> {}:{} : RTT = {} μs",
///         conn.0, conn.1, conn.2, conn.3,
///         tcp_info.basic.tcpi_rtt);
/// }
/// # Ok::<(), cerberus::netlink::inet_diag::InetDiagError>(())
/// ```
pub fn query_tcp_connections_batch(
    connections: &[(String, u16, String, u16)],
) -> Result<HashMap<(String, u16, String, u16), TcpConnectionData>, InetDiagError> {
    // === Early exit if no connections ===
    if connections.is_empty() {
        return Ok(HashMap::new());
    }

    // === Determine local socket from first connection ===
    //
    // All connections should have same local IP:port (that's the point of batch query).
    // We query all connections from this local socket, then filter.
    let (local_ip, local_port, _, _) = &connections[0];

    let local_addr: Ipv4Addr = local_ip.parse().map_err(|e| {
        InetDiagError::Other(format!("Invalid local IP address '{}': {}", local_ip, e))
    })?;

    // === Create socket ===
    let socket = NetlinkSocket::new()?;

    // === Build request for local socket (wildcard remote) ===
    //
    // This requests all connections from local_ip:local_port to any remote.
    // Kernel will send back all matching connections.
    let sock_id = build_local_socket_id(local_addr, *local_port);

    let req = InetDiagReqV2 {
        sdiag_family: AF_INET,
        sdiag_protocol: IPPROTO_TCP,
        idiag_ext: (1 << (INET_DIAG_INFO - 1)),
        pad: 0,
        idiag_states: 1 << TCP_ESTABLISHED, // Only ESTABLISHED
        id: sock_id,
    };

    let request = build_inet_diag_request(&req, 1);

    // === Send request and receive response ===
    socket.send(&request)?;
    let response = socket.recv_all()?;

    // === Parse response messages ===
    let messages = parse_netlink_messages(&response)?;

    // === Build set of requested remote addresses for fast lookup ===
    //
    // We use a HashSet for O(1) lookup instead of Vec O(n) contains().
    // With 100 connections, this is 100x faster!
    let mut requested_remotes = std::collections::HashSet::new();
    for (_, _, remote_ip, remote_port) in connections {
        requested_remotes.insert((remote_ip.clone(), *remote_port));
    }

    // === Extract matching connections ===
    let mut results = HashMap::new();

    for msg in messages {
        match msg {
            ParsedMessage::InetDiag { msg, attributes } => {
                // Extract remote address from InetDiagMsg
                let remote_ip = extract_ipv4_from_socket_id(&msg.id, false);
                let remote_port = u16::from_be(msg.id.idiag_dport);

                // Check if this is one of the requested connections
                if requested_remotes.contains(&(remote_ip.clone(), remote_port)) {
                    // Extract tcp_info
                    if let Some(tcp_info) = extract_tcp_info_from_attributes(&attributes)? {
                        let key = (local_ip.clone(), *local_port, remote_ip, remote_port);

                        // === CAPTURE QUEUE SIZES AND STATE ===
                        // Build TcpConnectionData with all information
                        let conn_data = TcpConnectionData {
                            tcp_info,
                            send_queue_bytes: msg.idiag_wqueue,
                            recv_queue_bytes: msg.idiag_rqueue,
                            tcp_state: msg.idiag_state,
                        };

                        results.insert(key, conn_data);
                    }
                }
            }

            ParsedMessage::Error(errno) => {
                // Handle error
                match errno {
                    13 => return Err(InetDiagError::PermissionDenied),
                    0 => {} // ACK
                    _ => {
                        return Err(InetDiagError::Other(format!(
                            "Kernel returned error: errno {}",
                            errno
                        )));
                    }
                }
            }

            ParsedMessage::Done => break,
        }
    }

    Ok(results)
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/// Extract tcp_info from attributes HashMap
///
/// Looks for INET_DIAG_INFO attribute and parses tcp_info structure.
///
/// # Parameters
///
/// * `attrs` - Attributes HashMap from ParsedMessage::InetDiag
///
/// # Returns
///
/// * `Ok(Some(TcpInfo))` - tcp_info found and parsed
/// * `Ok(None)` - No INET_DIAG_INFO attribute (shouldn't happen if we requested it)
/// * `Err(...)` - Parse error
fn extract_tcp_info_from_attributes(
    attrs: &HashMap<u16, Vec<u8>>,
) -> Result<Option<TcpInfo>, InetDiagError> {
    // Look for INET_DIAG_INFO attribute (type = 2)
    if let Some(tcp_info_bytes) = attrs.get(&INET_DIAG_INFO) {
        // Parse tcp_info structure from bytes
        let tcp_info = parse_tcp_info(tcp_info_bytes)?;
        Ok(Some(tcp_info))
    } else {
        // No tcp_info attribute
        // This can happen if we didn't request it in idiag_ext
        Ok(None)
    }
}

/// Extract IPv4 address from InetDiagSockId
///
/// Converts binary IPv4 address (u32 in network byte order) to string.
///
/// # Parameters
///
/// * `sock_id` - Socket ID structure
/// * `is_source` - True for source address, false for destination
///
/// # Returns
///
/// IP address as string (e.g., "192.168.1.5")
fn extract_ipv4_from_socket_id(sock_id: &InetDiagSockId, is_source: bool) -> String {
    // IPv4 addresses are stored in first element of idiag_src/idiag_dst arrays
    // in network byte order (big-endian)
    let ip_u32 = if is_source {
        u32::from_be(sock_id.idiag_src[0])
    } else {
        u32::from_be(sock_id.idiag_dst[0])
    };

    // Convert to Ipv4Addr
    let ip = Ipv4Addr::from(ip_u32);
    ip.to_string()
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_ipv4() {
        // Build a socket ID with known IP addresses
        let sock_id = build_exact_socket_id(
            Ipv4Addr::new(192, 168, 1, 100),
            8080,
            Ipv4Addr::new(10, 0, 1, 5),
            5000,
        );

        // Extract source address
        let src_ip = extract_ipv4_from_socket_id(&sock_id, true);
        assert_eq!(src_ip, "192.168.1.100");

        // Extract destination address
        let dst_ip = extract_ipv4_from_socket_id(&sock_id, false);
        assert_eq!(dst_ip, "10.0.1.5");
    }

    // Note: Integration tests that actually call kernel are not included
    // here because they require:
    // 1. Running on Linux
    // 2. Having actual TCP connections to query
    // 3. Possibly root permissions (RHEL 7)
    //
    // These should be tested manually or in integration test suite.
}
