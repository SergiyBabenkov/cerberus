// ============================================================================
// TCP Connection Health Monitoring Library
// ============================================================================
//
// Core functionality:
// - Discover TCP connections: Parse /proc/net/tcp on Linux
// - Query TCP metrics: Use Netlink INET_DIAG (recommended) or ss command (legacy)
// - Assess health: Evaluate queue accumulation, retransmissions, RTT, trends
// - Track history: Detect degradation patterns and stale connections
//
// Recommended API: get_tcp_connection_data_via_netlink() → assess_connection_health_v2()

use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::fmt::Write;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::{IpAddr, Ipv4Addr};

#[cfg(feature = "legacy_ss")]
use std::collections::{HashMap, HashSet};
#[cfg(feature = "legacy_ss")]
use std::process::{Command, Stdio};

#[cfg(all(target_os = "linux", feature = "netlink"))]
use std::collections::HashMap;

pub mod connection_history;
pub use connection_history::{ConnectionHistory, HistoryManager, QueueSample, TrendMetrics};

pub mod netlink;

// ============================================================================
// CONSTANTS: Health Assessment Thresholds
// ============================================================================

/// Queue size thresholds. These detect message delivery problems in systems
/// with typical message sizes of 1-2KB per message.
pub const SEND_QUEUE_CRITICAL: u32 = 4096; // ≥2 messages stuck; connection likely broken
pub const SEND_QUEUE_WARNING: u32 = 2048; // ≥1 message stuck; degraded delivery
pub const SEND_QUEUE_SUSPECT: u32 = 1024; // Partial message stuck; worth monitoring

pub const DEFAULT_HTTP_PORT: u16 = 8888;
pub const MAX_CONNECTIONS: usize = 100;

/// TCP state codes from Linux kernel. Used to match connection states
/// from /proc/net/tcp format.
pub const TCP_ESTABLISHED: u8 = 0x01;
pub const TCP_SYN_SENT: u8 = 0x02;
pub const TCP_SYN_RECV: u8 = 0x03;
pub const TCP_FIN_WAIT1: u8 = 0x04;
pub const TCP_FIN_WAIT2: u8 = 0x05;
pub const TCP_TIME_WAIT: u8 = 0x06;
pub const TCP_CLOSE: u8 = 0x07;
pub const TCP_CLOSE_WAIT: u8 = 0x08;
pub const TCP_LAST_ACK: u8 = 0x09;
pub const TCP_LISTEN: u8 = 0x0A;
pub const TCP_CLOSING: u8 = 0x0B;

// ============================================================================
// DATA STRUCTURES: TCP Connection Information
// ============================================================================

/// Basic TCP connection information from /proc/net/tcp.
/// Contains socket addresses and queue states, but not detailed TCP metrics.
/// Use with `get_tcp_connection_data_via_netlink()` for complete information.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ConnectionInfo {
    /// Local socket address (IP:port), e.g., "192.168.1.5:8080"
    pub local_address: String,
    /// Remote socket address (IP:port), e.g., "10.0.1.1:5000"
    pub remote_address: String,
    /// Human-readable state: "ESTABLISHED", "`TIME_WAIT`", "LISTEN", etc.
    pub state: String,
    /// Numeric TCP state code (0x01, 0x06, etc.)
    pub state_code: u8,
    /// Bytes waiting to be transmitted. High value = sender stalled.
    /// Compare against `SEND_QUEUE_CRITICAL`, `SEND_QUEUE_WARNING` for health assessment.
    pub send_queue_bytes: u32,
    /// Bytes received but not yet read by application.
    /// Usually low unless receiver is slow or buffer is full.
    pub recv_queue_bytes: u32,
}

// ============================================================================
// DATA STRUCTURES: TCP Metrics from Kernel
// ============================================================================

/// Low-level TCP metrics extracted from kernel `tcp_info` structure.
/// These metrics are the foundation for connection health assessment.
/// Available from both Netlink `INET_DIAG` (modern, 0.1-0.5ms) and ss command (legacy, 5-15ms).
///
/// Extended fields are optional and depend on kernel version:
/// - Kernel 3.10 (RHEL 7): Core metrics only; `bytes_sent/bytes_retrans` may be 0
/// - Kernel 4.6+ (RHEL 8+): Most extended metrics available
/// - Kernel 4.9+ (RHEL 8+): Bottleneck detection metrics available
///
/// Use `assess_connection_health_v2()` for comprehensive evaluation combining these metrics.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TcpMetrics {
    // ========================================================================
    // CORE METRICS: Always available (kernel 3.10+)
    // ========================================================================
    /// Round-trip time in milliseconds (time for data to travel to remote and back).
    /// Health indicators:
    /// - < 50ms: Excellent (local/fast link)
    /// - 50-200ms: Good (typical WAN)
    /// - 200-500ms: Acceptable (distant networks)
    /// - > 500ms: Concerning (latency adds up with retransmissions)
    /// - > 1000ms: Problematic (high risk of timeouts)
    pub rtt_ms: f64,

    /// RTT variance (standard deviation of RTT samples).
    /// Health indicators:
    /// - Low variance: Stable path, predictable latency
    /// - High variance: Network congestion, routing changes, packet prioritization
    ///   Interpretation: If `rtt_var_ms` is > 50% of `rtt_ms`, path is unstable
    pub rtt_var_ms: f64,

    /// Total bytes successfully sent on this connection (cumulative counter).
    /// Note: May be 0 on kernel 3.10 if field not available in that version
    /// Use case: Detect if connection is actually transmitting data or idle
    pub bytes_sent: u64,

    /// Bytes that had to be retransmitted due to packet loss.
    /// Health indicators:
    /// - 0: No packet loss detected (excellent)
    /// - > 0: Packet loss occurred (poor network quality)
    /// - High value: Persistent network issues or congestion
    ///   Interpretation: Compare to `bytes_sent` to calculate loss rate
    pub bytes_retrans: u64,

    /// Send congestion window size (in packets, not bytes).
    /// This is TCP's flow control: limits how many unacked packets can be in flight.
    /// Health indicators:
    /// - < 3: Connection just started (slow start) or severely congested
    /// - 10-50: Normal range for typical connections
    /// - > 100: High-bandwidth connection operating efficiently
    ///   > Interpretation: Compare cwnd to unacked_packets (high ratio = congestion)
    pub congestion_window: u32,

    /// Number of packets sent but not yet acknowledged.
    /// Health indicators:
    /// - 0: No packets in flight (idle or just finished)
    /// - 1-5: Normal data exchange
    /// - > cwnd: NOT POSSIBLE (violates TCP flow control; indicates kernel issue)
    /// - > 0 AND send_queue > 0: Stalling (sender waiting for ACKs)
    pub unacked_packets: u32,

    /// Count of retransmission events (separate from `bytes_retrans`).
    /// This counts HOW MANY TIMES TCP had to resend, not the total bytes.
    /// Health indicators:
    /// - 0: No retransmissions
    /// - > 0: Packet loss occurred; connection may be recovering
    ///   > Note: This is current state; may be 0 even if connection had retrans earlier
    pub retrans_events: u32,

    // ========================================================================
    // EXTENDED METRICS: Optional, kernel version dependent
    // ========================================================================
    /// Minimum RTT observed on this connection (milliseconds, kernel 4.6+).
    /// Health indicators:
    /// - Establishes baseline latency for this path
    /// - (`rtt_ms` - `min_rtt_ms`) = current latency overhead due to congestion
    ///   Interpretation: If current RTT >> `min_rtt`, congestion is adding delay
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_rtt_ms: Option<f64>,

    /// Actual data delivery rate (bytes/second, kernel 4.6+).
    /// This is the throughput TCP is currently achieving, NOT the link capacity.
    /// Health indicators:
    /// - High value: Connection using bandwidth efficiently
    /// - Low value: Congestion, packet loss, or receiver slow to read data
    ///   Interpretation: Compare to application requirements to detect bottlenecks
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delivery_rate_bps: Option<u64>,

    /// Total packets lost (cumulative, kernel 3.10+).
    /// Unlike `bytes_retrans`, this counts packets (not bytes retransmitted).
    /// Health indicators:
    /// - 0: No packet loss
    /// - > 0: Network quality issues
    ///   > Interpretation: High lost_packets / bytes_sent = poor link quality
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lost_packets: Option<u32>,

    /// Time blocked waiting for receiver's window (microseconds, kernel 4.9+).
    /// Receiver window = buffer space on remote host. High value means:
    /// - Receiver's buffer is full
    /// - Receiver application is slow to read data
    ///   NOT a sender problem - receiver is the bottleneck
    ///   Health indicators:
    /// - 0: Receiver always has buffer space
    /// - > 0: Receiver is slow; tune receiver buffer or app
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rwnd_limited_us: Option<u64>,

    /// Time blocked waiting for sender's buffer (microseconds, kernel 4.9+).
    /// Sender's buffer gets full when application doesn't provide data fast enough.
    /// This is an APPLICATION BOTTLENECK, not a network problem.
    /// Health indicators:
    /// - 0: Application producing data faster than network can send
    /// - > 0: Application is slow (CPU-bound, I/O-bound, or overloaded)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sndbuf_limited_us: Option<u64>,

    /// Cumulative time this connection actively transmitted (microseconds, kernel 4.9+).
    /// Useful for calculating connection utilization.
    /// Utilization = `busy_time_us` / `connection_lifetime_us`
    /// Health indicators:
    /// - High utilization (90%+): Connection constantly sending; may be saturated
    /// - Medium utilization (30-70%): Normal usage
    /// - Low utilization (<30%): Application not using connection much
    #[serde(skip_serializing_if = "Option::is_none")]
    pub busy_time_us: Option<u64>,

    /// Total retransmissions over entire connection lifetime (kernel 3.10+).
    /// Different from `retrans_events` (current state) - this is historical total.
    /// Health indicators:
    /// - 0: No retransmissions ever
    /// - > 0: Past packet loss events
    /// - High value: Persistent network issues
    ///   Interpretation: Use to assess overall connection quality over time
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_retrans: Option<u32>,

    /// Slow start threshold (in packets, kernel 3.10+).
    /// TCP's congestion control parameter.
    /// When cwnd > ssthresh, TCP switches from aggressive growth to conservative growth.
    /// Health indicators:
    /// - ssthresh > cwnd: Slow start mode (exponential growth)
    /// - ssthresh < cwnd: Congestion avoidance (linear growth)
    /// - ssthresh << cwnd: Recent packet loss (congestion); recovering
    /// - ssthresh very low (<5): Connection recently experienced congestion event
    ///   Interpretation: Low ssthresh + high unacked = connection struggling with congestion
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snd_ssthresh: Option<u32>,

    /// Milliseconds since last data transmission (kernel 3.10+).
    /// Identifies idle or inactive connections.
    /// Health indicators:
    /// - 0-100ms: Active transmission
    /// - 100-1000ms: Recent activity
    /// - > 1000ms: Connection idle or very slow
    /// - > 60000ms: Likely stale connection (should be closed)
    ///   > Use case: Detect zombie connections that haven't sent data in long time
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_data_sent_ms: Option<u32>,

    /// Path MTU (maximum transmission unit, kernel 3.10+).
    /// Maximum packet size without fragmentation on this path.
    /// Common values:
    /// - 1500: Standard Ethernet
    /// - 1492: `PPPoE` (8 bytes less for protocol header)
    /// - 9000: Jumbo frames (high-performance networks)
    /// - < 1500: Path includes tunnels, VPNs, or other constraints
    ///   Health impact: Lower MTU reduces throughput (more packets needed per byte)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pmtu: Option<u32>,
}

// ============================================================================
// DATA STRUCTURES: Health Assessment Results
// ============================================================================

/// Health assessment result for a connection.
/// Combines current metrics with optional historical trends for comprehensive
/// health determination. Used by API responses and monitoring dashboards.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HealthAssessment {
    /// Connection status: "HEALTHY" | "CAUTION" | "SUSPECT" | "DEGRADED" | "STALE"
    /// Determines safety for sending data on this connection
    pub status: String,
    /// Numeric health score (0 = healthy, higher = worse).
    /// Used internally for thresholding and sorting connections.
    pub score: i32,
    /// True if it's safe to send data on this connection
    pub safe_to_send: bool,
    /// Human-readable reasons explaining the assessment (semicolon-separated)
    pub reasons: String,
    /// Optional trend metrics from historical samples (shows degradation patterns)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trend_metrics: Option<TrendMetrics>,
}

/// Connection data paired with health assessment.
/// Used in API responses to return a complete picture of connection status.
#[derive(Debug, Serialize, Deserialize)]
pub struct ConnectionWithHealth {
    pub connection: ConnectionInfo,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tcp_metrics: Option<TcpMetrics>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub health: Option<HealthAssessment>,
}

// ============================================================================
// DATA STRUCTURES: HTTP API Request/Response
// ============================================================================

/// HTTP request for the /monitor endpoint.
/// Allows per-request specification of monitored local socket and filters.
/// This replaced startup configuration for better flexibility.
#[derive(Debug, Serialize, Deserialize)]
pub struct MonitorRequest {
    /// Local IP to monitor (required), e.g., "192.168.1.5"
    pub local_ip: String,
    /// Local port to monitor (required), e.g., 8080
    pub local_port: u16,
    /// Remote IP to query (required), e.g., "10.0.1.1"
    pub remote_ip: String,
    /// Remote port to filter (optional). Omit to query all remote ports.
    #[serde(default)]
    pub remote_port: Option<u16>,
    /// If true, return only ESTABLISHED connections (default: true)
    #[serde(default = "default_true")]
    pub established_only: bool,
    /// If true, sort results by health score descending (default: true)
    #[serde(default = "default_true")]
    pub sort_by_health: bool,
}

/// Helper: Default value provider for serde field defaults
#[must_use]
pub const fn default_true() -> bool {
    true
}

/// HTTP response for /monitor endpoint.
/// Enum variants handle both single and multiple connection responses.
/// Note: `TcpMetrics` is boxed (425 bytes → 8 byte pointer) to optimize enum size.
#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)]
pub enum MonitorResponse {
    /// Response for single connection query (when `remote_port` specified)
    Single {
        timestamp: u64,
        found: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        connection: Option<ConnectionInfo>,
        #[serde(skip_serializing_if = "Option::is_none")]
        tcp_metrics: Option<Box<TcpMetrics>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        health: Option<HealthAssessment>,
        #[serde(skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },
    /// Response for multiple connections query (when `remote_port` omitted)
    Multiple {
        timestamp: u64,
        count: usize,
        sorted_by_health: bool,
        connections: Vec<ConnectionWithHealth>,
        #[serde(skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },
}

/// Configuration information response for /config endpoint.
/// Advertises server capabilities and monitoring mode to clients.
#[derive(Debug, Serialize)]
pub struct ConfigResponse {
    pub http_server_info: String,
    pub monitor_per_request: bool,
}

// ============================================================================
// UTILITY FUNCTIONS: TCP State and Address Parsing
// ============================================================================

/// Convert TCP state code (0x01, 0x06, etc.) to human-readable name.
/// Necessary because /proc/net/tcp uses numeric codes; users expect names.
/// Inlined for performance in hot parsing loops.
#[inline]
#[must_use]
pub const fn get_tcp_state_name(state: u8) -> &'static str {
    match state {
        TCP_ESTABLISHED => "ESTABLISHED",
        TCP_SYN_SENT => "SYN_SENT",
        TCP_SYN_RECV => "SYN_RECV",
        TCP_FIN_WAIT1 => "FIN_WAIT1",
        TCP_FIN_WAIT2 => "FIN_WAIT2",
        TCP_TIME_WAIT => "TIME_WAIT",
        TCP_CLOSE => "CLOSE",
        TCP_CLOSE_WAIT => "CLOSE_WAIT",
        TCP_LAST_ACK => "LAST_ACK",
        TCP_LISTEN => "LISTEN",
        TCP_CLOSING => "CLOSING",
        _ => "UNKNOWN",
    }
}

/// Parse hexadecimal IP from /proc/net/tcp format to `IPv4Addr`.
/// /proc/net/tcp stores IP addresses in hex with little-endian byte order.
/// Example: "C0A80105" in /proc → 192.168.1.5 in dotted decimal
/// Internal helper for parsing connection data from kernel.
#[inline]
fn parse_hex_ipv4(hex_str: &str) -> Result<Ipv4Addr, String> {
    let ip_u32 =
        u32::from_str_radix(hex_str, 16).map_err(|e| format!("Failed to parse hex IP: {e}"))?;

    // Extract each byte (octet) from 32-bit integer in little-endian order
    let octets = [
        (ip_u32 & 0xFF) as u8,
        ((ip_u32 >> 8) & 0xFF) as u8,
        ((ip_u32 >> 16) & 0xFF) as u8,
        ((ip_u32 >> 24) & 0xFF) as u8,
    ];

    Ok(Ipv4Addr::from(octets))
}

/// Parse address from /proc/net/tcp format (hex:port) to (IP, port) tuple.
/// Example: "C0A80105:1F90" → (192.168.1.5, 8080)
/// Uses `split_once()` for efficiency (avoids heap allocation).
#[inline]
fn parse_proc_address(addr_str: &str) -> Result<(IpAddr, u16), String> {
    let (ip_str, port_str) = addr_str.split_once(':').ok_or("Invalid address format")?;
    let ip = parse_hex_ipv4(ip_str)?;
    let port =
        u16::from_str_radix(port_str, 16).map_err(|e| format!("Failed to parse port: {e}"))?;
    Ok((IpAddr::V4(ip), port))
}

// ============================================================================
// MAIN FUNCTIONS: Discover Connections from /proc/net/tcp
// ============================================================================

/// Find all TCP connections in /proc/net/tcp matching the specified 4-tuple filters.
/// Returns up to `MAX_CONNECTIONS` results. Critical for enumeration in monitoring queries.
///
/// Optimized with early filtering to avoid expensive parsing on non-matching lines:
/// 1. Check TCP state first (cheapest comparison)
/// 2. Parse and check local socket (most lines won't match)
/// 3. Only parse remote socket if local matches
/// 4. Exit early when limit reached
///
/// This optimization significantly improves performance when /proc/net/tcp has thousands
/// of connections and most don't match the requested local socket.
pub fn find_connections_in_proc(
    local_ip: &str,
    local_port: u16,
    remote_ip: Option<&str>,
    established_only: bool,
) -> Result<Vec<ConnectionInfo>, String> {
    let file =
        File::open("/proc/net/tcp").map_err(|e| format!("Cannot open /proc/net/tcp: {e}"))?;

    let reader = BufReader::new(file);

    // Pre-allocate to avoid reallocations during initial growth
    let mut connections: Vec<ConnectionInfo> = Vec::with_capacity(16);

    for (line_num, line) in reader.lines().enumerate() {
        if line_num == 0 {
            continue; // Skip header line
        }

        let line = line.map_err(|e| format!("Failed to read line: {e}"))?;
        let fields: Vec<&str> = line.split_whitespace().collect();

        if fields.len() < 5 {
            continue;
        }

        // Optimization 1: Check state first (avoids parsing addresses on mismatches)
        if established_only {
            let state = u8::from_str_radix(fields[3], 16).unwrap_or(0);
            if state != TCP_ESTABLISHED {
                continue;
            }
        }

        // Optimization 2: Parse local address before remote (faster fail)
        let (parsed_local_ip, parsed_local_port) = parse_proc_address(fields[1])?;
        if parsed_local_ip.to_string() != local_ip || parsed_local_port != local_port {
            continue;
        }

        // Optimization 3: Only parse remote if local matched
        let (parsed_remote_ip, parsed_remote_port) = parse_proc_address(fields[2])?;

        // Apply remote IP filter if specified
        if let Some(remote) = remote_ip
            && parsed_remote_ip.to_string() != remote
        {
            continue;
        }

        let state = u8::from_str_radix(fields[3], 16).unwrap_or(0);

        let (send_str, recv_str) = fields[4].split_once(':').unwrap_or((fields[4], "0"));
        let send_queue = u32::from_str_radix(send_str, 16).unwrap_or(0);
        let recv_queue = u32::from_str_radix(recv_str, 16).unwrap_or(0);

        connections.push(ConnectionInfo {
            local_address: format!("{local_ip}:{local_port}"),
            remote_address: format!("{parsed_remote_ip}:{parsed_remote_port}"),
            state: get_tcp_state_name(state).to_string(),
            state_code: state,
            send_queue_bytes: send_queue,
            recv_queue_bytes: recv_queue,
        });

        if connections.len() >= MAX_CONNECTIONS {
            break;
        }
    }

    Ok(connections)
}

/// Find a single TCP connection matching the exact 4-tuple (local IP:port, remote IP:port).
/// Returns immediately when found instead of reading entire /proc/net/tcp.
/// Critical for single-connection monitoring queries requiring low latency.
pub fn find_single_connection(
    local_ip: &str,
    local_port: u16,
    remote_ip: &str,
    remote_port: u16,
    established_only: bool,
) -> Result<ConnectionInfo, String> {
    let file =
        File::open("/proc/net/tcp").map_err(|e| format!("Cannot open /proc/net/tcp: {e}"))?;

    let reader = BufReader::new(file);
    let target_remote = format!("{remote_ip}:{remote_port}");

    for (line_num, line) in reader.lines().enumerate() {
        if line_num == 0 {
            continue;
        }

        let line = line.map_err(|e| format!("Failed to read line: {e}"))?;
        let fields: Vec<&str> = line.split_whitespace().collect();

        if fields.len() < 5 {
            continue;
        }

        // Check state first (early filter for performance)
        if established_only {
            let state = u8::from_str_radix(fields[3], 16).unwrap_or(0);
            if state != TCP_ESTABLISHED {
                continue;
            }
        }

        let (parsed_local_ip, parsed_local_port) = parse_proc_address(fields[1])?;
        if parsed_local_ip.to_string() != local_ip || parsed_local_port != local_port {
            continue;
        }

        let (parsed_remote_ip, parsed_remote_port) = parse_proc_address(fields[2])?;

        if parsed_remote_ip.to_string() == remote_ip && parsed_remote_port == remote_port {
            // Found the target connection
            let state = u8::from_str_radix(fields[3], 16).unwrap_or(0);

            let (send_str, recv_str) = fields[4].split_once(':').unwrap_or((fields[4], "0"));
            let send_queue = u32::from_str_radix(send_str, 16).unwrap_or(0);
            let recv_queue = u32::from_str_radix(recv_str, 16).unwrap_or(0);

            return Ok(ConnectionInfo {
                local_address: format!("{local_ip}:{local_port}"),
                remote_address: target_remote,
                state: get_tcp_state_name(state).to_string(),
                state_code: state,
                send_queue_bytes: send_queue,
                recv_queue_bytes: recv_queue,
            });
        }
    }

    Err("Connection not found".to_string())
}

// ============================================================================
// LEGACY SS IMPLEMENTATION: Subprocess-based metrics (fallback)
// ============================================================================

/// Parse 'ss' command output to extract TCP metrics.
/// Legacy implementation (5-15ms latency). Prefer Netlink path (0.1-0.5ms) for production.
/// Exists for compatibility with systems lacking Netlink INET_DIAG support.
#[cfg(feature = "legacy_ss")]
fn output_parsing(output_str: &str) -> Result<TcpMetrics, String> {
    let lines: Vec<&str> = output_str.lines().collect();

    if lines.len() < 2 {
        return Err("ss output has insufficient lines".to_string());
    }

    let mut metrics = TcpMetrics {
        rtt_ms: 0.0,
        rtt_var_ms: 0.0,
        bytes_sent: 0,
        bytes_retrans: 0,
        congestion_window: 0,
        unacked_packets: 0,
        retrans_events: 0,
        min_rtt_ms: None,
        delivery_rate_bps: None,
        lost_packets: None,
        rwnd_limited_us: None,
        sndbuf_limited_us: None,
        busy_time_us: None,
        total_retrans: None,
        snd_ssthresh: None,
        last_data_sent_ms: None,
        pmtu: None,
    };

    // Parse ss output using iterator chain (zero-cost abstraction).
    // Lazy evaluation enables compiler to optimize into single pass.
    let parsed_ss_output: HashMap<String, String> = output_str
        .lines()
        .skip(2) // Skip header lines
        .flat_map(|line| {
            line.split_whitespace().map(|field| {
                // Extract "key:value" fields; standalone words become key=value pairs
                if let Some((key, value)) = field.split_once(':') {
                    (key.to_string(), value.to_string())
                } else {
                    (field.to_string(), field.to_string())
                }
            })
        })
        .collect();

    // Extract metrics using Option chaining pattern:
    // .get() → .and_then() → .unwrap_or() for safe defaults
    metrics.bytes_sent = parsed_ss_output
        .get("bytes_sent")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    metrics.bytes_retrans = parsed_ss_output
        .get("bytes_retrans")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    metrics.congestion_window = parsed_ss_output
        .get("cwnd")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    metrics.unacked_packets = parsed_ss_output
        .get("unacked")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    metrics.retrans_events = parsed_ss_output
        .get("retrans")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    // Parse RTT in "value/variance" format
    if let Some((rtt_val, rtt_var)) = parsed_ss_output
        .get("rtt")
        .and_then(|rtt| rtt.split_once('/'))
    {
        metrics.rtt_ms = rtt_val.parse().unwrap_or(0.0);
        metrics.rtt_var_ms = rtt_var.parse().unwrap_or(0.0);
    }

    Ok(metrics)
}

/// Get TCP metrics from 'ss' command for a single connection.
/// Legacy fallback implementation. Use get_tcp_connection_data_via_netlink() instead.
/// Performance: 5-15ms (subprocess spawn + output parsing overhead).
#[cfg(feature = "legacy_ss")]
pub fn get_tcp_metrics_via_ss(
    local_ip: &str,
    local_port: u16,
    remote_ip: &str,
    remote_port: u16,
) -> Result<TcpMetrics, String> {
    let output = Command::new("ss")
        .args([
            "-tin",
            "dst",
            &format!("{remote_ip}:{remote_port}"),
            "src",
            &format!("{local_ip}:{local_port}"),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .map_err(|e| format!("Failed to execute ss: {e}"))?;

    let output_str = String::from_utf8_lossy(&output.stdout);
    output_parsing(&output_str)
}

// ============================================================================
// NETLINK IMPLEMENTATION: Direct kernel communication (recommended)
// ============================================================================

/// Query TCP connection metrics via Netlink `INET_DIAG` protocol.
/// Direct kernel communication without subprocess overhead.
/// Wrapper for backwards compatibility; new code should use
/// `get_tcp_connection_data_via_netlink()` for full connection data.
/// Performance: 0.1-0.5ms per query (10-50x faster than ss command).
#[cfg(all(target_os = "linux", feature = "netlink"))]
pub fn get_tcp_metrics_via_netlink(
    local_ip: &str,
    local_port: u16,
    remote_ip: &str,
    remote_port: u16,
) -> Result<TcpMetrics, String> {
    use crate::netlink::{query_tcp_connection, tcp_info_to_metrics};

    let conn_data = query_tcp_connection(local_ip, local_port, remote_ip, remote_port)
        .map_err(|e| format!("{e}"))?;

    Ok(tcp_info_to_metrics(&conn_data.tcp_info))
}

/// Get complete TCP connection data via Netlink `INET_DIAG` (recommended).
/// Returns full `tcp_info` structure plus queue sizes and TCP state.
/// This is the modern API for comprehensive connection health assessment.
/// Performance: 0.1-0.5ms per query. Preferred over ss command.
/// Use with `assess_connection_health_v2()` for best results.
#[cfg(all(target_os = "linux", feature = "netlink"))]
pub fn get_tcp_connection_data_via_netlink(
    local_ip: &str,
    local_port: u16,
    remote_ip: &str,
    remote_port: u16,
) -> Result<crate::netlink::TcpConnectionData, String> {
    use crate::netlink::query_tcp_connection;

    query_tcp_connection(local_ip, local_port, remote_ip, remote_port).map_err(|e| format!("{e}"))
}

/// Get TCP metrics for multiple connections via Netlink in a single query.
/// Batch optimization: single kernel query for all connections from same local socket.
/// Performance: 5-100x faster than individual queries for multiple connections.
/// Requirement: All connections must have the same local IP and port.
#[cfg(all(target_os = "linux", feature = "netlink"))]
pub fn get_tcp_metrics_batch_netlink(
    connections: &[(String, u16, String, u16)],
) -> HashMap<(String, u16, String, u16), TcpMetrics> {
    if connections.is_empty() {
        return HashMap::new();
    }

    use crate::netlink::{query_tcp_connections_batch, tcp_info_to_metrics};

    let Ok(conn_data_map) = query_tcp_connections_batch(connections) else {
        return HashMap::new();
    };

    // Convert TcpConnectionData to TcpMetrics for all connections
    conn_data_map
        .into_iter()
        .map(|(conn, conn_data)| (conn, tcp_info_to_metrics(&conn_data.tcp_info)))
        .collect()
}

/// Get complete connection data for multiple connections via Netlink (batch).
/// Returns full `tcp_info`, queue sizes, and TCP state for all connections.
/// Batch optimization: single kernel query instead of N individual queries.
#[cfg(all(target_os = "linux", feature = "netlink"))]
pub fn get_tcp_connection_data_batch_netlink(
    connections: &[(String, u16, String, u16)],
) -> HashMap<(String, u16, String, u16), crate::netlink::TcpConnectionData> {
    if connections.is_empty() {
        return HashMap::new();
    }

    use crate::netlink::query_tcp_connections_batch;
    query_tcp_connections_batch(connections).unwrap_or_default()
}

/// Get TCP metrics for multiple connections via ss command (legacy batch optimization).
/// Uses single 'ss' call with combined filter instead of N subprocess invocations.
/// Performance: 25-35% CPU reduction compared to individual queries.
/// Fallback implementation; use Netlink batch instead.
#[cfg(feature = "legacy_ss")]
pub fn get_tcp_metrics_batch(
    connections: &[(String, u16, String, u16)],
) -> HashMap<(String, u16, String, u16), TcpMetrics> {
    if connections.is_empty() {
        return HashMap::new();
    }

    // Single connection: use individual query (already optimized)
    if connections.len() == 1 {
        let (local_ip, local_port, remote_ip, remote_port) = &connections[0];
        if let Ok(metrics) = get_tcp_metrics_via_ss(local_ip, *local_port, remote_ip, *remote_port)
        {
            let mut result = HashMap::new();
            result.insert(connections[0].clone(), metrics);
            return result;
        }
        return HashMap::new();
    }

    // Build combined filter: "( dst IP:PORT and src IP:PORT ) or ( ... )"
    let filter_parts: Vec<String> = connections
        .iter()
        .map(|(local_ip, local_port, remote_ip, remote_port)| {
            format!("( dst {remote_ip}:{remote_port} and src {local_ip}:{local_port} )")
        })
        .collect();

    let filter = filter_parts.join(" or ");

    // let output = match Command::new("ss")
    //     .args(["-tin"])
    //     .arg(&filter)
    //     .stdout(Stdio::piped())
    //     .stderr(Stdio::null())
    //     .output()
    // {
    //     Ok(out) => out,
    //     Err(_) => return HashMap::new(),
    // };

    let Ok(output) = Command::new("ss")
        .args(["-tin"])
        .arg(&filter)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
    else {
        return HashMap::new();
    };

    let output_str = String::from_utf8_lossy(&output.stdout);
    parse_ss_batch_output(&output_str, connections)
}

/// Parse connection address from ss output line (legacy helper).
/// Returns None if parsing fails at any step (handles malformed input gracefully).
/// Inlined for performance in tight parsing loops.
#[cfg(feature = "legacy_ss")]
#[inline]
fn parse_connection_addresses(
    local_addr: &str,
    remote_addr: &str,
) -> Option<(String, u16, String, u16)> {
    let (local_ip, local_port_str) = local_addr.rsplit_once(':')?;
    let (remote_ip, remote_port_str) = remote_addr.rsplit_once(':')?;

    let local_port = local_port_str.parse::<u16>().ok()?;
    let remote_port = remote_port_str.parse::<u16>().ok()?;

    Some((
        local_ip.to_string(),
        local_port,
        remote_ip.to_string(),
        remote_port,
    ))
}

/// Parse batched ss output and map metrics to connections (legacy).
/// Optimizations: HashSet O(1) lookup, helper function for early returns,
/// pre-allocated String capacity to minimize allocations.
#[cfg(feature = "legacy_ss")]
fn parse_ss_batch_output(
    output: &str,
    connections: &[(String, u16, String, u16)],
) -> HashMap<(String, u16, String, u16), TcpMetrics> {
    // Convert to HashSet for O(1) lookup (avoids O(n) linear search)
    let connection_set: HashSet<_> = connections.iter().cloned().collect();
    let mut results = HashMap::with_capacity(connections.len());

    let lines: Vec<&str> = output.lines().collect();
    let mut i = 0;

    while i < lines.len() {
        if i == 0 {
            i += 1;
            continue; // Skip header line
        }

        let line = lines[i];
        let fields: Vec<&str> = line.split_whitespace().collect();

        if fields.len() < 5 {
            i += 1;
            continue;
        }

        let local_addr = fields[3];
        let remote_addr = fields[4];

        let Some(key) = parse_connection_addresses(local_addr, remote_addr) else {
            i += 1;
            continue;
        };

        // Check if this connection is in the requested list
        if !connection_set.contains(&key) {
            i += 1;
            continue;
        }

        // Collect indented metric lines following this connection
        if i + 1 >= lines.len() {
            i += 1;
            continue;
        }

        let mut metric_lines = Vec::new();
        let mut j = i + 1;

        while j < lines.len() && lines[j].starts_with(|c: char| c.is_whitespace()) {
            metric_lines.push(lines[j]);
            j += 1;
        }

        // Build single-connection output with pre-allocated capacity
        let header = "State Recv-Q Send-Q Local Remote";
        let estimated_capacity =
            header.len() + line.len() + 2 + metric_lines.iter().map(|l| l.len() + 1).sum::<usize>();

        let mut single_output = String::with_capacity(estimated_capacity);
        single_output.push_str(header);
        single_output.push('\n');
        single_output.push_str(line);
        single_output.push('\n');

        for metric_line in &metric_lines {
            single_output.push_str(metric_line);
            single_output.push('\n');
        }

        if let Ok(metrics) = output_parsing(&single_output) {
            results.insert(key, metrics);
        }

        i = j;
    }

    results
}

// ============================================================================
// HEALTH ASSESSMENT: TCP Connection Health Evaluation
// ============================================================================

/// Assess connection health based on current TCP metrics alone.
/// Evaluates queue accumulation, retransmissions, RTT elevation, and flow control.
/// Baseline assessment without historical context; see `assess_connection_health_with_history()`
/// for enhanced assessment with trend detection.
#[must_use]
pub fn assess_connection_health(
    conn_info: &ConnectionInfo,
    metrics: &TcpMetrics,
) -> HealthAssessment {
    let mut score = 0;
    let mut reasons: Vec<String> = Vec::new();
    let mut safe_to_send = true;

    let queue = conn_info.send_queue_bytes;

    // Factor 1: Send queue accumulation (critical for message delivery systems)
    if queue >= SEND_QUEUE_CRITICAL {
        score += 5;
        safe_to_send = false;
        reasons.push("CRITICAL: Send queue >= 4KB (2+ messages stuck)".to_string());
    } else if queue >= SEND_QUEUE_WARNING {
        score += 3;
        safe_to_send = false;
        reasons.push("WARNING: Send queue >= 2KB (1+ message stuck)".to_string());
    } else if queue >= SEND_QUEUE_SUSPECT {
        score += 2;
        reasons.push("Send queue >= 1KB (partial message stuck)".to_string());
    }

    // Factor 2: Retransmissions (indicates packet loss and poor link quality)
    if metrics.bytes_retrans > 0 {
        score += 4;
        safe_to_send = false;
        reasons.push("Active retransmissions detected".to_string());
    } else if metrics.retrans_events > 0 {
        score += 2;
        reasons.push("Recent retransmission events".to_string());
    }

    // Factor 3: Unacked packets with queued data (indicates stalling)
    if metrics.unacked_packets > 0 && queue > 0 {
        score += 2;
        reasons.push("Data queued with unacked packets (stalling)".to_string());
    }

    // Factor 4: Unacked ratio compared to congestion window (congestion indicator)
    if metrics.congestion_window > 0 {
        let unacked_ratio = metrics.unacked_packets as f32 / metrics.congestion_window as f32;
        if unacked_ratio > 0.7 {
            score += 3;
            safe_to_send = false;
            reasons.push("Unacked > 70% of cwnd (congestion)".to_string());
        } else if unacked_ratio > 0.5 {
            score += 1;
            reasons.push("Unacked > 50% of cwnd".to_string());
        }
    }

    // Factor 5: RTT latency thresholds
    if metrics.rtt_ms > 1000.0 {
        score += 3;
        safe_to_send = false;
        reasons.push("RTT > 1s (severe delay)".to_string());
    } else if metrics.rtt_ms > 500.0 {
        score += 2;
        reasons.push("RTT > 500ms (high delay)".to_string());
    } else if metrics.rtt_ms > 200.0 {
        score += 1;
        reasons.push("RTT > 200ms (elevated)".to_string());
    }

    // Classify based on accumulated score
    let status = if score >= 7 || !safe_to_send {
        safe_to_send = false;
        "STALE"
    } else if score >= 5 {
        safe_to_send = false;
        "DEGRADED"
    } else if score >= 3 {
        "SUSPECT"
    } else if score >= 1 {
        "CAUTION"
    } else {
        "HEALTHY"
    };

    let reasons_str = if reasons.is_empty() {
        "All metrics within acceptable range for message delivery".to_string()
    } else {
        reasons.join("; ")
    };

    HealthAssessment {
        status: status.to_string(),
        score,
        safe_to_send,
        reasons: reasons_str,
        trend_metrics: None,
    }
}

/// Extract remote IP and port from connection address string (format: "IP:port").
/// Used internally throughout the codebase for address parsing.
/// Optimized: inlined to eliminate function call overhead in hot paths.
#[inline]
#[must_use]
pub fn extract_remote_parts(conn_addr: &str) -> (String, u16) {
    if let Some((ip_str, port_str)) = conn_addr.split_once(':') {
        let port = port_str.parse().unwrap_or(0);
        (ip_str.to_string(), port)
    } else {
        (String::new(), 0)
    }
}

/// Assess connection health with historical trend analysis.
/// Enhances baseline assessment by detecting degradation patterns:
/// - Queue growth trends (worsening condition)
/// - Queue persistence (stuck, not temporary spikes)
/// - Queue acceleration (problem getting worse faster)
/// - High volatility (unstable connection behavior)
/// - Recovery signals (improving from degraded state)
///
/// Use this for continuous monitoring where you collect multiple samples.
/// For single-sample queries, use `assess_connection_health()` instead.
#[must_use]
pub fn assess_connection_health_with_history(
    conn_info: &ConnectionInfo,
    metrics: &TcpMetrics,
    history: Option<&ConnectionHistory>,
) -> HealthAssessment {
    let mut health = assess_connection_health(conn_info, metrics);

    // Apply trend-based score adjustments if historical data available
    if let Some(hist) = history {
        let trends = &hist.trend_metrics;

        // Queue growth trend: score increases if queue is getting worse
        if trends.queue_growing {
            health.score += 2;
            health.reasons.push_str("; Queue growing trend detected");

            // Worse if already elevated
            if conn_info.send_queue_bytes >= SEND_QUEUE_WARNING {
                health.score += 2;
                health.safe_to_send = false;
                health.reasons.push_str(" + queue already elevated");
            }
        }

        // Persistent high queue: held above threshold for multiple consecutive samples
        if trends.send_queue_persistent {
            health.score += 3;
            health.safe_to_send = false;
            write!(
                &mut health.reasons,
                "; Queue persistently high for {} consecutive samples",
                trends.send_queue_high_count
            )
            .unwrap();
        }

        // Queue acceleration: rate of queue growth is itself increasing
        if trends.send_queue_acceleration > 100.0 {
            health.score += 2;
            health.safe_to_send = false;
            write!(
                &mut health.reasons,
                "; Queue accelerating ({:.0} bytes/sec²)",
                trends.send_queue_acceleration
            )
            .unwrap();
        }

        // High volatility: queue size fluctuates erratically (unstable connection)
        if trends.high_volatility {
            health.score += 1;
            health
                .reasons
                .push_str("; High volatility indicates unstable connection");
        }

        // Recovery credit: score penalty reversal if connection improving from degraded state
        if !trends.queue_growing
            && hist.current_status.contains("DEGRADED")
            && trends.send_queue_ma_short < 1024.0
        {
            health.score = health.score.saturating_sub(1);
            health
                .reasons
                .push_str("; Connection appears to be recovering");
        }

        health.trend_metrics = Some(trends.clone());
    }

    // Re-classify status based on adjusted score
    let status = if health.score >= 7 || !health.safe_to_send {
        health.safe_to_send = false;
        "STALE"
    } else if health.score >= 5 {
        health.safe_to_send = false;
        "DEGRADED"
    } else if health.score >= 3 {
        "SUSPECT"
    } else if health.score >= 1 {
        "CAUTION"
    } else {
        "HEALTHY"
    };

    // health.status = status.to_owned();
    status.clone_into(&mut health.status);
    health
}

/// Assess connection health using `TcpConnectionData` (modern API, recommended).
/// Direct evaluation without intermediate `TcpMetrics` conversion.
/// This is the preferred health assessment function for Netlink-based queries.
///
/// Advantages over legacy API:
/// - Simpler: No struct conversion required
/// - Faster: Eliminates allocation and field copying
/// - More accurate: Uses full `tcp_info` data with proper unit conversion
/// - Type-safe: Queue data can't be lost during conversion
///
/// Evaluates the same factors as legacy API (queue, retransmissions, RTT, flow control)
/// plus optional historical trends for comprehensive assessment.
#[cfg(all(target_os = "linux", feature = "netlink"))]
pub fn assess_connection_health_v2(
    conn_data: &crate::netlink::TcpConnectionData,
    _remote_addr: &str, // Reserved for future use (logging, correlation)
    history: Option<&crate::connection_history::ConnectionHistory>,
) -> HealthAssessment {
    let mut score: i32 = 0;
    let mut reasons: Vec<String> = Vec::new();
    let mut safe_to_send = true;

    let queue = conn_data.send_queue_bytes;

    // Factor 1: Send queue accumulation
    if queue >= SEND_QUEUE_CRITICAL {
        score += 5;
        safe_to_send = false;
        reasons.push("CRITICAL: Send queue >= 4KB (2+ messages stuck)".to_string());
    } else if queue >= SEND_QUEUE_WARNING {
        score += 3;
        safe_to_send = false;
        reasons.push("WARNING: Send queue >= 2KB (1+ message stuck)".to_string());
    } else if queue >= SEND_QUEUE_SUSPECT {
        score += 2;
        reasons.push("Send queue >= 1KB (partial message stuck)".to_string());
    }

    // Factor 2: Retransmissions (packet loss indication)
    if conn_data.has_packet_loss() {
        score += 4;
        safe_to_send = false;
        reasons.push("Active retransmissions detected".to_string());

        // Add retransmission rate if extended metrics available
        if let Some(bytes_retrans) = conn_data.bytes_retransmitted()
            && bytes_retrans > 0
            && let Some(rate) = conn_data.retransmission_rate()
        {
            reasons.push(format!("Retransmit rate: {rate:.2}%"));
        }
    }

    // Factor 3: Unacked packets with queued data (stalling indicator)
    let unacked = conn_data.tcp_info.basic.tcpi_unacked;
    if unacked > 0 && queue > 0 {
        score += 2;
        reasons.push("Data queued with unacked packets (stalling)".to_string());
    }

    // Factor 4: Unacked ratio (flow control congestion)
    let cwnd = conn_data.congestion_window();
    if cwnd > 0 {
        let unacked_ratio = unacked as f32 / cwnd as f32;
        if unacked_ratio > 0.7 {
            score += 3;
            safe_to_send = false;
            reasons.push("Unacked > 70% of cwnd (congestion)".to_string());
        } else if unacked_ratio > 0.5 {
            score += 1;
            reasons.push("Unacked > 50% of cwnd".to_string());
        }
    }

    // Factor 5: RTT latency elevation
    let rtt_ms = conn_data.rtt_ms();
    if rtt_ms > 1000.0 {
        score += 3;
        safe_to_send = false;
        reasons.push("RTT > 1s (severe delay)".to_string());
    } else if rtt_ms > 500.0 {
        score += 2;
        reasons.push("RTT > 500ms (high delay)".to_string());
    } else if rtt_ms > 200.0 {
        score += 1;
        reasons.push("RTT > 200ms (elevated)".to_string());
    }

    // Factor 6: Congestion window reduction (past packet loss recovery)
    let ssthresh = conn_data.slow_start_threshold();
    if ssthresh < cwnd && ssthresh < 10 {
        score += 2;
        reasons.push(format!(
            "Low ssthresh ({ssthresh}) indicates past congestion"
        ));
    }

    // Trend-based adjustments (if historical data available)
    let mut trend_metrics_opt = None;

    if let Some(hist) = history {
        let trends = &hist.trend_metrics;
        trend_metrics_opt = Some(trends.clone());

        // Queue growth trend
        if trends.queue_growing {
            score += 2;
            reasons.push("Queue growing trend detected".to_string());

            if queue >= SEND_QUEUE_WARNING {
                score += 2;
                safe_to_send = false;
                reasons.push("Queue already elevated + growing".to_string());
            }
        }

        // Persistent high queue
        if trends.send_queue_persistent {
            score += 3;
            safe_to_send = false;
            reasons.push(format!(
                "Queue persistently high for {} consecutive samples",
                trends.send_queue_high_count
            ));
        }

        // Queue acceleration
        if trends.send_queue_acceleration > 100.0 {
            score += 2;
            safe_to_send = false;
            reasons.push(format!(
                "Queue accelerating ({:.0} bytes/sec²)",
                trends.send_queue_acceleration
            ));
        }

        // High volatility
        if trends.high_volatility {
            score += 1;
            reasons.push("High volatility indicates unstable connection".to_string());
        }

        // Recovery credit
        if !trends.queue_growing
            && hist.current_status.contains("DEGRADED")
            && trends.send_queue_ma_short < 1024.0
        {
            score = score.saturating_sub(1);
            reasons.push("Connection appears to be recovering".to_string());
        }
    }

    // Final classification
    let status = if score >= 7 || !safe_to_send {
        safe_to_send = false;
        "STALE"
    } else if score >= 5 {
        safe_to_send = false;
        "DEGRADED"
    } else if score >= 3 {
        "SUSPECT"
    } else if score >= 1 {
        "CAUTION"
    } else {
        "HEALTHY"
    };

    let reasons_str = if reasons.is_empty() {
        "All metrics within acceptable range for message delivery".to_string()
    } else {
        reasons.join("; ")
    };

    HealthAssessment {
        status: status.to_string(),
        score,
        safe_to_send,
        reasons: reasons_str,
        trend_metrics: trend_metrics_opt,
    }
}

/// `ConnectionWithHealth` comparison implementation.
/// Sorts by health score descending (higher score = worse = comes first),
/// then by send queue size if scores are equal (higher queue = worse).
impl ConnectionWithHealth {
    /// Compare two connections by health for sorting.
    /// Used by the API to return results ordered by severity.
    #[must_use]
    pub fn cmp_by_health(&self, other: &Self) -> Ordering {
        let self_score = self.health.as_ref().map_or(0_i32, |h| h.score);
        let other_score = other.health.as_ref().map_or(0_i32, |h| h.score);

        match other_score.cmp(&self_score) {
            Ordering::Equal => other
                .connection
                .send_queue_bytes
                .cmp(&self.connection.send_queue_bytes),
            other_ordering => other_ordering,
        }
    }
}

// ============================================================================
// UNIT TESTS
// ============================================================================

#[cfg(test)]
mod tests;
