//! Netlink `INET_DIAG` implementation
//!
//! This module provides native Linux Netlink communication for querying
//! TCP socket information. It replaces subprocess-based `ss` command
//! with direct kernel queries for 10-50x performance improvement.
//!
//!

// ============================================================================
// SUBMODULE DECLARATIONS
// ============================================================================

// Phase 1: Core infrastructure
#[cfg(target_os = "linux")]
pub mod socket; // Netlink socket management (Linux only)
pub mod structures; // Binary protocol structures (cross-platform for testing)

// Phase 2: INET_DIAG protocol implementation
#[cfg(target_os = "linux")]
pub mod inet_diag; // High-level query API (Linux only)
#[cfg(target_os = "linux")]
pub mod message; // Message construction and parsing (Linux only)
#[cfg(target_os = "linux")]
pub mod tcp_info; // tcp_info structure parsing (Linux only)

// ============================================================================
// PUBLIC RE-EXPORTS (Phase 3: Integration)
// ============================================================================

// Re-export commonly used types for easier access.
// Users can now write:
//   use cerberus::netlink::{query_tcp_connection, TcpInfo};
// instead of:
//   use cerberus::netlink::inet_diag::query_tcp_connection;
//   use cerberus::netlink::tcp_info::TcpInfo;
//
// ## Phase 3 Design
//
// We expose only the high-level API that users need for integration:
// - query_tcp_connection() - Query single connection by 4-tuple
// - query_tcp_connections_batch() - Query multiple connections efficiently
// - TcpInfo - Parsed TCP metrics structure
// - Error types - For proper error handling
//
// Internal modules (socket, structures, message) remain private.
// This keeps the public API clean and focused.

// === HIGH-LEVEL QUERY API (Phase 2) ===
// These are the main entry points for querying TCP connections
#[cfg(target_os = "linux")]
pub use inet_diag::{
    InetDiagError,               // Error type for query operations
    TcpConnectionData,           // Complete connection data (tcp_info + queue sizes + state)
    query_tcp_connection,        // Single connection query
    query_tcp_connections_batch, // Batch query for multiple connections
};

// === TCP INFO STRUCTURES (Phase 2) ===
// These represent parsed TCP metrics from kernel
#[cfg(target_os = "linux")]
pub use tcp_info::{
    TcpInfo,             // Complete tcp_info (basic + optional extended)
    TcpInfoBasic,        // Basic metrics (kernel 3.10+, RHEL 7+)
    TcpInfoError,        // Error type for tcp_info parsing
    TcpInfoExtended,     // Extended metrics (kernel 4.2+, RHEL 8+)
    tcp_info_to_metrics, // Convert TcpInfo to TcpMetrics (for integration)
};
