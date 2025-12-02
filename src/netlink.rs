//! Netlink `INET_DIAG` implementation
//!
//! This module provides native Linux Netlink communication for querying
//! TCP socket information. It replaces subprocess-based `ss` command
//! with direct kernel queries for 10-50x performance improvement.
//!
//! # Architecture
//!
//! ## Phase 1: Core Infrastructure (COMPLETED)
//! - `socket`: Low-level Netlink socket management (syscalls, RAII)
//! - `structures`: Binary structures matching kernel layout (repr(C))
//!
//! ## Phase 2: `INET_DIAG` Protocol (COMPLETED)
//! - `message`: Message construction and parsing
//! - `inet_diag`: High-level `INET_DIAG` query functions
//! - `tcp_info`: TCP metrics parsing and conversion
//!
//! # Educational Notes
//!
//! ## What is a Module in Rust?
//!
//! A module is Rust's way of organizing code into namespaces.
//! - `mod.rs` is the module root file (like `__init__.py` in Python)
//! - Other files are submodules (like `socket.rs`, `structures.rs`)
//! - Visibility controlled by `pub` keyword
//!
//! ## Module Declaration
//!
//! ```rust
//! mod socket;        // Private: only this module can use it
//! pub mod socket;    // Public: other modules can use it
//! ```
//!
//! ## Re-exports
//!
//! We can make items easier to access:
//! ```rust
//! pub use socket::NetlinkSocket;
//! // Now users can write:
//! // use cerberus::netlink::NetlinkSocket;
//! // instead of:
//! // use cerberus::netlink::socket::NetlinkSocket;
//! ```
//!
//! ## Conditional Compilation
//!
//! Some modules are Linux-only (Netlink is a Linux-specific kernel interface).
//! We use #[`cfg(target_os` = "linux")] to compile them only on Linux.
//! This allows the code to compile on macOS for development while clearly
//! marking which parts are platform-specific.

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

// === INTERNAL MODULES (kept private) ===
//
// The following modules are implementation details and not exposed:
// - socket::NetlinkSocket - Low-level Netlink socket management
// - structures::* - Binary protocol structures (repr(C))
// - message::* - Message construction and parsing
//
// Users of this library don't need to interact with these directly.
// They use the high-level query_tcp_connection() API instead.
