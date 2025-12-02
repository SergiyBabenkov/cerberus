// ============================================================================
// FILE OVERVIEW: TCP Monitor HTTP Server - Main Entry Point
// ============================================================================
//
// === WHAT THIS FILE DOES ===
// This program runs an HTTP server that monitors TCP connections on the system.
// It accepts HTTP requests asking "what is the status of connection X?" and
// responds with detailed TCP metrics, health assessment, and historical trends.
//
// === KEY RUST CONCEPTS DEMONSTRATED ===
// 1. Concurrency with Arc (Atomic Reference Counting) and RwLock
// 2. Thread pools for parallel request handling
// 3. Atomic operations for thread-safe flags
// 4. Ownership and borrowing in multi-threaded contexts
// 5. Pattern matching with Result and Option types
// 6. Iterators and functional programming patterns
//
// === ARCHITECTURE ===
// - Main thread: Listens for incoming HTTP connections
// - Thread pool: Handles client requests in parallel
// - Shared state: HistoryManager wrapped in Arc<RwLock<>> for safe concurrent access
//
// === PERFORMANCE OPTIMIZATIONS ===
// This code uses several advanced optimization techniques:
// 1. Batched system calls: One ss command instead of N individual calls
// 2. Single lock acquisition: Get write lock once, do all work, release
// 3. Thread pool sizing: 2x CPU cores for I/O-bound work
// 4. Reference borrowing: Avoid cloning data when possible
//
// ============================================================================

// === IMPORTS SECTION ===

// parking_lot::RwLock: A faster alternative to std::sync::RwLock
// WHY parking_lot? It's optimized for cases with many readers and few writers
// PERFORMANCE: No poisoning mechanism = less overhead, better throughput
use parking_lot::RwLock;

use std::env;

// Read and Write traits: Allow us to use .read() and .write_all() on TcpStream
// These are TRAITS (like interfaces in other languages)
use std::io::{Read, Write};

// TcpListener: Listens for incoming TCP connections (the HTTP server)
// TcpStream: Represents a single client connection
use std::net::{TcpListener, TcpStream};

// Arc: Atomic Reference Counted smart pointer
// === WHAT IS Arc? ===
// Arc allows MULTIPLE threads to own the SAME data safely
// When the last Arc is dropped, the data is freed
// === WHY Arc? ===
// We need multiple worker threads to access the same HistoryManager
// Arc uses atomic operations (thread-safe counting) to track references
// === ALTERNATIVE ===
// Could use Rc, but Rc is NOT thread-safe (faster, but single-threaded only)
use std::sync::Arc;

// AtomicBool: A boolean that can be safely read/written from multiple threads
// === WHAT IS ATOMIC? ===
// Atomic types use CPU-level atomic instructions (lock-free concurrency)
// Reading/writing happens in a single, indivisible operation
// === WHY AtomicBool? ===
// We need the main loop and signal handler to share a "running" flag
// Normal bool would cause data races (undefined behavior)
// === MEMORY ORDERING ===
// AtomicOrdering controls how operations are synchronized across threads
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};

// Time utilities
// Instant: Monotonic clock (for measuring elapsed time, never goes backwards)
// SystemTime: Wall clock time (can jump when user changes system clock)
// UNIX_EPOCH: January 1, 1970 00:00:00 UTC (standard reference point)
use std::time::{Instant, SystemTime, UNIX_EPOCH};

// ThreadPool: Manages a pool of worker threads for parallel task execution
// === WHY THREAD POOL? ===
// Creating/destroying threads is expensive (system calls, memory allocation)
// Thread pool reuses threads: create once, use many times
// === ALTERNATIVE ===
// Could spawn thread per request, but this can exhaust system resources
// Thread pools limit concurrency and amortize thread creation cost
use threadpool::ThreadPool;

// Import all public types and functions from our library crate
// === RUST MODULE SYSTEM ===
// cerberus:: refers to the library crate (src/lib.rs)
// This separation keeps business logic (lib.rs) separate from server code (main.rs)
// BENEFIT: Library code can be tested without running the server
use cerberus::{
    ConfigResponse,                        // Response format for /config endpoint
    ConnectionInfo,                        // Data about a single TCP connection
    ConnectionWithHealth,                  // Connection + metrics + health assessment
    DEFAULT_HTTP_PORT,                     // Constant: default port number
    HistoryManager,                        // Tracks queue sizes over time for trend analysis
    MonitorRequest,                        // JSON format for incoming requests
    MonitorResponse,                       // JSON format for responses (Single or Multiple)
    assess_connection_health_with_history, // Health scoring algorithm (legacy)
    extract_remote_parts,                  // Parse "IP:port" string
    find_connections_in_proc,              // Find all connections matching criteria
    find_single_connection,                // Find one specific connection
};

// TcpMetrics is only directly used in legacy_ss and development paths
// In netlink path, we use cerberus::TcpMetrics (fully qualified)
#[cfg(not(all(target_os = "linux", feature = "netlink")))]
use cerberus::TcpMetrics;

// ============================================================================
// CONDITIONAL IMPORTS: Netlink vs Legacy ss
// ============================================================================
//
// === PERFORMANCE COMPARISON ===
// Netlink INET_DIAG (Modern, RECOMMENDED):
//   - Single query: 0.1-0.5 ms (direct kernel communication)
//   - Batch 100 connections: ~3 ms
//   - CPU overhead: Minimal (no process spawning)
//   - Improvement: 10-50x faster than subprocess
//
// Legacy ss Command (Fallback):
//   - Single query: 5-15 ms (subprocess spawn + parse)
//   - Batch 100 connections: ~1000 ms
//   - CPU overhead: Higher (process creation, shell parsing)
//   - Compatibility: Works on any Linux with ss installed
//
// === FEATURE FLAG STRATEGY ===
// - default = ["netlink"]: Most users get fast implementation
// - --features legacy_ss: Fallback for older systems or debugging
// - Both can be enabled simultaneously for A/B testing

// Import Netlink-based functions when netlink feature is enabled (default)
// These use direct kernel communication via INET_DIAG protocol
#[cfg(all(target_os = "linux", feature = "netlink"))]
use cerberus::{
    assess_connection_health_v2, // RECOMMENDED: Modern health assessment v2 API
    get_tcp_connection_data_batch_netlink, // RECOMMENDED: Batch query with full data
    get_tcp_connection_data_via_netlink, // RECOMMENDED: Single query with full data
};

// Import legacy ss-based functions when legacy_ss feature is enabled
// These spawn subprocess and parse text output (slower but more compatible)
#[cfg(feature = "legacy_ss")]
use cerberus::{
    get_tcp_metrics_batch, // OPTIMIZED: Get metrics for multiple connections via ss
    get_tcp_metrics_via_ss, // Get metrics for single connection via ss
};

// ============================================================================
// COMPILE-TIME FEATURE VALIDATION
// ============================================================================
//
// === WHAT THIS DOES ===
// Ensures that at least one TCP metrics implementation is available.
// Without either netlink or legacy_ss, the program cannot function on Linux.
//
// === PLATFORM CONSIDERATIONS ===
// - On Linux: At least one of netlink or legacy_ss must be enabled
// - On macOS/other: Only legacy_ss is available (netlink is Linux-only)
//   But this is a development/testing environment, so we allow compilation
//
// === HOW IT WORKS ===
// compile_error! is a compiler builtin that stops compilation with an error message
// The #[cfg(...)] attribute controls when the check runs
//
// === WHEN THIS TRIGGERS ===
// On Linux: If you build with cargo build --no-default-features
// On macOS: Never (this is a development environment)
//
// === CORRECT USAGE ===
// cargo build                                    ← Uses default (netlink on Linux)
// cargo build --features legacy_ss               ← Uses both implementations
// cargo build --no-default-features --features netlink    ← Netlink only (Linux)
// cargo build --no-default-features --features legacy_ss  ← Legacy only
//
// === ERROR MESSAGE EXPLANATION ===
// The error message tells users exactly what went wrong and how to fix it
#[cfg(all(
    target_os = "linux",
    not(any(feature = "netlink", feature = "legacy_ss"))
))]
compile_error!(
    "At least one TCP metrics implementation must be enabled on Linux!\n\
     \n\
     Available options:\n\
     1. Netlink (RECOMMENDED, fast): cargo build --features netlink\n\
     2. Legacy ss (fallback, slow): cargo build --features legacy_ss\n\
     3. Both (for testing): cargo build --features netlink,legacy_ss\n\
     \n\
     Note: 'netlink' is the default feature. Use --no-default-features to disable it.\n\
     \n\
     See Cargo.toml [features] section for more information."
);

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/// Get current timestamp in milliseconds since Unix epoch
///
/// === WHAT THIS DOES ===
/// Returns current time as milliseconds since Jan 1, 1970 UTC
///
/// === WHY THIS APPROACH ===
/// - Millisecond precision is good enough for monitoring
/// - Unix epoch is a standard timestamp format (portable across systems)
/// - Using u64 avoids overflow until year 584,542,046 CE
///
/// === HOW IT WORKS ===
/// 1. `SystemTime::now()` gets current wall clock time
/// 2. .`duration_since(UNIX_EPOCH)` calculates time elapsed since Jan 1, 1970
/// 3. .`unwrap_or_default()` handles edge case where clock went backwards
///    (returns `Duration::ZERO` if error occurs)
/// 4. .`as_millis()` converts Duration to milliseconds
/// 5. Cast to u64 because `as_millis()` returns u128 (we don't need that range)
///
/// === RUST CONCEPT: Result and Option ===
/// `duration_since` returns Result<Duration, `SystemTimeError`>
/// `unwrap_or_default()` converts Result → Duration (no panic)
///
/// === ALTERNATIVE ===
/// Could use `Instant::now()` but that doesn't map to wall clock time
/// #[inline] - maybe make it inline?
/// fn `get_timestamp_ms()` -> u64 {
///     `SystemTime::now()`
///         .`duration_since(UNIX_EPOCH)`
///         .`unwrap_or_default()`
///         .`as_millis()` as u64
/// }
/// ============================================================================
/// HTTP REQUEST HANDLER
/// ============================================================================
/// Handle HTTP client connection for monitoring requests
///
/// === FUNCTION SIGNATURE EXPLAINED ===
/// - `mut stream: TcpStream`
///   Takes OWNERSHIP of stream (stream is moved into this function)
///   mut = we'll write to it, modifying its state
///   After this function returns, stream is automatically closed (Drop trait)
///
/// - `history_manager: Arc<RwLock<HistoryManager>>`
///   Arc = shared ownership (this is a clone of Arc, not the data inside)
///   `RwLock` = Reader-Writer lock for safe concurrent access
///   `HistoryManager` = the actual data we're protecting
///
/// === WHY Arc<`RwLock`<T>> PATTERN? ===
/// This is the standard Rust pattern for shared mutable state across threads:
/// - Arc: Allows multiple threads to share ownership
/// - `RwLock`: Allows multiple readers OR one writer (never both)
/// - When we call .`write()`, we get exclusive access
/// - When we call .`read()`, we get shared access (many readers allowed)
///
/// === MEMORY SAFETY ===
/// The type system PREVENTS:
/// - Data races (two threads writing simultaneously)
/// - Use-after-free (accessing freed memory)
/// - Null pointer dereferences
///
/// === PERFORMANCE CONSIDERATION ===
/// This function runs in a worker thread from the thread pool
/// Blocking here doesn't block the main thread or other workers
///
/// === FLOW ===
/// 1. Read HTTP request from socket
/// 2. Parse HTTP method and path
/// 3. Extract JSON body (for POST requests)
/// 4. Process request based on endpoint
/// 5. Write HTTP response back to socket
fn handle_client(mut stream: TcpStream, history_manager: Arc<RwLock<HistoryManager>>) {
    // === STACK ALLOCATION ===
    // This allocates 4096 bytes on the STACK (not heap)
    // [0u8; 4096] means: array of 4096 bytes, all initialized to zero
    // WHY 4096? Common page size, good balance between memory and request size
    // RUST CONCEPT: Arrays have fixed size known at compile time
    let mut buffer = [0u8; 4096];

    // === READING FROM SOCKET ===
    // stream.read(&mut buffer) attempts to fill buffer with data from socket
    //
    // OWNERSHIP NOTE: `&mut buffer` is a MUTABLE BORROW
    // - We're lending buffer to the read() function temporarily
    // - read() can modify buffer (fill it with data)
    // - After read() returns, we get buffer back
    // - We still own buffer (it wasn't moved)
    //
    // RETURN TYPE: Result<usize, io::Error>
    // - Ok(bytes_read) means success, contains number of bytes read
    // - Err(e) means failure (connection closed, timeout, etc.)
    //
    // PATTERN: `if let Ok(bytes_read) = ...`
    // This is pattern matching on Result:
    // - If Ok, extract bytes_read and enter the block
    // - If Err, skip the block entirely (no error handling in this case)
    //
    // ALTERNATIVE: Could use match or .unwrap() but those have different semantics
    if let Ok(bytes_read) = stream.read(&mut buffer) {
        // === STRING CONVERSION ===
        // Convert bytes to UTF-8 string
        //
        // &buffer[..bytes_read] is a SLICE (borrowed view into array)
        // SYNTAX: [start..end] means "from start up to (not including) end"
        // [..bytes_read] means "from beginning up to bytes_read"
        //
        // from_utf8_lossy: Converts bytes to string, replacing invalid UTF-8 with �
        // RETURNS: Cow<str> (Clone on Write string)
        // WHY Cow? Avoids allocation if input is valid UTF-8 (zero-copy)
        //
        // MEMORY: This creates a string in memory (heap allocation if needed)
        // LIFETIME: request lives until end of this if-block
        let request = String::from_utf8_lossy(&buffer[..bytes_read]);

        // === HTTP REQUEST ROUTING ===
        // Parse HTTP request line to determine which endpoint was requested
        //
        // RUST STRING METHODS:
        // .starts_with() checks if string begins with given prefix
        // Returns bool (true/false)

        if request.starts_with("POST /monitor") {
            // === ENDPOINT: POST /monitor ===
            // This is the main monitoring endpoint
            // Expected format: POST /monitor HTTP/1.1\r\n...headers...\r\n\r\n{JSON body}

            // === FINDING JSON BODY ===
            // HTTP has headers, then blank line (\r\n\r\n), then body
            // .find("\r\n\r\n") searches for blank line separator
            //
            // RETURN TYPE: Option<usize>
            // - Some(index) if found (index is position of first \r)
            // - None if not found
            //
            // PATTERN: `if let Some(body_start) = ...`
            // Only proceed if blank line is found
            if let Some(body_start) = request.find("\r\n\r\n") {
                // === STRING SLICING ===
                // &request[body_start + 4..]
                // Start at body_start + 4 (skip past "\r\n\r\n")
                // Go to end (no ending index specified)
                // RESULT: String slice (&str) pointing into request
                // MEMORY: No allocation, just a pointer + length
                let body = &request[body_start + 4..];

                // === JSON DESERIALIZATION ===
                // Convert JSON string → Rust struct
                //
                // serde_json::from_str::<MonitorRequest>(body)
                // GENERIC TYPE: ::<MonitorRequest> tells compiler what type to parse into
                // WHY NEEDED? Rust needs to know the type to parse correctly
                //
                // RETURN TYPE: Result<MonitorRequest, serde_json::Error>
                // - Ok(req) means successful parse
                // - Err(e) means invalid JSON or doesn't match struct shape
                //
                // PATTERN: `match` is exhaustive (must handle all cases)

                if let Ok(req) = serde_json::from_str::<MonitorRequest>(body) {
                    // === EXTRACT REQUEST PARAMETERS ===
                    // req.local_ip is a String field in MonitorRequest struct
                    // &req.local_ip borrows the string (no ownership transfer)
                    // WHY BORROW? We only need to read it, not own it
                    //
                    // LIFETIME: local_ip reference is valid as long as req exists
                    let local_ip = &req.local_ip;

                    // req.local_port is u16 (unsigned 16-bit integer)
                    // u16 implements Copy trait, so this is a COPY, not a move
                    // WHY Copy? Small integers are cheap to copy (just 2 bytes)
                    // MEMORY: Copied onto stack (no heap allocation)
                    let local_port = req.local_port;

                    // Get timestamp for this response
                    let timestamp = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64;

                    // === REQUEST TYPE DETECTION ===
                    // MonitorRequest can query either:
                    // 1. Single connection: remote_port is Some(port)
                    // 2. Multiple connections: remote_port is None
                    //
                    // RUST CONCEPT: Option<T>
                    // Option is an enum: either Some(value) or None
                    // WHY? Rust has no null pointers - Option is the safe alternative
                    //
                    // PATTERN: `if let Some(remote_port) = req.remote_port`
                    // If req.remote_port is Some, extract the value and enter block
                    // If None, skip to else block
                    let response = if let Some(remote_port) = req.remote_port {
                        // ========================================================
                        // SINGLE CONNECTION QUERY PATH
                        // ========================================================
                        // All 4-tuple parameters provided:
                        // (local_ip, local_port, remote_ip, remote_port)

                        // === STEP 1: Find connection in /proc/net/tcp ===
                        //
                        // FUNCTION SIGNATURE:
                        // find_single_connection(
                        //     local_ip: &str,           // Borrowed string
                        //     local_port: u16,          // Copied value
                        //     remote_ip: &str,          // Borrowed string
                        //     remote_port: u16,         // Copied value
                        //     established_only: bool    // Copied value
                        // ) -> Result<ConnectionInfo, String>
                        //
                        // WHY BORROW &str?
                        // - We don't need to own the strings
                        // - Function just needs to read them
                        // - Avoids unnecessary cloning
                        //
                        // RETURN TYPE: Result<ConnectionInfo, String>
                        // - Ok(conn_info) if connection found
                        // - Err(error_message) if not found or error
                        match find_single_connection(
                            local_ip,
                            local_port,
                            &req.remote_ip,
                            remote_port,
                            req.established_only,
                        ) {
                            // === CONNECTION FOUND ===
                            Ok(conn_info) => {
                                // === PARSE REMOTE ADDRESS ===
                                // conn_info.remote_address is format "IP:port"
                                // extract_remote_parts splits it into (IP, port)
                                //
                                // OWNERSHIP:
                                // &conn_info.remote_address borrows the string
                                // Function returns (String, u16) - NEW owned String
                                // This is necessary because we need IP and port separately
                                // Note: For netlink path, these are used in the netlink call
                                // For legacy_ss path, these are used in the ss call
                                #[allow(unused_variables)]
                                // Used in conditional compilation blocks below
                                let (remote_ip, remote_port) =
                                    extract_remote_parts(&conn_info.remote_address);

                                // === STEP 2: Get TCP metrics ===
                                //
                                // === CONDITIONAL COMPILATION: Netlink vs ss ===
                                // This code compiles to different implementations based on features:
                                //
                                // WITH netlink feature (default):
                                //   - Calls get_tcp_metrics_via_netlink()
                                //   - Direct kernel communication via INET_DIAG
                                //   - Performance: 0.1-0.5 ms (10-50x faster)
                                //   - No subprocess overhead
                                //
                                // WITH legacy_ss feature:
                                //   - Calls get_tcp_metrics_via_ss()
                                //   - Spawns subprocess: ss -tin "dst IP:port"
                                //   - Parses text output
                                //   - Performance: 5-15 ms
                                //
                                // WHY SEPARATE CALL FROM /proc/net/tcp?
                                // /proc/net/tcp: Basic info (state, queues)
                                // Metrics source: Detailed TCP metrics (retransmits, RTT, cwnd)
                                // No single source has everything we need
                                //
                                // === COMPILATION BEHAVIOR ===
                                // Only ONE of these blocks compiles into the binary
                                // Zero runtime overhead - decision made at compile time

                                // === NETLINK PATH (default, RECOMMENDED) ===
                                // Compiles on Linux with netlink feature
                                // NOW GETS FULL CONNECTION DATA (tcp_info + queue sizes + state)
                                #[cfg(all(target_os = "linux", feature = "netlink"))]
                                let conn_data_result = get_tcp_connection_data_via_netlink(
                                    local_ip,
                                    local_port,
                                    &remote_ip,
                                    remote_port,
                                );

                                // === LEGACY SS PATH (fallback) ===
                                // Compiles when legacy_ss feature is enabled (any platform)
                                #[cfg(all(
                                    feature = "legacy_ss",
                                    not(all(target_os = "linux", feature = "netlink"))
                                ))]
                                let metrics_result = get_tcp_metrics_via_ss(
                                    local_ip,
                                    local_port,
                                    &remote_ip,
                                    remote_port,
                                );

                                // === DEVELOPMENT/FALLBACK PATH ===
                                // On non-Linux platforms (macOS) or when no features enabled
                                // This allows the binary to compile for development/testing
                                // At runtime, this will return an error since metrics can't be retrieved
                                #[cfg(not(any(
                                        all(target_os = "linux", feature = "netlink"),
                                        feature = "legacy_ss"
                                    )))]
                                    let metrics_result: Result<cerberus::TcpMetrics, String> = Err(
                                        "TCP metrics not available: build with --features netlink or --features legacy_ss".to_string()
                                    );

                                // ================================================
                                // PROCESS RESULT (different paths for different features)
                                // ================================================

                                // === NETLINK PATH: Use full connection data ===
                                #[cfg(all(target_os = "linux", feature = "netlink"))]
                                let process_result = conn_data_result.as_ref().map(|conn_data| {
                                    // ================================================
                                    // OPTIMIZATION: Single Lock Acquisition
                                    // ================================================
                                    //
                                    // === OLD APPROACH (2 lock acquisitions) ===
                                    // 1. Get write lock, add sample, release lock
                                    // 2. Get read lock, get history, release lock
                                    // COST: 2 lock operations, potential contention
                                    //
                                    // === NEW APPROACH (1 lock acquisition) ===
                                    // 1. Get write lock once
                                    // 2. Add sample
                                    // 3. Get history (while still holding lock)
                                    // 4. Clone history
                                    // 5. Release lock
                                    // BENEFIT: 50% reduction in lock operations
                                    //
                                    // === SCOPE BLOCK { } ===
                                    // The curly braces create a new scope
                                    // WHY? To control LIFETIME of the lock guard
                                    // When scope ends, `manager` is dropped, lock is released
                                    // This is called RAII (Resource Acquisition Is Initialization)
                                    let history = {
                                        // === ACQUIRE WRITE LOCK ===
                                        // history_manager.write() acquires exclusive access
                                        //
                                        // WHAT TYPE IS `manager`?
                                        // RwLockWriteGuard<HistoryManager>
                                        // This is a smart pointer that:
                                        // 1. Provides mutable access to HistoryManager
                                        // 2. Automatically releases lock when dropped
                                        //
                                        // BLOCKING BEHAVIOR:
                                        // If another thread holds the lock, this blocks (waits)
                                        // parking_lot is fair: first waiter gets next turn
                                        //
                                        // PANIC BEHAVIOR:
                                        // Unlike std::sync::RwLock, parking_lot doesn't poison
                                        // If thread panics while holding lock, lock still works
                                        let mut manager = history_manager.write();

                                        // === ADD SAMPLE TO HISTORY WITH FULL TCP DATA ===
                                        // Uses new add_sample_from_netlink() method
                                        // This populates ALL TCP health metrics, not just queues!
                                        //
                                        // WHAT THIS FIXES:
                                        // - OLD: Only queue sizes recorded → health metrics all 0
                                        // - NEW: Full tcp_info recorded → health metrics work!
                                        //
                                        // DATA INCLUDED:
                                        // - Queue sizes (send_queue_bytes, recv_queue_bytes)
                                        // - Timing (last_data_sent_ms, last_ack_recv_ms)
                                        // - RTT (rtt_us, rtt_var_us, min_rtt_us)
                                        // - Loss (retrans, total_retrans, lost)
                                        // - Congestion (snd_cwnd, snd_ssthresh)
                                        // - Bottleneck (busy_time, rwnd_limited, sndbuf_limited)
                                        // - TCP state (tcp_state)
                                        manager.add_sample_from_netlink(
                                            local_ip,
                                            local_port,
                                            &remote_ip,
                                            remote_port,
                                            conn_data,
                                        );

                                        // === GET HISTORY WHILE HOLDING LOCK ===
                                        // Retrieve historical samples for this connection
                                        //
                                        // RETURN TYPE: Option<&ConnectionHistory>
                                        // - Some(&history) if we have samples
                                        // - None if this is first sample
                                        //
                                        // PROBLEM: We can't return &ConnectionHistory
                                        // because the reference is tied to the lock guard
                                        // When scope ends, lock is released, reference invalid!
                                        //
                                        // SOLUTION: .cloned()
                                        // Clone the history so we own it
                                        // Now we can release the lock safely
                                        //
                                        // PERFORMANCE COST: One clone
                                        // PERFORMANCE BENEFIT: One fewer lock acquisition
                                        // NET RESULT: Usually a win (cloning is cheaper than locking)
                                        manager
                                            .get_with_local(
                                                local_ip,
                                                local_port,
                                                &remote_ip,
                                                remote_port,
                                            )
                                            .cloned()

                                        // === LOCK RELEASED HERE ===
                                        // When scope ends, `manager` is dropped
                                        // Drop trait releases the write lock
                                        // Other threads can now acquire the lock
                                    };

                                    // === BUILD REMOTE ADDRESS STRING ===
                                    // v2 API expects remote_addr in "IP:port" format
                                    // We already have remote_ip and remote_port from earlier parsing
                                    let remote_addr = format!("{}:{}", remote_ip, remote_port);

                                    // === ASSESS CONNECTION HEALTH (V2 API) ===
                                    // NEW: Direct assessment using TcpConnectionData
                                    // No TcpMetrics conversion needed - eliminates ~50ns overhead!
                                    //
                                    // Analyzes connection health based on:
                                    // - Full TCP connection data (conn_data)
                                    // - Remote address for context
                                    // - Historical trends (with FULL TCP health data!)
                                    //
                                    // BENEFITS over old API:
                                    // - No data loss from tcp_info → TcpMetrics conversion
                                    // - Better health assessment (includes retransmit rate, ssthresh)
                                    // - Simpler code (one function call vs two + conversion)
                                    // - Type safety (queue data can't be lost)
                                    let health = assess_connection_health_v2(
                                        conn_data,
                                        &remote_addr,
                                        history.as_ref(),
                                    );

                                    // === CONVERT TO TCPMETRICS FOR RESPONSE ===
                                    // Response format still uses TcpMetrics (for compatibility)
                                    // But we only convert AFTER health assessment
                                    // This means health gets full tcp_info data, not lossy conversion
                                    use cerberus::netlink::tcp_info_to_metrics;
                                    let metrics = tcp_info_to_metrics(&conn_data.tcp_info);

                                    // === BUILD SUCCESS RESPONSE ===
                                    // Response includes comprehensive health data
                                    // Health was assessed using v2 API with full connection data
                                    MonitorResponse::Single {
                                        timestamp,
                                        found: true,
                                        connection: Some(conn_info.clone()),
                                        tcp_metrics: Some(Box::new(metrics)),
                                        health: Some(health),
                                        error: None,
                                    }
                                });

                                // === LEGACY SS PATH: Use old approach ===
                                #[cfg(all(
                                    feature = "legacy_ss",
                                    not(all(target_os = "linux", feature = "netlink"))
                                ))]
                                let process_result = metrics_result.as_ref().map(|metrics| {
                                    let history = {
                                        let mut manager = history_manager.write();

                                        // Legacy: Only queue sizes available
                                        manager.add_sample_with_local(
                                            local_ip,
                                            local_port,
                                            &remote_ip,
                                            remote_port,
                                            conn_info.send_queue_bytes,
                                            conn_info.recv_queue_bytes,
                                        );

                                        manager
                                            .get_with_local(
                                                local_ip,
                                                local_port,
                                                &remote_ip,
                                                remote_port,
                                            )
                                            .cloned()
                                    };

                                    let health = assess_connection_health_with_history(
                                        &conn_info,
                                        metrics,
                                        history.as_ref(),
                                    );

                                    MonitorResponse::Single {
                                        timestamp,
                                        found: true,
                                        connection: Some(conn_info.clone()),
                                        tcp_metrics: Some(Box::new(metrics.clone())),
                                        health: Some(health),
                                        error: None,
                                    }
                                });

                                // === DEVELOPMENT PATH ===
                                #[cfg(not(any(
                                    all(target_os = "linux", feature = "netlink"),
                                    feature = "legacy_ss"
                                )))]
                                let process_result =
                                    metrics_result.map(|_| MonitorResponse::Single {
                                        timestamp,
                                        found: false,
                                        connection: None,
                                        tcp_metrics: None,
                                        health: None,
                                        error: Some("Not available".to_string()),
                                    });

                                // === HANDLE RESULT ===
                                match process_result {
                                    Ok(response) => response,

                                    // === METRICS RETRIEVAL FAILED ===
                                    // ss command failed or returned unparseable output
                                    //
                                    // STILL USEFUL:
                                    // We have connection info from /proc/net/tcp
                                    // Just missing detailed TCP metrics
                                    //
                                    // PARAMETER: Err(e)
                                    // e is the error (String describing what went wrong)
                                    Err(e) => MonitorResponse::Single {
                                        timestamp,
                                        found: true,
                                        connection: Some(conn_info),
                                        tcp_metrics: None, // No metrics available
                                        health: None,      // Can't assess health without metrics
                                        error: Some(format!("Could not retrieve TCP metrics: {e}")),
                                    },
                                }
                            }

                            // === CONNECTION NOT FOUND ===
                            // find_single_connection returned Err
                            //
                            // REASONS:
                            // - Connection doesn't exist
                            // - Connection closed
                            // - Wrong parameters
                            // - /proc/net/tcp read failure
                            Err(e) => MonitorResponse::Single {
                                timestamp,
                                found: false,
                                connection: None,
                                tcp_metrics: None,
                                health: None,
                                error: Some(e),
                            },
                        }
                    } else {
                        // ========================================================
                        // MULTIPLE CONNECTIONS QUERY PATH
                        // ========================================================
                        // remote_port was None, so we query ALL connections
                        // matching (local_ip, local_port, remote_ip)

                        // === STEP 1: Find all matching connections ===
                        //
                        // PARAMETERS:
                        // - local_ip: &str
                        // - local_port: u16
                        // - Some(&req.remote_ip): Option<&str>
                        //   We wrap &req.remote_ip in Some() to match function signature
                        //   Function signature: remote_ip: Option<&str>
                        //   None would mean "match any remote IP"
                        // - established_only: bool
                        //
                        // RETURN TYPE: Result<Vec<ConnectionInfo>, String>
                        // - Ok(connections) with vector of all matches
                        // - Err(error_message) if read failed
                        match find_connections_in_proc(
                            local_ip,
                            local_port,
                            Some(&req.remote_ip),
                            req.established_only,
                        ) {
                            Ok(connections) => {
                                // ================================================
                                // OPTIMIZATION: Batched ss Command
                                // ================================================
                                //
                                // === PROBLEM ===
                                // We have N connections
                                // Each needs TCP metrics from ss command
                                // Naive approach: N separate ss invocations
                                // COST: N process spawns, N parsing operations
                                //
                                // === SOLUTION ===
                                // Batch all queries into ONE ss invocation
                                // BENEFIT: 1 process spawn instead of N
                                // PERFORMANCE: With 5 connections, 80% fewer process spawns

                                // === BUILD CONNECTION TUPLES ===
                                // Create a list of all connections to query
                                //
                                // TYPE: Vec<(String, u16, String, u16)>
                                // Each tuple: (local_ip, local_port, remote_ip, remote_port)
                                //
                                // RUST ITERATOR CHAIN:
                                // connections.iter() creates iterator over &ConnectionInfo
                                // .map(|conn_info| { ... }) transforms each element
                                // .collect() consumes iterator and builds Vec
                                //
                                // WHY iter() vs into_iter()?
                                // iter() borrows - we still need connections later!
                                // into_iter() would consume connections (move ownership)
                                //
                                // Note: On non-Linux development platforms, this variable may appear unused
                                // because the batch functions aren't available. The #[allow] suppresses that warning.
                                #[allow(unused_variables)]
                                let conn_tuples: Vec<(
                                    String,
                                    u16,
                                    String,
                                    u16,
                                )> = connections
                                    .iter()
                                    .map(|conn_info| {
                                        // Extract remote IP and port from "IP:port" string
                                        let (remote_ip, remote_port) =
                                            extract_remote_parts(&conn_info.remote_address);

                                        // Build tuple with all 4 parts
                                        // local_ip.to_string() clones the string
                                        // WHY CLONE? Function returns owned tuple
                                        // Can't return borrowed &str (would be invalid after function returns)
                                        (local_ip.clone(), local_port, remote_ip, remote_port)
                                    })
                                    .collect();

                                // === BATCH METRICS CALL ===
                                //
                                // === CONDITIONAL COMPILATION: Netlink vs ss ===
                                // This code compiles to different implementations based on features:
                                //
                                // WITH netlink feature (default):
                                //   - Calls get_tcp_metrics_batch_netlink()
                                //   - Single Netlink query for all connections
                                //   - Performance: ~3 ms for 100 connections
                                //   - Improvement: 333x faster than subprocess batch!
                                //   - No process spawning overhead
                                //
                                // WITH legacy_ss feature:
                                //   - Calls get_tcp_metrics_batch()
                                //   - Single ss subprocess for all connections
                                //   - Performance: ~1000 ms for 100 connections
                                //   - Still better than N individual ss calls
                                //
                                // BOTH APPROACHES RETURN:
                                //   HashMap<(String, u16, String, u16), TcpMetrics>
                                //   Key: (local_ip, local_port, remote_ip, remote_port)
                                //   Value: TcpMetrics for that connection
                                //   PERFORMANCE: O(1) lookup time (hash table)
                                //   If connection not found, it won't be in map
                                //
                                // === COMPILATION BEHAVIOR ===
                                // Only ONE of these blocks compiles into the binary
                                // Zero runtime overhead - decision made at compile time

                                // === NETLINK PATH (default, RECOMMENDED) ===
                                // Compiles on Linux with netlink feature
                                // NOW GETS FULL CONNECTION DATA (tcp_info + queue sizes + state)
                                #[cfg(all(target_os = "linux", feature = "netlink"))]
                                let conn_data_map =
                                    get_tcp_connection_data_batch_netlink(&conn_tuples);

                                // === LEGACY SS PATH (fallback) ===
                                // Compiles when legacy_ss feature is enabled (any platform)
                                #[cfg(all(
                                    feature = "legacy_ss",
                                    not(all(target_os = "linux", feature = "netlink"))
                                ))]
                                let metrics_map = get_tcp_metrics_batch(&conn_tuples);

                                // === DEVELOPMENT/FALLBACK PATH ===
                                // On non-Linux platforms (macOS) or when no features enabled
                                // Returns empty map - no metrics available
                                #[cfg(not(any(
                                        all(target_os = "linux", feature = "netlink"),
                                        feature = "legacy_ss"
                                    )))]
                                    let _metrics_map: std::collections::HashMap<(String, u16, String, u16), cerberus::TcpMetrics> =
                                        std::collections::HashMap::new();

                                // === BUILD CONNECTION DATA WITH FULL TCP INFO ===
                                // Combine connection info with pre-fetched data
                                // Different paths for netlink (full data) vs legacy (metrics only)

                                // === NETLINK PATH: Full TcpConnectionData ===
                                #[cfg(all(target_os = "linux", feature = "netlink"))]
                                let conn_data: Vec<(
                                    ConnectionInfo,
                                    String,
                                    u16,
                                    Option<cerberus::netlink::TcpConnectionData>,
                                )> = connections
                                    .into_iter()
                                    .map(|conn_info| {
                                        let (remote_ip, remote_port) =
                                            extract_remote_parts(&conn_info.remote_address);

                                        let key = (
                                            local_ip.clone(),
                                            local_port,
                                            remote_ip.clone(),
                                            remote_port,
                                        );

                                        // Lookup full connection data from batch result
                                        let conn_data_opt = conn_data_map.get(&key).cloned();

                                        (conn_info, remote_ip, remote_port, conn_data_opt)
                                    })
                                    .collect();

                                // === LEGACY SS PATH: Only TcpMetrics ===
                                #[cfg(all(
                                    feature = "legacy_ss",
                                    not(all(target_os = "linux", feature = "netlink"))
                                ))]
                                let conn_data: Vec<(
                                    ConnectionInfo,
                                    String,
                                    u16,
                                    Option<TcpMetrics>,
                                )> = connections
                                    .into_iter()
                                    .map(|conn_info| {
                                        let (remote_ip, remote_port) =
                                            extract_remote_parts(&conn_info.remote_address);

                                        let key = (
                                            local_ip.to_string(),
                                            local_port,
                                            remote_ip.clone(),
                                            remote_port,
                                        );

                                        let tcp_metrics = metrics_map.get(&key).cloned();

                                        (conn_info, remote_ip, remote_port, tcp_metrics)
                                    })
                                    .collect();

                                // === DEVELOPMENT PATH: No metrics ===
                                #[cfg(not(any(
                                    all(target_os = "linux", feature = "netlink"),
                                    feature = "legacy_ss"
                                )))]
                                let conn_data: Vec<(
                                    ConnectionInfo,
                                    String,
                                    u16,
                                    Option<TcpMetrics>,
                                )> = connections
                                    .into_iter()
                                    .map(|conn_info| {
                                        let (remote_ip, remote_port) =
                                            extract_remote_parts(&conn_info.remote_address);

                                        (conn_info, remote_ip, remote_port, None)
                                    })
                                    .collect();

                                // ================================================
                                // OPTIMIZATION: Single Lock for All Operations
                                // ================================================
                                //
                                // === OLD APPROACH ===
                                // For each connection:
                                //   1. Get write lock, add sample, release
                                //   2. Get read lock, get history, release
                                // COST: N * 2 lock acquisitions
                                //
                                // === NEW APPROACH ===
                                // 1. Get write lock ONCE
                                // 2. Add ALL samples
                                // 3. Get ALL histories
                                // 4. Release lock
                                // COST: 1 lock acquisition
                                //
                                // === EXAMPLE ===
                                // With 5 connections:
                                // Old: 10 lock operations
                                // New: 1 lock operation
                                // Improvement: 90% reduction!
                                //
                                // === SCOPE BLOCK ===
                                // Curly braces control lock guard lifetime
                                let histories = {
                                    // === ACQUIRE WRITE LOCK ===
                                    // Exclusive access to HistoryManager
                                    let mut manager = history_manager.write();

                                    // === ADD ALL SAMPLES ===
                                    // Loop through connection data and add to history
                                    // Different methods for netlink (full data) vs legacy (queue only)

                                    // === NETLINK PATH: Add with full TCP health data ===
                                    #[cfg(all(target_os = "linux", feature = "netlink"))]
                                    for (conn_info, remote_ip, remote_port, conn_data_opt) in
                                        &conn_data
                                    {
                                        // If we have full connection data, add it with TCP metrics
                                        // Otherwise fall back to queue-only method
                                        if let Some(tcp_conn_data) = conn_data_opt {
                                            // NEW: Add with full TCP health data
                                            // This populates ALL TCP health metrics!
                                            manager.add_sample_from_netlink(
                                                local_ip,
                                                local_port,
                                                remote_ip,
                                                *remote_port,
                                                tcp_conn_data,
                                            );
                                        } else {
                                            // Fallback: Only queue data available
                                            manager.add_sample_with_local(
                                                local_ip,
                                                local_port,
                                                remote_ip,
                                                *remote_port,
                                                conn_info.send_queue_bytes,
                                                conn_info.recv_queue_bytes,
                                            );
                                        }
                                    }

                                    // === LEGACY SS PATH: Add with queue data only ===
                                    #[cfg(all(
                                        feature = "legacy_ss",
                                        not(all(target_os = "linux", feature = "netlink"))
                                    ))]
                                    for (conn_info, remote_ip, remote_port, _) in &conn_data {
                                        manager.add_sample_with_local(
                                            local_ip,
                                            local_port,
                                            remote_ip,
                                            *remote_port,
                                            conn_info.send_queue_bytes,
                                            conn_info.recv_queue_bytes,
                                        );
                                    }

                                    // === DEVELOPMENT PATH: Add with queue data only ===
                                    #[cfg(not(any(
                                        all(target_os = "linux", feature = "netlink"),
                                        feature = "legacy_ss"
                                    )))]
                                    for (conn_info, remote_ip, remote_port, _) in &conn_data {
                                        manager.add_sample_with_local(
                                            local_ip,
                                            local_port,
                                            remote_ip,
                                            *remote_port,
                                            conn_info.send_queue_bytes,
                                            conn_info.recv_queue_bytes,
                                        );
                                    }

                                    // === GET ALL HISTORIES ===
                                    // Retrieve historical data for all connections
                                    //
                                    // ITERATOR CHAIN:
                                    // conn_data.iter() creates iterator over references
                                    // .map() transforms each element
                                    // .collect::<Vec<_>>() builds vector
                                    //   ::<Vec<_>> explicitly specifies type
                                    //   _ means "infer element type" (compiler figures it out)
                                    //
                                    // RETURN TYPE: Vec<Option<ConnectionHistory>>
                                    // Each element is Option because:
                                    // - Some(history) if we have samples for this connection
                                    // - None if this is first sample for this connection
                                    conn_data
                                        .iter()
                                        .map(|(_, remote_ip, remote_port, _)| {
                                            // Get history for this connection
                                            //
                                            // RETURN: Option<&ConnectionHistory>
                                            // .cloned(): Option<&T> → Option<T>
                                            // Clone the history so we can release the lock
                                            manager
                                                .get_with_local(
                                                    local_ip,
                                                    local_port,
                                                    remote_ip,
                                                    *remote_port,
                                                )
                                                .cloned()
                                        })
                                        .collect::<Vec<_>>()

                                    // === LOCK RELEASED HERE ===
                                    // `manager` goes out of scope
                                    // Drop trait automatically releases write lock
                                };

                                // ================================================
                                // BUILD RESPONSE (NO LOCKS NEEDED)
                                // ================================================
                                //
                                // At this point we have:
                                // - conn_data: Vec of (ConnectionInfo, IP, port, metrics)
                                // - histories: Vec of Option<ConnectionHistory>
                                //
                                // Now we combine them to build response
                                // NO LOCKS NEEDED: All data is owned by this function

                                // === COMBINE DATA WITH ZIP ===
                                // conn_data.into_iter() consumes the vector
                                // .zip(histories) combines two iterators pairwise
                                //
                                // WHAT IS ZIP?
                                // Takes two iterators, produces pairs:
                                // [a, b, c].zip([1, 2, 3]) → [(a,1), (b,2), (c,3)]
                                //
                                // HERE:
                                // Each iteration gives us:
                                // - One element from conn_data
                                // - Corresponding element from histories
                                //
                                // TYPE SIGNATURE:
                                // Vec<ConnectionWithHealth>
                                // Each element contains connection, metrics, and health
                                let mut conn_with_health: Vec<ConnectionWithHealth> = conn_data
                                    .into_iter()
                                    .zip(histories)
                                    .map(
                                        |(
                                            (
                                                conn_info,
                                                remote_ip,
                                                remote_port,
                                                tcp_data_or_metrics,
                                            ),
                                            history,
                                        )| {
                                            // ================================================
                                            // ASSESS HEALTH - Different paths for v2 vs legacy
                                            // ================================================
                                            //
                                            // Note: remote_ip and remote_port are used in netlink path
                                            // but not in legacy_ss/development paths (conditional compilation)

                                            // === NETLINK PATH: Use v2 API ===
                                            #[cfg(all(target_os = "linux", feature = "netlink"))]
                                            let (tcp_metrics, health) = {
                                                // Build remote address for v2 API
                                                let remote_addr =
                                                    format!("{}:{}", remote_ip, remote_port);

                                                // Assess health using v2 API if we have connection data
                                                // NEW: Direct assessment without TcpMetrics conversion
                                                let health =
                                                    tcp_data_or_metrics.as_ref().map(|conn_data| {
                                                        assess_connection_health_v2(
                                                            conn_data,
                                                            &remote_addr,
                                                            history.as_ref(),
                                                        )
                                                    });

                                                // Convert to TcpMetrics for response (after health assessment)
                                                // This preserves full data for health while maintaining response format
                                                let tcp_metrics =
                                                    tcp_data_or_metrics.map(|conn_data| {
                                                        use cerberus::netlink::tcp_info_to_metrics;
                                                        tcp_info_to_metrics(&conn_data.tcp_info)
                                                    });

                                                (tcp_metrics, health)
                                            };

                                            // === LEGACY SS PATH: Use old API ===
                                            #[cfg(all(
                                                feature = "legacy_ss",
                                                not(all(
                                                    target_os = "linux",
                                                    feature = "netlink"
                                                ))
                                            ))]
                                            let (tcp_metrics, health) = {
                                                // Already TcpMetrics, no conversion needed
                                                let tcp_metrics = tcp_data_or_metrics;

                                                // Use old health assessment API
                                                let health = tcp_metrics.as_ref().map(|metrics| {
                                                    assess_connection_health_with_history(
                                                        &conn_info,
                                                        metrics,
                                                        history.as_ref(),
                                                    )
                                                });

                                                (tcp_metrics, health)
                                            };

                                            // === DEVELOPMENT PATH: Use old API ===
                                            #[cfg(not(any(
                                                all(target_os = "linux", feature = "netlink"),
                                                feature = "legacy_ss"
                                            )))]
                                            let (tcp_metrics, health) = {
                                                // Already TcpMetrics (Option<TcpMetrics>)
                                                let tcp_metrics = tcp_data_or_metrics;

                                                // Use old health assessment API (no actual assessment on dev platform)
                                                let health = tcp_metrics.as_ref().map(|metrics| {
                                                    assess_connection_health_with_history(
                                                        &conn_info,
                                                        metrics,
                                                        history.as_ref(),
                                                    )
                                                });

                                                (tcp_metrics, health)
                                            };

                                            // === BUILD RESPONSE ELEMENT ===
                                            // ConnectionWithHealth is a struct with 3 fields
                                            //
                                            // OWNERSHIP:
                                            // All values are moved into this struct
                                            // Can't use them after this point
                                            ConnectionWithHealth {
                                                connection: conn_info,
                                                tcp_metrics,
                                                health,
                                            }
                                        },
                                    )
                                    .collect();

                                // === SORT BY HEALTH IF REQUESTED ===
                                // Client can request results sorted by health score
                                //
                                // .sort_by() takes a comparison function
                                // Signature: fn(&T, &T) -> Ordering
                                //
                                // .cmp_by_health(b) is a method on ConnectionWithHealth
                                // Returns Ordering:
                                // - Less: a should come before b
                                // - Equal: same health score
                                // - Greater: a should come after b
                                //
                                // PERFORMANCE: O(n log n) time complexity (quicksort)
                                // MEMORY: Sorts in-place (no extra allocation)
                                if req.sort_by_health {
                                    // conn_with_health.sort_by(|a, b| a.cmp_by_health(b));
                                    conn_with_health
                                        .sort_by(cerberus::ConnectionWithHealth::cmp_by_health);
                                }

                                // === BUILD ERROR MESSAGE IF EMPTY ===
                                // If we found no connections, include helpful error
                                //
                                // .is_empty() checks if vector has length 0
                                // Returns bool (true if empty)
                                //
                                // TERNARY-LIKE PATTERN:
                                // if condition { Some(value) } else { None }
                                // This builds an Option based on condition
                                // let error = if conn_with_health.is_empty() {
                                //     Some("No connections found".to_string())
                                // } else {
                                //     None
                                // };
                                let error = conn_with_health
                                    .is_empty()
                                    .then(|| "No connections found".to_owned());

                                // === BUILD MULTIPLE RESPONSE ===
                                // MonitorResponse::Multiple variant
                                //
                                // FIELDS:
                                // - timestamp: When this response was generated
                                // - count: Number of connections found
                                //   .len() returns usize (vector length)
                                // - sorted_by_health: Whether results are sorted
                                // - connections: The actual connection data
                                // - error: Optional error message
                                MonitorResponse::Multiple {
                                    timestamp,
                                    count: conn_with_health.len(),
                                    sorted_by_health: req.sort_by_health,
                                    connections: conn_with_health,
                                    error,
                                }
                            }

                            // === FIND CONNECTIONS FAILED ===
                            // find_connections_in_proc returned Err
                            //
                            // REASONS:
                            // - /proc/net/tcp read failure
                            // - Permission denied
                            // - File doesn't exist (not Linux)
                            Err(e) => MonitorResponse::Multiple {
                                timestamp,
                                count: 0,
                                sorted_by_health: req.sort_by_health,
                                connections: vec![], // Empty vector
                                error: Some(e),
                            },
                        }
                    };

                    // ================================================
                    // SEND HTTP RESPONSE
                    // ================================================

                    // === SERIALIZE TO JSON ===
                    // Convert Rust struct → JSON string
                    //
                    // serde_json::to_string_pretty(&response)
                    // PARAMETERS:
                    // &response: Borrowed MonitorResponse
                    //   Function only needs to read it
                    //   We still own it (not moved)
                    //
                    // RETURN TYPE: Result<String, serde_json::Error>
                    //
                    // .unwrap() extracts Ok value, panics on Err
                    // WHY SAFE HERE?
                    // MonitorResponse is designed to always serialize successfully
                    // If it fails, it's a programming error (not runtime error)
                    // Better to crash and fix the bug than silently fail
                    //
                    // to_string_pretty adds formatting (newlines, indentation)
                    // ALTERNATIVE: to_string() is more compact (no whitespace)
                    let json_body = serde_json::to_string_pretty(&response).unwrap();

                    // === BUILD HTTP RESPONSE ===
                    // format!() is like printf/sprintf in C
                    // {} are placeholders for arguments
                    //
                    // HTTP RESPONSE FORMAT:
                    // HTTP/1.1 200 OK\r\n              <- Status line
                    // Content-Type: application/json\r\n <- Headers
                    // Content-Length: {}\r\n
                    // Connection: close\r\n
                    // \r\n                              <- Blank line (end of headers)
                    // {}                                <- Body (JSON)
                    //
                    // WHY Content-Length?
                    // Tells client how many bytes to read
                    // json_body.len() returns number of bytes (not characters!)
                    //
                    // WHY Connection: close?
                    // We don't support keep-alive
                    // Client should close connection after receiving response
                    let http_response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        json_body.len(),
                        json_body
                    );

                    // === WRITE RESPONSE TO SOCKET ===
                    // stream.write_all() writes ALL bytes to socket
                    //
                    // .as_bytes() converts String → &[u8] (byte slice)
                    // WHY? Network sockets work with bytes, not characters
                    //
                    // RETURN TYPE: Result<(), io::Error>
                    // - Ok(()) means all bytes written successfully
                    // - Err(e) means write failed (connection closed, etc.)
                    //
                    // `let _ = ...` ignores the result
                    // WHY? We're about to close connection anyway
                    // If write fails, not much we can do
                    // Client will see connection closed
                    let _ = stream.write_all(http_response.as_bytes());
                }
                // === JSON PARSE ERROR ===
                // Client sent invalid JSON or wrong structure
                else {
                    // Build error response
                    // HTTP 400 = Bad Request (client error)
                    let error_response = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n\
                             {\"error\": \"Invalid JSON format\"}\n";
                    let _ = stream.write_all(error_response.as_bytes());
                }
            }
        } else if request.starts_with("GET /health") {
            // === ENDPOINT: GET /health ===
            // Simple health check endpoint
            // Returns 200 OK if server is running
            //
            // USE CASE: Load balancers, monitoring systems
            // They can check if service is alive
            let health_response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n\
                 {\"status\": \"ok\"}\n";
            let _ = stream.write_all(health_response.as_bytes());
        } else if request.starts_with("GET /config") {
            // === ENDPOINT: GET /config ===
            // Returns server configuration information
            //
            // USEFUL FOR:
            // - Clients to discover server capabilities
            // - Debugging (what version is running?)
            // - Feature detection

            // Build configuration response struct
            let config_resp = ConfigResponse {
                http_server_info:
                    "Cerberus TCP Monitor v0.1.0 - Dynamic socket monitoring per request"
                        .to_string(),
                monitor_per_request: true,
            };

            // Serialize to JSON
            let json_body = serde_json::to_string_pretty(&config_resp).unwrap();

            // Build HTTP response
            let http_response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                json_body.len(),
                json_body
            );
            let _ = stream.write_all(http_response.as_bytes());
        } else {
            // === UNKNOWN ENDPOINT ===
            // Client requested a path we don't support
            //
            // HTTP 404 = Not Found
            // This is the standard response for unknown paths
            let not_found = "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n\
                 Not Found\n";
            let _ = stream.write_all(not_found.as_bytes());
        }
    }

    // === FUNCTION ENDS, STREAM CLOSED ===
    // When this function returns, `stream` goes out of scope
    // TcpStream implements Drop trait
    // Drop automatically closes the socket
    // This is RAII: Resource Acquisition Is Initialization
    // Resources are tied to object lifetime
    // No need for manual close() call
    // BENEFIT: Can't forget to close socket (memory safety + resource safety)
}

// ============================================================================
// MAIN FUNCTION - PROGRAM ENTRY POINT
// ============================================================================

/// Main entry point for TCP Monitor HTTP server
///
/// === WHAT THIS DOES ===
/// 1. Parse command line arguments (HTTP port)
/// 2. Create shared history manager for all threads
/// 3. Create thread pool for handling requests
/// 4. Listen for HTTP connections
/// 5. Dispatch each connection to thread pool
/// 6. Periodically cleanup stale connection history
/// 7. Graceful shutdown on Ctrl-C
///
/// === THREADING MODEL ===
/// - Main thread: Accept connections, dispatch to workers
/// - Worker threads: Handle client requests (from thread pool)
/// - Signal handler: Sets shutdown flag when Ctrl-C pressed
///
/// === CONCURRENCY ===
/// - Arc<`RwLock`<HistoryManager>>: Shared mutable state
/// - Arc<AtomicBool>: Shared shutdown flag
/// - Thread pool: Limits concurrent request processing
///
/// Note: Local IP and port are now specified in each API request, not at startup
fn main() {
    // === PARSE COMMAND LINE ARGUMENTS ===
    //
    // std::env::args() returns iterator over command line arguments
    // FIRST ARGUMENT: Program name (argv[0] in C)
    // SUBSEQUENT ARGUMENTS: User-provided arguments
    //
    // .collect() builds Vec<String> from iterator
    // WHY Vec? We want to index into arguments (args[1])
    //
    // TYPE: Vec<String>
    // Each argument is owned String (not &str)
    let args: Vec<String> = env::args().collect();

    // === PARSE HTTP PORT PARAMETER ===
    //
    // LOGIC:
    // If user provided argument (args.len() > 1), parse it as port number
    // If not provided or invalid, use default
    //
    // PATTERN: `let port: u16 = if condition { value1 } else { value2 };`
    // This is an expression (evaluates to a value)
    // The type of value1 and value2 must match (both u16)
    let http_port: u16 = if args.len() > 1 {
        // === PARSE STRING TO INTEGER ===
        // args[1] is String (owned)
        // .parse() attempts to convert string → number
        //
        // GENERIC METHOD: parse::<u16>()
        // Could also write: args[1].parse()
        // Compiler can infer u16 from `http_port: u16` declaration
        //
        // RETURN TYPE: Result<u16, ParseIntError>
        // - Ok(port) if string is valid number
        // - Err(e) if string is not a number or out of range
        //
        // .unwrap_or_else(|_| { ... })
        // If Ok(port), return port
        // If Err(_), run the closure (anonymous function)
        //
        // CLOSURE: |_| { ... }
        // |_| means "function with one parameter we ignore"
        // Parameter is the error, but we don't use it
        args[1].parse().unwrap_or_else(|_| {
            // Print error to stderr (not stdout)
            // eprintln! is like println! but writes to stderr
            // WHY stderr? Error messages should go to stderr, not stdout
            // This allows users to separate normal output from errors
            eprintln!("Invalid HTTP port, using default {DEFAULT_HTTP_PORT}");

            // Return default port
            DEFAULT_HTTP_PORT
        })
    } else {
        // No argument provided, use default
        DEFAULT_HTTP_PORT
    };

    // ================================================
    // CREATE SHARED HISTORY MANAGER
    // ================================================
    //
    // === GOAL ===
    // We need ONE HistoryManager shared across ALL worker threads
    //
    // === TYPE: Arc<RwLock<HistoryManager>> ===
    // Let's break this down from inside out:
    //
    // 1. HistoryManager: The actual data structure
    //    Stores ring buffers of queue samples per connection
    //
    // 2. RwLock<HistoryManager>: Adds safe concurrent access
    //    RULES:
    //    - Many threads can read simultaneously (.read())
    //    - Only one thread can write (.write())
    //    - Writers have exclusive access (no readers allowed)
    //
    //    WHY RwLock vs Mutex?
    //    - Mutex: Only one thread at a time (read OR write)
    //    - RwLock: Many readers OR one writer
    //    - BENEFIT: If we have 10 readers, they can all run in parallel
    //
    // 3. Arc<RwLock<HistoryManager>>: Adds shared ownership
    //    Arc = Atomic Reference Counted
    //
    //    HOW ARC WORKS:
    //    - Maintains reference count using atomic operations
    //    - Each .clone() increments count (cheap, just adds 1)
    //    - Each drop decrements count
    //    - When count reaches 0, inner data is freed
    //
    //    WHY ARC?
    //    - We pass HistoryManager to multiple threads
    //    - Each thread needs to "own" it (can't have dangling references)
    //    - Can't use normal references (lifetime too complex)
    //    - Arc solves this: shared ownership across threads
    //
    // === CONSTRUCTION ===
    // HistoryManager::new() creates new empty HistoryManager
    // RwLock::new() wraps it in a read-write lock
    // Arc::new() wraps that in atomic reference counting
    //
    // MEMORY:
    // This allocates on the heap (not stack)
    // WHY? Stack is thread-local, heap is shared
    // Arc points to heap memory
    let history_manager = Arc::new(RwLock::new(HistoryManager::new()));

    // ================================================
    // CREATE THREAD POOL
    // ================================================
    //
    // === GOAL ===
    // Handle multiple client requests in parallel
    //
    // === WHY THREAD POOL? ===
    // PROBLEM: Creating thread per request is expensive
    // - System call overhead (clone/spawn)
    // - Stack allocation (usually 2MB per thread)
    // - Context switching overhead
    //
    // SOLUTION: Thread pool
    // - Create N threads once at startup
    // - Reuse threads for all requests
    // - Threads wait on queue for work
    //
    // === OPTIMAL THREAD COUNT ===
    // Rule of thumb:
    // - CPU-bound work: 1x CPU core count
    // - I/O-bound work: 2x-4x CPU core count
    //
    // WHY MORE THREADS FOR I/O?
    // When thread waits for I/O (reading /proc, running ss command),
    // CPU is idle. Having more threads lets CPU work on other requests
    // while some threads are blocked on I/O.
    //
    // === GET CPU COUNT ===
    // std::thread::available_parallelism() returns number of CPU cores
    //
    // RETURN TYPE: Result<NonZeroUsize, io::Error>
    // - Ok(count) on success
    // - Err(e) if can't determine (rare)
    //
    // NonZeroUsize: Guaranteed to be >= 1 (type-level guarantee)
    // .get() extracts the usize value
    //
    // .map(|n| n.get()): If Ok, extract value
    // .unwrap_or(4): If Err, use 4 as default
    let cpu_count = std::thread::available_parallelism()
        .map(std::num::NonZero::get)
        .unwrap_or(4);

    // === CALCULATE THREAD COUNT ===
    // Formula: 2x CPU count (for I/O-bound work)
    //
    // .clamp(4, 16) restricts to range [4, 16]
    // WHY MINIMUM 4?
    // - Single-core systems exist (Raspberry Pi, VMs)
    // - Want some parallelism even on small systems
    //
    // WHY MAXIMUM 16?
    // - Too many threads causes overhead (context switching)
    // - Diminishing returns beyond certain point
    // - 16 is reasonable for most systems
    //
    // EXAMPLE:
    // - 1 CPU: (1 * 2).clamp(4, 16) → 4 threads
    // - 4 CPUs: (4 * 2).clamp(4, 16) → 8 threads
    // - 16 CPUs: (16 * 2).clamp(4, 16) → 16 threads (clamped at max)
    let thread_count = (cpu_count * 2).clamp(4, 16);

    // Print thread pool configuration to stderr
    // This helps with debugging and understanding system behavior
    eprintln!("System has {cpu_count} CPU cores, creating thread pool with {thread_count} workers");

    // === CREATE THREAD POOL ===
    // ThreadPool::new(n) creates pool with n worker threads
    //
    // WHAT HAPPENS:
    // 1. Creates n OS threads immediately
    // 2. Each thread waits on a channel for work
    // 3. .execute(closure) sends closure to channel
    // 4. First available thread picks it up and runs it
    //
    // LIFETIME:
    // Threads live until:
    // - pool.join() is called (wait for all work to complete)
    // - pool is dropped (automatic shutdown)
    let pool = ThreadPool::new(thread_count);

    // ================================================
    // BIND TCP LISTENER
    // ================================================
    //
    // === WHAT IS TcpListener? ===
    // A socket that listens for incoming TCP connections
    // Like calling socket() + bind() + listen() in C
    //
    // === BIND ADDRESS ===
    // format!("127.0.0.1:{}", http_port) builds string like "127.0.0.1:8080"
    //
    // WHY 127.0.0.1?
    // - Loopback address (localhost)
    // - Only accepts connections from same machine
    // - MORE SECURE: Not exposed to network
    //
    // ALTERNATIVE: 0.0.0.0 would listen on all interfaces (less secure)
    //
    // === ERROR HANDLING ===
    // TcpListener::bind() returns Result<TcpListener, io::Error>
    // .expect("message") unwraps Ok, panics on Err with custom message
    //
    // WHY PANIC ON ERROR?
    // If we can't bind the port, program can't function
    // Better to crash immediately with clear error message
    // than continue in broken state
    //
    // COMMON REASONS FOR FAILURE:
    // - Port already in use
    // - Permission denied (ports < 1024 need root)
    // - Invalid port number
    let listener =
        TcpListener::bind(format!("127.0.0.1:{http_port}")).expect("Failed to bind to address");

    // === PRINT STARTUP INFORMATION ===
    // Print to stdout (not stderr) - this is normal program output
    println!("TCP Monitor HTTP Server - Version 1.1");
    println!("======================================");
    println!("HTTP server listening on: 127.0.0.1:{http_port}");
    println!("\nEndpoints:");
    println!("  POST http://127.0.0.1:{http_port}/monitor - Monitor connection(s)");
    println!("  GET  http://127.0.0.1:{http_port}/health  - Health check");
    println!("  GET  http://127.0.0.1:{http_port}/config  - Show configuration");
    println!("\nRequest Format (POST /monitor):");
    println!("  Required fields in JSON:");
    println!("    - local_ip: IP address to monitor");
    println!("    - local_port: Port to monitor");
    println!("    - remote_ip: Remote IP to query");
    println!("  Optional fields:");
    println!("    - remote_port: Remote port (omit for all ports)");
    println!("    - established_only: bool (default: true)");
    println!("    - sort_by_health: bool (default: true)");
    println!("\nFeatures:");
    println!("  - Dynamic socket monitoring: specify local_ip:local_port per request");
    println!("  - Trend analysis: tracks last 10 queue samples");
    println!("  - Health assessment: uses historical context");
    println!("  - 4-tuple keyed history: local_ip:local_port:remote_ip:remote_port");
    println!("\nPress Ctrl+C to stop\n");

    // ================================================
    // SETUP SHUTDOWN SIGNAL HANDLING
    // ================================================
    //
    // === GOAL ===
    // Gracefully shutdown when user presses Ctrl-C
    //
    // === ATOMIC BOOL FOR SHUTDOWN FLAG ===
    //
    // TYPE: Arc<AtomicBool>
    //
    // AtomicBool: Thread-safe boolean
    // OPERATIONS:
    // - .load(ordering): Read current value
    // - .store(value, ordering): Write new value
    //
    // WHY ATOMIC?
    // Regular bool would cause data races:
    // - Thread 1 reads: false
    // - Thread 2 writes: true
    // - Thread 1 still sees false (cached in CPU register)
    // - Program never shuts down!
    //
    // ATOMIC GUARANTEE:
    // All threads see changes immediately (memory fence)
    // No caching issues, no data races
    //
    // Arc<AtomicBool>: So we can share between main loop and signal handler
    // Arc::new(AtomicBool::new(true)) creates flag initialized to true
    let running = Arc::new(AtomicBool::new(true));

    // === CLONE ARC FOR SIGNAL HANDLER ===
    // Arc::clone() increments reference count
    // Now we have 2 Arc pointers to same AtomicBool:
    // - `running`: Used in main loop
    // - `r`: Used in signal handler closure
    //
    // MEMORY:
    // Only ONE AtomicBool exists (on heap)
    // Both Arc pointers refer to same memory
    // Arc keeps memory alive until both are dropped
    let r = running.clone();

    // === TRACK LAST CLEANUP TIME ===
    // Instant: Monotonic clock (for measuring elapsed time)
    // WHY Instant vs SystemTime?
    // - Instant never goes backwards (even if user changes clock)
    // - Perfect for measuring durations
    // - Can't be converted to wall clock time (that's ok here)
    let mut last_cleanup = Instant::now();

    // === REGISTER SIGNAL HANDLER ===
    // ctrlc crate provides cross-platform Ctrl-C handling
    //
    // .set_handler() takes a closure (anonymous function)
    // This closure runs when user presses Ctrl-C
    //
    // CLOSURE: move || { ... }
    // `move` keyword: Closure takes OWNERSHIP of variables it uses
    // HERE: Takes ownership of `r` (the Arc<AtomicBool>)
    //
    // WHY move?
    // Signal handler might run after main() returns
    // Can't have borrowed reference (would be dangling)
    // Taking ownership (via Arc) keeps data alive
    //
    // THREAD SAFETY:
    // Signal handler runs in separate thread (signal handling thread)
    // Arc and AtomicBool are both thread-safe
    // Safe to access from multiple threads
    ctrlc::set_handler(move || {
        // === SET SHUTDOWN FLAG ===
        // r.store(false, ...) writes false to AtomicBool
        //
        // ATOMIC ORDERING: SeqCst (Sequentially Consistent)
        // This is the strongest ordering guarantee:
        // - All threads see operations in same order
        // - No reordering by compiler or CPU
        //
        // ALTERNATIVES:
        // - Relaxed: Weakest, allows reordering (not safe here)
        // - Acquire/Release: Medium strength
        // - SeqCst: Strongest, always correct (slight performance cost)
        //
        // WHEN TO USE SeqCst?
        // When you're not sure, use SeqCst (safe default)
        // Profile first if you suspect performance issue
        r.store(false, AtomicOrdering::SeqCst);
    })
    .expect("Error setting Ctrl-C handler");

    // ================================================
    // CONFIGURE NON-BLOCKING SOCKET
    // ================================================
    //
    // === WHY NON-BLOCKING? ===
    // By default, listener.accept() BLOCKS (waits forever for connection)
    // Problem: Can't check shutdown flag while blocked
    //
    // SOLUTION: Non-blocking mode
    // listener.accept() returns immediately:
    // - Ok(stream, addr): New connection
    // - Err(WouldBlock): No connection available right now
    //
    // BENEFIT: We can check shutdown flag every iteration
    //
    // .set_nonblocking(true) enables non-blocking mode
    // RETURN TYPE: Result<(), io::Error>
    // .expect() panics if this fails (shouldn't happen)
    listener
        .set_nonblocking(true)
        .expect("Cannot set non-blocking");

    // ================================================
    // MAIN SERVER LOOP
    // ================================================
    //
    // === LOOP WHILE RUNNING ===
    // running.load(AtomicOrdering::SeqCst) reads shutdown flag
    // Returns true (keep running) or false (shutdown)
    //
    // EVERY ITERATION:
    // 1. Check for new connection
    // 2. Check if cleanup needed
    // 3. Check shutdown flag
    //
    // LOOP EXITS when running becomes false (Ctrl-C pressed)
    while running.load(AtomicOrdering::SeqCst) {
        // === TRY TO ACCEPT CONNECTION ===
        // listener.accept() attempts to accept incoming connection
        //
        // RETURN TYPE: Result<(TcpStream, SocketAddr), io::Error>
        // - Ok((stream, addr)): New connection
        //   stream: Socket for talking to client
        //   addr: Client's IP address and port
        // - Err(e): Error occurred
        //
        // PATTERN: `match listener.accept()`
        // Handle different cases
        match listener.accept() {
            // === NEW CONNECTION ARRIVED ===
            Ok((stream, _)) => {
                // _ means we ignore the SocketAddr (don't need it)

                // === CLONE ARC FOR WORKER THREAD ===
                // Arc::clone() increments reference count
                // Creates new Arc pointer to same HistoryManager
                //
                // WHY CLONE?
                // Worker thread needs to own an Arc
                // Can't move `history_manager` (we need it for next connection)
                // Cloning Arc is cheap (just increment atomic counter)
                //
                // MEMORY:
                // Still only ONE HistoryManager on heap
                // Just more Arc pointers to it
                let history_clone = Arc::clone(&history_manager);

                // === DISPATCH TO THREAD POOL ===
                // pool.execute() sends closure to thread pool
                //
                // CLOSURE: move || { ... }
                // `move` captures variables by ownership
                // HERE: Takes ownership of `stream` and `history_clone`
                //
                // WHY move?
                // - Closure runs in different thread
                // - That thread needs to own the data
                // - Can't borrow (lifetime would be invalid)
                //
                // WHAT HAPPENS:
                // 1. Closure is sent to channel
                // 2. First available worker thread picks it up
                // 3. Worker runs handle_client()
                // 4. Worker returns to pool, waits for next task
                //
                // CONCURRENCY:
                // Multiple workers can run handle_client() in parallel
                // Each has its own `stream` (different clients)
                // All share same `history_manager` (via Arc<RwLock<>>)
                pool.execute(move || {
                    handle_client(stream, history_clone);
                });
            }

            // === NO CONNECTION AVAILABLE (WOULD BLOCK) ===
            // In non-blocking mode, this is normal (not an error)
            //
            // PATTERN: `Err(ref e) if e.kind() == ...`
            // ref e: Borrow the error (don't move it)
            // WHY ref? We just need to check error type, not consume it
            //
            // e.kind() returns ErrorKind enum
            // WouldBlock means "operation would block but we're in non-blocking mode"
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // ================================================
                // PERIODIC CLEANUP
                // ================================================
                //
                // === GOAL ===
                // Remove history for connections that haven't been queried recently
                // Prevents unbounded memory growth
                //
                // === CHECK IF CLEANUP NEEDED ===
                // last_cleanup.elapsed() returns Duration since last cleanup
                // .as_secs() converts Duration to seconds (u64)
                //
                // >= 60: At least 60 seconds passed
                if last_cleanup.elapsed().as_secs() >= 60 {
                    // === ACQUIRE WRITE LOCK ===
                    // Need exclusive access to modify HistoryManager
                    let mut manager = history_manager.write();

                    // === RUN CLEANUP ===
                    // Removes entries older than threshold (defined in HistoryManager)
                    manager.cleanup_stale_connections();

                    // === GET CONNECTION COUNT ===
                    // How many connections are we tracking?
                    let count = manager.connection_count();

                    // === LOG STATUS ===
                    // Only print if we're tracking connections
                    // Avoids spam when idle
                    if count > 0 {
                        eprintln!(
                            "[{}] Tracking {} connections",
                            last_cleanup.elapsed().as_secs(),
                            count
                        );
                    }

                    // === RESET CLEANUP TIMER ===
                    // Instant::now() gets current time
                    // Next cleanup in 60 seconds
                    last_cleanup = Instant::now();

                    // === LOCK RELEASED HERE ===
                    // `manager` goes out of scope
                    // Drop trait releases write lock
                }

                // === SLEEP TO AVOID BUSY LOOP ===
                // Without sleep, this loop would spin at 100% CPU
                // checking for connections constantly
                //
                // std::thread::sleep() pauses this thread
                // Duration::from_millis(100) = 100 milliseconds
                //
                // TRADEOFF:
                // - Longer sleep: Less CPU usage, higher latency
                // - Shorter sleep: More CPU usage, lower latency
                // 100ms is good balance for most use cases
                //
                // RESPONSE TIME:
                // Worst case: New connection arrives right after we checked
                // We sleep 100ms, then check again and accept it
                // So maximum delay is 100ms (acceptable for this use case)
                std::thread::sleep(std::time::Duration::from_millis(100));
            }

            // === REAL ERROR ===
            // Something went wrong (not just WouldBlock)
            //
            // REASONS:
            // - File descriptor limit reached
            // - Socket closed unexpectedly
            // - System error
            //
            // ACTION: Log error, continue running
            // Don't crash - transient errors might resolve
            Err(e) => eprintln!("Error accepting connection: {e}"),
        }
    }

    // ================================================
    // GRACEFUL SHUTDOWN
    // ================================================
    //
    // Loop exited (running == false)
    // This happens when Ctrl-C was pressed

    // === WAIT FOR WORKER THREADS ===
    // pool.join() blocks until:
    // 1. All queued tasks complete
    // 2. All worker threads finish
    //
    // WHY NECESSARY?
    // Without this, program would exit immediately
    // In-progress requests would be aborted
    // Clients would see connection closed mid-response
    //
    // WITH JOIN:
    // - Existing requests complete normally
    // - Clean shutdown
    // - No data loss
    pool.join();

    // Print shutdown message
    println!("\nShutting down...");

    // === CLEANUP ===
    // When main() returns:
    // 1. `listener` is dropped → socket closed
    // 2. `history_manager` Arc is dropped → reference count decremented
    // 3. If last Arc, HistoryManager is freed
    // 4. All heap memory is reclaimed
    //
    // RUST GUARANTEES:
    // - No memory leaks (all allocations freed)
    // - No dangling pointers (all references are valid)
    // - No double-frees (ownership system prevents this)
    //
    // This is RAII in action: Resources tied to object lifetime
}

// ============================================================================
// END OF FILE
// ============================================================================
//
// === KEY RUST CONCEPTS DEMONSTRATED ===
//
// 1. OWNERSHIP AND BORROWING:
//    - Values have single owner
//    - Borrowing with &T (shared) and &mut T (exclusive)
//    - Move semantics (transferring ownership)
//    - Copy trait for small types
//
// 2. SMART POINTERS:
//    - Arc<T>: Atomic reference counting for shared ownership
//    - Automatic cleanup when last reference dropped
//
// 3. CONCURRENCY:
//    - RwLock: Safe shared mutable state
//    - AtomicBool: Lock-free thread-safe flag
//    - Thread pool: Reusable worker threads
//
// 4. ERROR HANDLING:
//    - Result<T, E>: Success (Ok) or failure (Err)
//    - Option<T>: Value (Some) or no value (None)
//    - No exceptions: errors are values
//
// 5. PATTERN MATCHING:
//    - match: Exhaustive case analysis
//    - if let: Convenient for single case
//    - Destructuring: Extract values from enums/tuples
//
// 6. ITERATORS:
//    - Lazy evaluation: No work until .collect()
//    - Combinators: .map(), .filter(), .zip()
//    - Zero-cost abstractions: Compiles to efficient code
//
// 7. MEMORY SAFETY:
//    - No null pointers (Option instead)
//    - No data races (ownership prevents)
//    - No use-after-free (lifetime system prevents)
//
// 8. OPTIMIZATION TECHNIQUES:
//    - Batching system calls (1 instead of N)
//    - Single lock acquisition (minimize contention)
//    - Borrowing instead of cloning
//    - Thread pool sizing for workload type
//
// === PERFORMANCE CHARACTERISTICS ===
//
// - Thread pool: Amortizes thread creation cost
// - Arc: Atomic operations (lock-free when possible)
// - RwLock: Multiple concurrent readers
// - Batched ss calls: 80%+ reduction in subprocess spawns
// - Single lock pattern: 50% reduction in lock operations
//
// === COMPARISON TO C++ ===
//
// Similar to C++:
// - RAII (constructors/destructors)
// - Zero-cost abstractions
// - Systems programming level
//
// Different from C++:
// - Ownership enforced at compile time (not runtime)
// - No null pointers by default
// - Data races prevented by type system
// - No undefined behavior in safe code
//
// === LEARNING RESOURCES ===
//
// To learn more about concepts in this file:
// - Ownership: https://doc.rust-lang.org/book/ch04-00-understanding-ownership.html
// - Concurrency: https://doc.rust-lang.org/book/ch16-00-concurrency.html
// - Smart Pointers: https://doc.rust-lang.org/book/ch15-00-smart-pointers.html
// - Error Handling: https://doc.rust-lang.org/book/ch09-00-error-handling.html
//
// ============================================================================
