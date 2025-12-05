// ============================================================================
// TCP Monitor HTTP Server - Main Entry Point
// ============================================================================
//
// This program runs an HTTP server that monitors TCP connection health.
// Clients send requests asking "what is the status of connection X?" and
// receive detailed TCP metrics, health assessment, and historical trends.
//
// Architecture:
// - Main thread: Listen for HTTP connections
// - Worker threads: Handle requests in parallel (thread pool)
// - Shared state: HistoryManager wrapped in Arc<RwLock<>> for safe concurrent access
//
// Performance optimizations:
// - Batch system calls: Query all connections in one netlink/ss call
// - Single lock acquisition: Get write lock once per request, not per connection
// - Thread pool sizing: 2x CPU cores (I/O-bound work needs extra threads)
// - Reference borrowing: Avoid cloning when just reading data
//
// ============================================================================

// parking_lot::RwLock is faster than std::sync::RwLock (no poisoning overhead)
use parking_lot::RwLock;

use core::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::env;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use threadpool::ThreadPool;

use cerberus::{
    ConfigResponse, ConnectionInfo, ConnectionWithHealth, DEFAULT_HTTP_PORT, HistoryManager,
    MonitorRequest, MonitorResponse, assess_connection_health_with_history, extract_remote_parts,
    find_connections_in_proc, find_single_connection,
};

#[cfg(not(all(target_os = "linux", feature = "netlink")))]
use cerberus::TcpMetrics;

// ============================================================================
// CONDITIONAL IMPORTS: Netlink (modern, recommended) vs Legacy ss (fallback)
// ============================================================================

#[cfg(all(target_os = "linux", feature = "netlink"))]
use cerberus::{
    assess_connection_health_v2, get_tcp_connection_data_batch_netlink,
    get_tcp_connection_data_via_netlink,
};

#[cfg(feature = "legacy_ss")]
use cerberus::{get_tcp_metrics_batch, get_tcp_metrics_via_ss};

// ============================================================================
// COMPILE-TIME FEATURE VALIDATION
// ============================================================================
//
// Ensure at least one TCP metrics implementation is available on Linux.
// Without either netlink or legacy_ss, the program cannot function.

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
     Note: 'netlink' is the default feature. Use --no-default-features to disable it."
);

// ============================================================================
// HTTP REQUEST HANDLER
// ============================================================================

/// Handle a single HTTP client connection.
///
/// Reads the HTTP request, routes to appropriate endpoint, and sends JSON response.
/// Runs in a worker thread from the thread pool.
fn handle_client(mut stream: TcpStream, history_manager: Arc<RwLock<HistoryManager>>) {
    let mut buffer = [0_u8; 4096];

    if let Ok(bytes_read) = stream.read(&mut buffer) {
        let request = String::from_utf8_lossy(&buffer[..bytes_read]);

        // ====================================================================
        // POST /monitor - Main monitoring endpoint
        // ====================================================================
        if request.starts_with("POST /monitor") {
            if let Some((_, body)) = request.split_once("\r\n\r\n") {
                // Parse JSON request body
                if let Ok(req) = serde_json::from_str::<MonitorRequest>(body) {
                    let local_ip = &req.local_ip;
                    let local_port = req.local_port;
                    let timestamp = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64;

                    // Check if querying single connection or all connections
                    let response = if let Some(remote_port) = req.remote_port {
                        // ================================================
                        // SINGLE CONNECTION QUERY
                        // ================================================
                        match find_single_connection(
                            local_ip,
                            local_port,
                            &req.remote_ip,
                            remote_port,
                            req.established_only,
                        ) {
                            Ok(conn_info) => {
                                let (remote_ip, remote_port) =
                                    extract_remote_parts(&conn_info.remote_address);

                                // Get TCP metrics based on available implementation
                                let (remote_ip, remote_port) =
                                    extract_remote_parts(&conn_info.remote_address);

                                // NETLINK PATH (default, fast)
                                #[cfg(all(target_os = "linux", feature = "netlink"))]
                                let conn_data_result = get_tcp_connection_data_via_netlink(
                                    local_ip,
                                    local_port,
                                    &remote_ip,
                                    remote_port,
                                );

                                // LEGACY SS PATH (fallback)
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

                                // DEVELOPMENT PATH (macOS/test without features)
                                #[cfg(not(any(
                                        all(target_os = "linux", feature = "netlink"),
                                        feature = "legacy_ss"
                                    )))]
                                let metrics_result: Result<cerberus::TcpMetrics, String> =
                                    Err("TCP metrics not available: build with --features netlink or --features legacy_ss"
                                        .to_owned());

                                // Process results and build response
                                #[cfg(all(target_os = "linux", feature = "netlink"))]
                                let process_result = conn_data_result.as_ref().map(|conn_data| {
                                    // Single lock acquisition: add sample and get history
                                    let history = {
                                        let mut manager = history_manager.write();
                                        manager.add_sample_from_netlink(
                                            local_ip,
                                            local_port,
                                            &remote_ip,
                                            remote_port,
                                            conn_data,
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

                                    let remote_addr = format!("{remote_ip}:{remote_port}");
                                    let health = assess_connection_health_v2(
                                        conn_data,
                                        &remote_addr,
                                        history.as_ref(),
                                    );

                                    use cerberus::netlink::tcp_info_to_metrics;
                                    let metrics = tcp_info_to_metrics(&conn_data.tcp_info);

                                    MonitorResponse::Single {
                                        timestamp,
                                        found: true,
                                        connection: Some(conn_info.clone()),
                                        tcp_metrics: Some(Box::new(metrics)),
                                        health: Some(health),
                                        error: None,
                                    }
                                });

                                #[cfg(all(
                                    feature = "legacy_ss",
                                    not(all(target_os = "linux", feature = "netlink"))
                                ))]
                                let process_result = metrics_result.as_ref().map(|metrics| {
                                    let history = {
                                        let mut manager = history_manager.write();
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

                                match process_result {
                                    Ok(response) => response,
                                    Err(e) => MonitorResponse::Single {
                                        timestamp,
                                        found: true,
                                        connection: Some(conn_info),
                                        tcp_metrics: None,
                                        health: None,
                                        error: Some(format!("Could not retrieve TCP metrics: {e}")),
                                    },
                                }
                            }
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
                        // ================================================
                        // MULTIPLE CONNECTIONS QUERY (all remote ports)
                        // ================================================
                        match find_connections_in_proc(
                            local_ip,
                            local_port,
                            Some(&req.remote_ip),
                            req.established_only,
                        ) {
                            Ok(connections) => {
                                // Build list of (local_ip, local_port, remote_ip, remote_port) tuples
                                let conn_tuples: Vec<(String, u16, String, u16)> = connections
                                    .iter()
                                    .map(|conn_info| {
                                        let (remote_ip, remote_port) =
                                            extract_remote_parts(&conn_info.remote_address);
                                        (local_ip.clone(), local_port, remote_ip, remote_port)
                                    })
                                    .collect();

                                // Get metrics for all connections in one batch call
                                #[cfg(all(target_os = "linux", feature = "netlink"))]
                                let conn_data_map =
                                    get_tcp_connection_data_batch_netlink(&conn_tuples);

                                #[cfg(all(
                                    feature = "legacy_ss",
                                    not(all(target_os = "linux", feature = "netlink"))
                                ))]
                                let metrics_map = get_tcp_metrics_batch(&conn_tuples);

                                #[cfg(not(any(
                                        all(target_os = "linux", feature = "netlink"),
                                        feature = "legacy_ss"
                                    )))]
                                let _metrics_map: std::collections::HashMap<(String, u16, String, u16), cerberus::TcpMetrics> =
                                    std::collections::HashMap::new();

                                // Build connection data with metrics lookup
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
                                        let conn_data_opt = conn_data_map.get(&key).cloned();
                                        (conn_info, remote_ip, remote_port, conn_data_opt)
                                    })
                                    .collect();

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

                                // Single lock acquisition for all samples and history retrieval
                                let histories = {
                                    let mut manager = history_manager.write();

                                    // Add samples for all connections (different methods for netlink vs legacy)
                                    #[cfg(all(target_os = "linux", feature = "netlink"))]
                                    for (conn_info, remote_ip, remote_port, conn_data_opt) in
                                        &conn_data
                                    {
                                        if let Some(tcp_conn_data) = conn_data_opt {
                                            manager.add_sample_from_netlink(
                                                local_ip,
                                                local_port,
                                                remote_ip,
                                                *remote_port,
                                                tcp_conn_data,
                                            );
                                        } else {
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

                                    // Get all histories while holding the lock, then release
                                    conn_data
                                        .iter()
                                        .map(|(_, remote_ip, remote_port, _)| {
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
                                };

                                // Build response with health assessment
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
                                            // Assess health using appropriate API
                                            #[cfg(all(target_os = "linux", feature = "netlink"))]
                                            let (tcp_metrics, health) = {
                                                let remote_addr =
                                                    format!("{remote_ip}:{remote_port}");
                                                let health =
                                                    tcp_data_or_metrics.as_ref().map(|conn_data| {
                                                        assess_connection_health_v2(
                                                            conn_data,
                                                            &remote_addr,
                                                            history.as_ref(),
                                                        )
                                                    });
                                                let tcp_metrics =
                                                    tcp_data_or_metrics.map(|conn_data| {
                                                        use cerberus::netlink::tcp_info_to_metrics;
                                                        tcp_info_to_metrics(&conn_data.tcp_info)
                                                    });
                                                (tcp_metrics, health)
                                            };

                                            #[cfg(all(
                                                feature = "legacy_ss",
                                                not(all(
                                                    target_os = "linux",
                                                    feature = "netlink"
                                                ))
                                            ))]
                                            let (tcp_metrics, health) = {
                                                let tcp_metrics = tcp_data_or_metrics;
                                                let health = tcp_metrics.as_ref().map(|metrics| {
                                                    assess_connection_health_with_history(
                                                        &conn_info,
                                                        metrics,
                                                        history.as_ref(),
                                                    )
                                                });
                                                (tcp_metrics, health)
                                            };

                                            #[cfg(not(any(
                                                all(target_os = "linux", feature = "netlink"),
                                                feature = "legacy_ss"
                                            )))]
                                            let (tcp_metrics, health) = {
                                                let tcp_metrics = tcp_data_or_metrics;
                                                let health = tcp_metrics.as_ref().map(|metrics| {
                                                    assess_connection_health_with_history(
                                                        &conn_info,
                                                        metrics,
                                                        history.as_ref(),
                                                    )
                                                });
                                                (tcp_metrics, health)
                                            };

                                            ConnectionWithHealth {
                                                connection: conn_info,
                                                tcp_metrics,
                                                health,
                                            }
                                        },
                                    )
                                    .collect();

                                // Sort by health score if requested
                                if req.sort_by_health {
                                    conn_with_health
                                        .sort_by(cerberus::ConnectionWithHealth::cmp_by_health);
                                }

                                let error = conn_with_health
                                    .is_empty()
                                    .then(|| "No connections found".to_owned());

                                MonitorResponse::Multiple {
                                    timestamp,
                                    count: conn_with_health.len(),
                                    sorted_by_health: req.sort_by_health,
                                    connections: conn_with_health,
                                    error,
                                }
                            }
                            Err(e) => MonitorResponse::Multiple {
                                timestamp,
                                count: 0,
                                sorted_by_health: req.sort_by_health,
                                connections: vec![],
                                error: Some(e),
                            },
                        }
                    };

                    // Send JSON response
                    let json_body = serde_json::to_string_pretty(&response).unwrap();
                    let http_response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        json_body.len(),
                        json_body
                    );
                    let _ = stream.write_all(http_response.as_bytes());
                } else {
                    // Invalid JSON request
                    let error_response = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n\
                         {\"error\": \"Invalid JSON format\"}\n";
                    let _ = stream.write_all(error_response.as_bytes());
                }
            }
        } else if request.starts_with("GET /health") {
            // ====================================================================
            // GET /health - Simple health check for load balancers
            // ====================================================================
            let health_response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n\
                 {\"status\": \"ok\"}\n";
            let _ = stream.write_all(health_response.as_bytes());
        } else if request.starts_with("GET /config") {
            // ====================================================================
            // GET /config - Return server configuration
            // ====================================================================
            let config_resp = ConfigResponse {
                http_server_info:
                    "Cerberus TCP Monitor v0.1.0 - Dynamic socket monitoring per request".to_owned(),
                monitor_per_request: true,
            };

            let json_body = serde_json::to_string_pretty(&config_resp).unwrap();
            let http_response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                json_body.len(),
                json_body
            );
            let _ = stream.write_all(http_response.as_bytes());
        } else {
            // ====================================================================
            // Unknown endpoint
            // ====================================================================
            let not_found = "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n\
                 Not Found\n";
            let _ = stream.write_all(not_found.as_bytes());
        }
    }
    // Socket automatically closes when stream is dropped (RAII pattern)
}

// ============================================================================
// MAIN FUNCTION - Server Startup and Event Loop
// ============================================================================

/// Start the TCP Monitor HTTP server.
///
/// Initializes the thread pool, binds to the listening port, and runs the main
/// event loop that accepts connections and dispatches them to worker threads.
/// Handles graceful shutdown on Ctrl-C.
fn main() {
    // Parse HTTP port from command line argument
    let args: Vec<String> = env::args().collect();
    let http_port: u16 = if args.len() > 1 {
        args[1].parse().unwrap_or_else(|_| {
            eprintln!("Invalid HTTP port, using default {DEFAULT_HTTP_PORT}");
            DEFAULT_HTTP_PORT
        })
    } else {
        DEFAULT_HTTP_PORT
    };

    // Create shared HistoryManager for all worker threads
    // Arc (Atomic Reference Counted): Multiple threads can own the data
    // RwLock: Many readers OR one writer (not both simultaneously)
    let history_manager = Arc::new(RwLock::new(HistoryManager::new()));

    // Size thread pool based on CPU cores
    // I/O-bound work benefits from more threads than CPU count (2x cores is typical)
    let cpu_count = std::thread::available_parallelism()
        .map(std::num::NonZero::get)
        .unwrap_or(4);
    let thread_count = (cpu_count * 2).clamp(4, 16);
    eprintln!("System has {cpu_count} CPU cores, creating thread pool with {thread_count} workers");

    let pool = ThreadPool::new(thread_count);

    // Bind to localhost on the specified port
    let listener =
        TcpListener::bind(format!("127.0.0.1:{http_port}")).expect("Failed to bind to address");

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

    // Setup graceful shutdown on Ctrl-C
    // AtomicBool: Thread-safe flag (no data races across threads)
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        // Set shutdown flag (SeqCst = strongest ordering guarantee)
        r.store(false, AtomicOrdering::SeqCst);
    })
    .expect("Error setting Ctrl-C handler");

    // Use non-blocking socket so we can check the shutdown flag periodically
    listener
        .set_nonblocking(true)
        .expect("Cannot set non-blocking");

    let mut last_cleanup = Instant::now();

    // ========================================================================
    // MAIN SERVER LOOP
    // ========================================================================
    while running.load(AtomicOrdering::SeqCst) {
        match listener.accept() {
            Ok((stream, _)) => {
                // Dispatch request to thread pool worker
                let history_clone = Arc::clone(&history_manager);
                pool.execute(move || {
                    handle_client(stream, history_clone);
                });
            }

            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // No connection available; check if cleanup is needed
                if last_cleanup.elapsed().as_secs() >= 60 {
                    let mut manager = history_manager.write();
                    manager.cleanup_stale_connections();
                    let count = manager.connection_count();
                    if count > 0 {
                        eprintln!(
                            "[{}] Tracking {} connections",
                            last_cleanup.elapsed().as_secs(),
                            count
                        );
                    }
                    last_cleanup = Instant::now();
                }

                // Sleep to avoid busy loop; 100ms is acceptable latency for this use case
                std::thread::sleep(core::time::Duration::from_millis(100));
            }

            Err(e) => eprintln!("Error accepting connection: {e}"),
        }
    }

    // Wait for all worker threads to finish before exiting
    // This ensures in-progress requests complete normally
    pool.join();
    println!("\nShutting down...");
}
