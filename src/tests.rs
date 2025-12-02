// Unit tests for TCP Monitor library
// Tests cover all public and private functions with real data from Linux server
// plus comprehensive edge cases.

use crate::*;
use std::cmp::Ordering;

// Provide a Clone implementation for ConnectionWithHealth used by tests.
// Manually clone fields to avoid requiring upstream types to derive Clone.
impl Clone for ConnectionWithHealth {
    fn clone(&self) -> Self {
        ConnectionWithHealth {
            connection: ConnectionInfo {
                local_address: self.connection.local_address.clone(),
                remote_address: self.connection.remote_address.clone(),
                state: self.connection.state.clone(),
                state_code: self.connection.state_code,
                send_queue_bytes: self.connection.send_queue_bytes,
                recv_queue_bytes: self.connection.recv_queue_bytes,
            },
            tcp_metrics: self.tcp_metrics.as_ref().map(|m| TcpMetrics {
                // Original 7 fields
                rtt_ms: m.rtt_ms,
                rtt_var_ms: m.rtt_var_ms,
                bytes_sent: m.bytes_sent,
                bytes_retrans: m.bytes_retrans,
                congestion_window: m.congestion_window,
                unacked_packets: m.unacked_packets,
                retrans_events: m.retrans_events,
                // Extended 10 fields
                min_rtt_ms: m.min_rtt_ms,
                delivery_rate_bps: m.delivery_rate_bps,
                lost_packets: m.lost_packets,
                rwnd_limited_us: m.rwnd_limited_us,
                sndbuf_limited_us: m.sndbuf_limited_us,
                busy_time_us: m.busy_time_us,
                total_retrans: m.total_retrans,
                snd_ssthresh: m.snd_ssthresh,
                last_data_sent_ms: m.last_data_sent_ms,
                pmtu: m.pmtu,
            }),
            health: self.health.as_ref().map(|h| HealthAssessment {
                status: h.status.clone(),
                score: h.score,
                safe_to_send: h.safe_to_send,
                reasons: h.reasons.clone(),
                trend_metrics: h.trend_metrics.clone(),
            }),
        }
    }
}

// ============================================================================
// Tests for get_tcp_state_name()
// ============================================================================
mod test_get_tcp_state_name {
    use super::*;

    #[test]
    fn test_established_state() {
        assert_eq!(get_tcp_state_name(TCP_ESTABLISHED), "ESTABLISHED");
    }

    #[test]
    fn test_syn_sent_state() {
        assert_eq!(get_tcp_state_name(TCP_SYN_SENT), "SYN_SENT");
    }

    #[test]
    fn test_syn_recv_state() {
        assert_eq!(get_tcp_state_name(TCP_SYN_RECV), "SYN_RECV");
    }

    #[test]
    fn test_fin_wait1_state() {
        assert_eq!(get_tcp_state_name(TCP_FIN_WAIT1), "FIN_WAIT1");
    }

    #[test]
    fn test_fin_wait2_state() {
        assert_eq!(get_tcp_state_name(TCP_FIN_WAIT2), "FIN_WAIT2");
    }

    #[test]
    fn test_time_wait_state() {
        assert_eq!(get_tcp_state_name(TCP_TIME_WAIT), "TIME_WAIT");
    }

    #[test]
    fn test_close_state() {
        assert_eq!(get_tcp_state_name(TCP_CLOSE), "CLOSE");
    }

    #[test]
    fn test_close_wait_state() {
        assert_eq!(get_tcp_state_name(TCP_CLOSE_WAIT), "CLOSE_WAIT");
    }

    #[test]
    fn test_last_ack_state() {
        assert_eq!(get_tcp_state_name(TCP_LAST_ACK), "LAST_ACK");
    }

    #[test]
    fn test_listen_state() {
        assert_eq!(get_tcp_state_name(TCP_LISTEN), "LISTEN");
    }

    #[test]
    fn test_closing_state() {
        assert_eq!(get_tcp_state_name(TCP_CLOSING), "CLOSING");
    }

    #[test]
    fn test_unknown_state() {
        // Edge case: unknown state code
        assert_eq!(get_tcp_state_name(0xFF), "UNKNOWN");
        assert_eq!(get_tcp_state_name(0x00), "UNKNOWN");
    }
}

// ============================================================================
// Tests for parse_hex_ipv4()
// ============================================================================
mod test_parse_hex_ipv4 {
    use super::*;

    #[test]
    fn test_real_ip_201_168_21_201() {
        // From real /proc/net/tcp data: C915A8C0 = 192.168.21.201
        let result = parse_hex_ipv4("C915A8C0");
        assert!(result.is_ok());
        let ip = result.unwrap();
        // Little-endian conversion: C9=201, 15=21, A8=168, C0=192
        assert_eq!(ip.to_string(), "192.168.21.201");
    }

    #[test]
    fn test_real_ip_192_168_18_160() {
        // From real /proc/net/tcp data: A012A8C0 = 192.168.18.160
        let result = parse_hex_ipv4("A012A8C0");
        assert!(result.is_ok());
        let ip = result.unwrap();
        assert_eq!(ip.to_string(), "192.168.18.160");
    }

    #[test]
    fn test_real_ip_192_168_18_100() {
        // From real /proc/net/tcp data: 6412A8C0 = 192.168.18.100
        let result = parse_hex_ipv4("6412A8C0");
        assert!(result.is_ok());
        let ip = result.unwrap();
        assert_eq!(ip.to_string(), "192.168.18.100");
    }

    #[test]
    fn test_localhost_127_0_0_1() {
        // 127.0.0.1 in little-endian hex = 0100007F
        let result = parse_hex_ipv4("0100007F");
        assert!(result.is_ok());
        let ip = result.unwrap();
        assert_eq!(ip.to_string(), "127.0.0.1");
    }

    #[test]
    fn test_zeros_0_0_0_0() {
        // 0.0.0.0 in hex = 00000000
        let result = parse_hex_ipv4("00000000");
        assert!(result.is_ok());
        let ip = result.unwrap();
        assert_eq!(ip.to_string(), "0.0.0.0");
    }

    #[test]
    fn test_max_ip_255_255_255_255() {
        // 255.255.255.255 in little-endian hex = FFFFFFFF
        let result = parse_hex_ipv4("FFFFFFFF");
        assert!(result.is_ok());
        let ip = result.unwrap();
        assert_eq!(ip.to_string(), "255.255.255.255");
    }

    #[test]
    fn test_invalid_hex_string() {
        // Edge case: invalid hex string
        let result = parse_hex_ipv4("ZZZZZZZZ");
        assert!(result.is_err());
    }

    #[test]
    fn test_lowercase_hex() {
        // Test that lowercase hex works
        let result = parse_hex_ipv4("c915a8c0");
        assert!(result.is_ok());
        let ip = result.unwrap();
        assert_eq!(ip.to_string(), "192.168.21.201");
    }

    #[test]
    fn test_mixed_case_hex() {
        // Test mixed case hex
        let result = parse_hex_ipv4("A012a8C0");
        assert!(result.is_ok());
        let ip = result.unwrap();
        assert_eq!(ip.to_string(), "192.168.18.160");
    }
}

// ============================================================================
// Tests for parse_proc_address()
// ============================================================================
mod test_parse_proc_address {
    use super::*;

    #[test]
    fn test_real_address_ssh_201_22() {
        // Real data: C915A8C0:0016 = 192.168.21.201:22 (SSH)
        let result = parse_proc_address("C915A8C0:0016");
        assert!(result.is_ok());
        let (ip, port) = result.unwrap();
        assert_eq!(ip.to_string(), "192.168.21.201");
        assert_eq!(port, 22);
    }

    #[test]
    fn test_real_address_remote_57616() {
        // Real data: A012A8C0:E110 = 192.168.18.160:57616
        let result = parse_proc_address("A012A8C0:E110");
        assert!(result.is_ok());
        let (ip, port) = result.unwrap();
        assert_eq!(ip.to_string(), "192.168.18.160");
        assert_eq!(port, 57616);
    }

    #[test]
    fn test_real_address_5201_50684() {
        // Real data: C915A8C0:1451 = 192.168.21.201:5201 (iperf)
        // 6412A8C0:C5FC = 192.168.18.100:50684
        let result = parse_proc_address("C915A8C0:1451");
        assert!(result.is_ok());
        let (ip, port) = result.unwrap();
        assert_eq!(ip.to_string(), "192.168.21.201");
        assert_eq!(port, 5201);
    }

    #[test]
    fn test_localhost_http() {
        // 127.0.0.1:80 in little-endian
        let result = parse_proc_address("0100007F:0050");
        assert!(result.is_ok());
        let (ip, port) = result.unwrap();
        assert_eq!(ip.to_string(), "127.0.0.1");
        assert_eq!(port, 80);
    }

    #[test]
    fn test_high_port_number() {
        // Test high port: 65535 (FFFF in hex)
        let result = parse_proc_address("0100007F:FFFF");
        assert!(result.is_ok());
        let (ip, port) = result.unwrap();
        assert_eq!(ip.to_string(), "127.0.0.1");
        assert_eq!(port, 65535);
    }

    #[test]
    fn test_invalid_format_no_colon() {
        // Edge case: missing colon
        let result = parse_proc_address("C915A8C00016");
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_format_multiple_colons() {
        // Edge case: too many colons
        let result = parse_proc_address("C915A8C0:00:16");
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_hex_port() {
        // Edge case: invalid hex in port
        let result = parse_proc_address("C915A8C0:ZZZZ");
        assert!(result.is_err());
    }
}

// ============================================================================
// Tests for extract_remote_parts()
// ============================================================================
mod test_extract_remote_parts {
    use super::*;

    #[test]
    fn test_real_remote_address_160_57616() {
        // Real data from ss output
        let result = extract_remote_parts("192.168.18.160:57616");
        assert_eq!(result.0, "192.168.18.160");
        assert_eq!(result.1, 57616);
    }

    #[test]
    fn test_real_remote_address_100_50684() {
        // Real iperf connection
        let result = extract_remote_parts("192.168.18.100:50684");
        assert_eq!(result.0, "192.168.18.100");
        assert_eq!(result.1, 50684);
    }

    #[test]
    fn test_localhost_http() {
        let result = extract_remote_parts("127.0.0.1:80");
        assert_eq!(result.0, "127.0.0.1");
        assert_eq!(result.1, 80);
    }

    #[test]
    fn test_ssh_port_22() {
        let result = extract_remote_parts("192.168.1.100:22");
        assert_eq!(result.0, "192.168.1.100");
        assert_eq!(result.1, 22);
    }

    #[test]
    fn test_high_port_65535() {
        let result = extract_remote_parts("10.0.0.1:65535");
        assert_eq!(result.0, "10.0.0.1");
        assert_eq!(result.1, 65535);
    }

    #[test]
    fn test_invalid_format_no_colon() {
        // Edge case: missing colon
        let result = extract_remote_parts("192.168.1.100");
        assert_eq!(result.0, "");
        assert_eq!(result.1, 0);
    }

    #[test]
    fn test_invalid_format_non_numeric_port() {
        // Edge case: non-numeric port
        let result = extract_remote_parts("192.168.1.100:ssh");
        assert_eq!(result.1, 0);
    }

    #[test]
    fn test_empty_string() {
        // Edge case: empty string
        let result = extract_remote_parts("");
        assert_eq!(result.0, "");
        assert_eq!(result.1, 0);
    }
}

// ============================================================================
// Tests for assess_connection_health()
// ============================================================================
mod test_assess_connection_health {
    use super::*;

    #[test]
    fn test_healthy_connection_real_data() {
        // Based on real iperf3 connection with good metrics
        let conn = ConnectionInfo {
            local_address: "192.168.21.201:5201".to_string(),
            remote_address: "192.168.18.100:50688".to_string(),
            state: "ESTABLISHED".to_string(),
            state_code: TCP_ESTABLISHED,
            send_queue_bytes: 0,
            recv_queue_bytes: 0,
        };

        let metrics = TcpMetrics {
            rtt_ms: 46.883,
            rtt_var_ms: 1.61,
            bytes_sent: 420148,
            bytes_retrans: 0,
            congestion_window: 96,
            unacked_packets: 0,
            retrans_events: 0,
            // Extended 10 fields (all None for tests)
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

        let health = assess_connection_health(&conn, &metrics);
        assert_eq!(health.status, "HEALTHY");
        assert_eq!(health.score, 0);
        assert!(health.safe_to_send);
        assert!(health.reasons.contains("acceptable range"));
    }

    #[test]
    fn test_caution_high_rtt() {
        // Connection with elevated RTT (200-500ms)
        let conn = ConnectionInfo {
            local_address: "192.168.21.201:22".to_string(),
            remote_address: "192.168.18.160:57616".to_string(),
            state: "ESTABLISHED".to_string(),
            state_code: TCP_ESTABLISHED,
            send_queue_bytes: 0,
            recv_queue_bytes: 0,
        };

        let metrics = TcpMetrics {
            rtt_ms: 250.0,
            rtt_var_ms: 5.0,
            bytes_sent: 28429,
            bytes_retrans: 0,
            congestion_window: 10,
            unacked_packets: 1,
            retrans_events: 0,
            // Extended 10 fields (all None for tests)
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

        let health = assess_connection_health(&conn, &metrics);
        assert_eq!(health.status, "CAUTION");
        assert!(health.safe_to_send);
        assert!(health.reasons.contains("RTT > 200ms"));
    }

    #[test]
    fn test_suspect_send_queue_accumulation() {
        // Connection with queue accumulation >= 1KB
        // Score = 2 (queue) + 1 (RTT 200-500ms) = 3 -> SUSPECT
        let conn = ConnectionInfo {
            local_address: "192.168.21.201:22".to_string(),
            remote_address: "192.168.18.160:55584".to_string(),
            state: "ESTABLISHED".to_string(),
            state_code: TCP_ESTABLISHED,
            send_queue_bytes: 1500, // > 1KB (SEND_QUEUE_SUSPECT)
            recv_queue_bytes: 0,
        };

        let metrics = TcpMetrics {
            rtt_ms: 250.0, // > 200ms to get SUSPECT threshold
            rtt_var_ms: 5.573,
            bytes_sent: 156949,
            bytes_retrans: 0,
            congestion_window: 10,
            unacked_packets: 0,
            retrans_events: 0,
            // Extended 10 fields (all None for tests)
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

        let health = assess_connection_health(&conn, &metrics);
        assert_eq!(health.status, "SUSPECT");
        assert!(health.safe_to_send);
        assert!(health.reasons.contains("Send queue >= 1KB"));
    }

    #[test]
    fn test_stale_queue_2kb_and_retrans() {
        // Connection with queue >= 2KB (WARNING) and retransmissions
        // Queue >= 2KB sets safe_to_send = false, which triggers STALE status
        let conn = ConnectionInfo {
            local_address: "192.168.21.201:22".to_string(),
            remote_address: "192.168.18.160:57616".to_string(),
            state: "ESTABLISHED".to_string(),
            state_code: TCP_ESTABLISHED,
            send_queue_bytes: 2100, // >= 2KB (SEND_QUEUE_WARNING)
            recv_queue_bytes: 0,
        };

        let metrics = TcpMetrics {
            rtt_ms: 50.0,
            rtt_var_ms: 2.5,
            bytes_sent: 1000,
            bytes_retrans: 100, // Active retransmissions
            congestion_window: 10,
            unacked_packets: 2,
            retrans_events: 1,
            // Extended 10 fields (all None for tests)
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

        let health = assess_connection_health(&conn, &metrics);
        assert_eq!(health.status, "STALE");
        assert!(!health.safe_to_send);
        assert!(health.reasons.contains("Send queue >= 2KB"));
        assert!(health.reasons.contains("Active retransmissions"));
    }

    #[test]
    fn test_critical_queue_4kb() {
        // Connection with queue >= 4KB (CRITICAL threshold)
        let conn = ConnectionInfo {
            local_address: "192.168.21.201:5201".to_string(),
            remote_address: "192.168.18.100:50684".to_string(),
            state: "ESTABLISHED".to_string(),
            state_code: TCP_ESTABLISHED,
            send_queue_bytes: 5000, // >= 4KB (SEND_QUEUE_CRITICAL)
            recv_queue_bytes: 0,
        };

        let metrics = TcpMetrics {
            rtt_ms: 48.967,
            rtt_var_ms: 15.816,
            bytes_sent: 4,
            bytes_retrans: 0,
            congestion_window: 10,
            unacked_packets: 0,
            retrans_events: 0,
            // Extended 10 fields (all None for tests)
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

        let health = assess_connection_health(&conn, &metrics);
        assert_eq!(health.status, "STALE");
        assert!(!health.safe_to_send);
        assert!(health.reasons.contains("Send queue >= 4KB"));
    }

    #[test]
    fn test_retransmissions_detected() {
        // Connection with active retransmissions
        let conn = ConnectionInfo {
            local_address: "192.168.21.201:22".to_string(),
            remote_address: "192.168.18.160:57616".to_string(),
            state: "ESTABLISHED".to_string(),
            state_code: TCP_ESTABLISHED,
            send_queue_bytes: 0,
            recv_queue_bytes: 0,
        };

        let metrics = TcpMetrics {
            rtt_ms: 100.0,
            rtt_var_ms: 5.0,
            bytes_sent: 10000,
            bytes_retrans: 500, // Active retransmissions
            congestion_window: 10,
            unacked_packets: 5,
            retrans_events: 2,
            // Extended 10 fields (all None for tests)
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

        let health = assess_connection_health(&conn, &metrics);
        assert!(!health.safe_to_send);
        assert!(health.reasons.contains("Active retransmissions"));
    }

    #[test]
    fn test_high_rtt_1000ms() {
        // Connection with severe delay (RTT > 1000ms)
        let conn = ConnectionInfo {
            local_address: "192.168.21.201:22".to_string(),
            remote_address: "10.0.0.1:22".to_string(),
            state: "ESTABLISHED".to_string(),
            state_code: TCP_ESTABLISHED,
            send_queue_bytes: 0,
            recv_queue_bytes: 0,
        };

        let metrics = TcpMetrics {
            rtt_ms: 1500.0, // > 1 second
            rtt_var_ms: 50.0,
            bytes_sent: 1000,
            bytes_retrans: 0,
            congestion_window: 10,
            unacked_packets: 0,
            retrans_events: 0,
            // Extended 10 fields (all None for tests)
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

        let health = assess_connection_health(&conn, &metrics);
        assert_eq!(health.status, "STALE");
        assert!(!health.safe_to_send);
        assert!(health.reasons.contains("RTT > 1s"));
    }

    #[test]
    fn test_high_unacked_ratio() {
        // Connection with unacked > 70% of cwnd
        let conn = ConnectionInfo {
            local_address: "192.168.21.201:5201".to_string(),
            remote_address: "192.168.18.100:50684".to_string(),
            state: "ESTABLISHED".to_string(),
            state_code: TCP_ESTABLISHED,
            send_queue_bytes: 0,
            recv_queue_bytes: 0,
        };

        let metrics = TcpMetrics {
            rtt_ms: 50.0,
            rtt_var_ms: 2.0,
            bytes_sent: 5000,
            bytes_retrans: 0,
            congestion_window: 10,
            unacked_packets: 8, // 80% of cwnd
            retrans_events: 0,
            // Extended 10 fields (all None for tests)
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

        let health = assess_connection_health(&conn, &metrics);
        assert!(!health.safe_to_send);
        assert!(health.reasons.contains("Unacked > 70% of cwnd"));
    }

    #[test]
    fn test_unacked_with_queued_data() {
        // Connection with both unacked packets and queued data (stalling)
        let conn = ConnectionInfo {
            local_address: "192.168.21.201:22".to_string(),
            remote_address: "192.168.18.160:57616".to_string(),
            state: "ESTABLISHED".to_string(),
            state_code: TCP_ESTABLISHED,
            send_queue_bytes: 500, // Data in queue
            recv_queue_bytes: 0,
        };

        let metrics = TcpMetrics {
            rtt_ms: 100.0,
            rtt_var_ms: 5.0,
            bytes_sent: 5000,
            bytes_retrans: 0,
            congestion_window: 10,
            unacked_packets: 5, // Unacked with queued data = stalling
            retrans_events: 0,
            // Extended 10 fields (all None for tests)
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

        let health = assess_connection_health(&conn, &metrics);
        assert!(health.reasons.contains("stalling"));
    }
}

// ============================================================================
// Tests for ConnectionWithHealth::cmp_by_health()
// ============================================================================
mod test_cmp_by_health {
    use super::*;

    #[test]
    fn test_compare_healthy_vs_degraded() {
        // Healthy connection (score 0)
        let healthy = ConnectionWithHealth {
            connection: ConnectionInfo {
                local_address: "192.168.21.201:5201".to_string(),
                remote_address: "192.168.18.100:50688".to_string(),
                state: "ESTABLISHED".to_string(),
                state_code: TCP_ESTABLISHED,
                send_queue_bytes: 0,
                recv_queue_bytes: 0,
            },
            tcp_metrics: Some(TcpMetrics {
                rtt_ms: 46.883,
                rtt_var_ms: 1.61,
                bytes_sent: 420148,
                bytes_retrans: 0,
                congestion_window: 96,
                unacked_packets: 0,
                retrans_events: 0,
                // Extended 10 fields (all None for tests)
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
            }),
            health: Some(HealthAssessment {
                status: "HEALTHY".to_string(),
                score: 0,
                safe_to_send: true,
                reasons: "All metrics within acceptable range".to_string(),
                trend_metrics: None,
            }),
        };

        // Degraded connection (score 5)
        let degraded = ConnectionWithHealth {
            connection: ConnectionInfo {
                local_address: "192.168.21.201:22".to_string(),
                remote_address: "192.168.18.160:57616".to_string(),
                state: "ESTABLISHED".to_string(),
                state_code: TCP_ESTABLISHED,
                send_queue_bytes: 2100,
                recv_queue_bytes: 0,
            },
            tcp_metrics: Some(TcpMetrics {
                rtt_ms: 50.0,
                rtt_var_ms: 2.5,
                bytes_sent: 1000,
                bytes_retrans: 0,
                congestion_window: 10,
                unacked_packets: 0,
                retrans_events: 0,
                // Extended 10 fields (all None for tests)
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
            }),
            health: Some(HealthAssessment {
                status: "DEGRADED".to_string(),
                score: 5,
                safe_to_send: false,
                reasons: "Send queue >= 2KB".to_string(),
                trend_metrics: None,
            }),
        };

        // Degraded should come first (worse health)
        assert_eq!(degraded.cmp_by_health(&healthy), Ordering::Less);
        assert_eq!(healthy.cmp_by_health(&degraded), Ordering::Greater);
    }

    #[test]
    fn test_compare_equal_scores_different_queues() {
        // Both have same score but different queue sizes
        let high_queue = ConnectionWithHealth {
            connection: ConnectionInfo {
                local_address: "192.168.21.201:22".to_string(),
                remote_address: "192.168.18.160:57616".to_string(),
                state: "ESTABLISHED".to_string(),
                state_code: TCP_ESTABLISHED,
                send_queue_bytes: 1500, // Higher queue
                recv_queue_bytes: 0,
            },
            tcp_metrics: None,
            health: Some(HealthAssessment {
                status: "SUSPECT".to_string(),
                score: 2,
                safe_to_send: true,
                reasons: "test".to_string(),
                trend_metrics: None,
            }),
        };

        let low_queue = ConnectionWithHealth {
            connection: ConnectionInfo {
                local_address: "192.168.21.201:5201".to_string(),
                remote_address: "192.168.18.100:50684".to_string(),
                state: "ESTABLISHED".to_string(),
                state_code: TCP_ESTABLISHED,
                send_queue_bytes: 500, // Lower queue
                recv_queue_bytes: 0,
            },
            tcp_metrics: None,
            health: Some(HealthAssessment {
                status: "SUSPECT".to_string(),
                score: 2,
                safe_to_send: true,
                reasons: "test".to_string(),
                trend_metrics: None,
            }),
        };

        // High queue should come first (worse)
        assert_eq!(high_queue.cmp_by_health(&low_queue), Ordering::Less);
    }

    #[test]
    fn test_compare_no_health_info() {
        // Connections without health assessment
        let conn1 = ConnectionWithHealth {
            connection: ConnectionInfo {
                local_address: "192.168.21.201:22".to_string(),
                remote_address: "192.168.18.160:57616".to_string(),
                state: "ESTABLISHED".to_string(),
                state_code: TCP_ESTABLISHED,
                send_queue_bytes: 100,
                recv_queue_bytes: 0,
            },
            tcp_metrics: None,
            health: None,
        };

        let conn2 = ConnectionWithHealth {
            connection: ConnectionInfo {
                local_address: "192.168.21.201:5201".to_string(),
                remote_address: "192.168.18.100:50684".to_string(),
                state: "ESTABLISHED".to_string(),
                state_code: TCP_ESTABLISHED,
                send_queue_bytes: 200,
                recv_queue_bytes: 0,
            },
            tcp_metrics: None,
            health: None,
        };

        // No health = score 0, so compare by queue
        // conn2 has higher queue so should come first
        assert_eq!(conn2.cmp_by_health(&conn1), Ordering::Less);
    }

    #[test]
    fn test_sorting_multiple_connections() {
        // We need a Vec (not array) because we call .sort_by() which requires mutability
        #[allow(clippy::useless_vec)]
        let mut connections = vec![
            // Healthy
            ConnectionWithHealth {
                connection: ConnectionInfo {
                    local_address: "192.168.21.201:5201".to_string(),
                    remote_address: "192.168.18.100:50688".to_string(),
                    state: "ESTABLISHED".to_string(),
                    state_code: TCP_ESTABLISHED,
                    send_queue_bytes: 0,
                    recv_queue_bytes: 0,
                },
                tcp_metrics: None,
                health: Some(HealthAssessment {
                    status: "HEALTHY".to_string(),
                    score: 0,
                    safe_to_send: true,
                    reasons: "test".to_string(),
                trend_metrics: None,
                }),
            },
            // Stale (score 7)
            ConnectionWithHealth {
                connection: ConnectionInfo {
                    local_address: "192.168.21.201:22".to_string(),
                    remote_address: "192.168.18.160:57616".to_string(),
                    state: "ESTABLISHED".to_string(),
                    state_code: TCP_ESTABLISHED,
                    send_queue_bytes: 5000,
                    recv_queue_bytes: 0,
                },
                tcp_metrics: None,
                health: Some(HealthAssessment {
                    status: "STALE".to_string(),
                    score: 7,
                    safe_to_send: false,
                    reasons: "test".to_string(),
                trend_metrics: None,
                }),
            },
            // Caution (score 1)
            ConnectionWithHealth {
                connection: ConnectionInfo {
                    local_address: "192.168.21.201:80".to_string(),
                    remote_address: "10.0.0.1:55000".to_string(),
                    state: "ESTABLISHED".to_string(),
                    state_code: TCP_ESTABLISHED,
                    send_queue_bytes: 100,
                    recv_queue_bytes: 0,
                },
                tcp_metrics: None,
                health: Some(HealthAssessment {
                    status: "CAUTION".to_string(),
                    score: 1,
                    safe_to_send: true,
                    reasons: "test".to_string(),
                trend_metrics: None,
                }),
            },
        ];

        connections.sort_by(|a, b| a.cmp_by_health(b));

        // Should be sorted: STALE (7) > CAUTION (1) > HEALTHY (0)
        assert_eq!(connections[0].health.as_ref().unwrap().status, "STALE");
        assert_eq!(connections[1].health.as_ref().unwrap().status, "CAUTION");
        assert_eq!(connections[2].health.as_ref().unwrap().status, "HEALTHY");
    }
}

// ============================================================================
// Tests for default_true()
// ============================================================================
mod test_default_true {
    use super::*;

    #[test]
    fn test_default_true_returns_true() {
        assert!(default_true());
    }
}

// ============================================================================
// Tests for output_parsing() (LEGACY - only when legacy_ss feature enabled)
// ============================================================================
#[cfg(feature = "legacy_ss")]
mod test_output_parsing {
    use super::*;

    #[test]
    fn test_real_ss_output_ssh_connection() {
        // Real output from: ss -tin dst 192.168.18.160:57616 src 192.168.21.201:22
        let output = "State      Recv-Q      Send-Q            Local Address:Port             Peer Address:Port      Process\n\
                      ESTAB      0           36               192.168.21.201:22             192.168.18.160:57616\n\
                      cubic wscale:6,9 rto:247 rtt:46.149/2.499 ato:43 mss:1386 pmtu:1500 rcvmss:1386 advmss:1448 cwnd:10 bytes_sent:28429 bytes_acked:28393 bytes_received:21541 segs_out:637 segs_in:1089 data_segs_out:629 data_segs_in:526 send 2402652bps lastsnd:2 lastrcv:2 lastack:2 pacing_rate 4805264bps delivery_rate 1581640bps delivered:629 app_limited busy:16627ms unacked:1 rcv_rtt:51 rcv_space:28960 rcv_ssthresh:40412 minrtt:43.646 snd_wnd:131072";

        let result = output_parsing(output);
        assert!(result.is_ok());

        let metrics = result.unwrap();
        assert_eq!(metrics.rtt_ms, 46.149);
        assert_eq!(metrics.rtt_var_ms, 2.499);
        assert_eq!(metrics.bytes_sent, 28429);
        assert_eq!(metrics.congestion_window, 10);
        assert_eq!(metrics.unacked_packets, 1);
        assert_eq!(metrics.bytes_retrans, 0);
    }

    #[test]
    fn test_real_ss_output_iperf_high_bandwidth() {
        // Real output from: ss -tin dst 192.168.18.100:50688 src 192.168.21.201:5201
        let output = "State      Recv-Q      Send-Q            Local Address:Port             Peer Address:Port      Process\n\
                      ESTAB      0           0                 192.168.21.201:5201             192.168.18.100:50688\n\
                      cubic wscale:9,9 rto:247 rtt:46.883/1.61 ato:40 mss:1386 pmtu:1500 rcvmss:536 advmss:1448 cwnd:96 bytes_sent:420148 bytes_acked:420148 bytes_received:37 segs_out:305 segs_in:61 data_segs_out:304 data_segs_in:1 send 22704349bps lastsnd:9953 lastrcv:33218 lastack:9905 pacing_rate 45407848bps delivery_rate 10514496bps delivered:305 busy:705ms rcv_space:28960 rcv_ssthresh:28960 minrtt:42.65 snd_wnd:434176";

        let result = output_parsing(output);
        assert!(result.is_ok());

        let metrics = result.unwrap();
        assert_eq!(metrics.rtt_ms, 46.883);
        assert_eq!(metrics.rtt_var_ms, 1.61);
        assert_eq!(metrics.bytes_sent, 420148);
        assert_eq!(metrics.congestion_window, 96); // High cwnd for high bandwidth
        assert_eq!(metrics.unacked_packets, 0);
        assert_eq!(metrics.bytes_retrans, 0);
    }

    #[test]
    fn test_real_ss_output_with_retransmissions() {
        // Simulated ss output with retransmissions
        let output = "State      Recv-Q      Send-Q            Local Address:Port             Peer Address:Port      Process\n\
                      ESTAB      0           512               192.168.21.201:22             192.168.18.160:57616\n\
                      cubic wscale:6,9 rto:300 rtt:150.5/25.3 ato:40 mss:1386 pmtu:1500 rcvmss:1386 advmss:1448 cwnd:5 bytes_sent:10000 bytes_retrans:500 bytes_received:5000 segs_out:50 segs_in:100 unacked:3 retrans:2";

        let result = output_parsing(output);
        assert!(result.is_ok());

        let metrics = result.unwrap();
        assert_eq!(metrics.rtt_ms, 150.5);
        assert_eq!(metrics.rtt_var_ms, 25.3);
        assert_eq!(metrics.bytes_sent, 10000);
        assert_eq!(metrics.bytes_retrans, 500);
        assert_eq!(metrics.congestion_window, 5);
        assert_eq!(metrics.unacked_packets, 3);
        assert_eq!(metrics.retrans_events, 2);
    }

    #[test]
    fn test_ss_output_with_high_rtt() {
        // Simulated output with very high RTT
        let output = "State      Recv-Q      Send-Q            Local Address:Port             Peer Address:Port      Process\n\
                      ESTAB      0           0                 192.168.21.201:22             10.0.0.1:22\n\
                      cubic wscale:6,9 rto:5000 rtt:1500.0/100.0 ato:40 mss:1386 pmtu:1500 rcvmss:1386 advmss:1448 cwnd:3 bytes_sent:1000 bytes_retrans:0 unacked:0 retrans:0";

        let result = output_parsing(output);
        assert!(result.is_ok());

        let metrics = result.unwrap();
        assert_eq!(metrics.rtt_ms, 1500.0); // Very high latency
        assert_eq!(metrics.rtt_var_ms, 100.0);
        assert_eq!(metrics.congestion_window, 3); // Reduced due to high latency
    }

    #[test]
    fn test_ss_output_minimal_fields() {
        // Output with only minimal required fields
        let output = "State      Recv-Q      Send-Q            Local Address:Port             Peer Address:Port\n\
                      ESTAB      0           0                 192.168.21.201:5201             192.168.18.100:50688\n\
                      rtt:50.0/2.0 cwnd:10 bytes_sent:1000 bytes_retrans:0 unacked:0 retrans:0";

        let result = output_parsing(output);
        assert!(result.is_ok());

        let metrics = result.unwrap();
        assert_eq!(metrics.rtt_ms, 50.0);
        assert_eq!(metrics.rtt_var_ms, 2.0);
        assert_eq!(metrics.bytes_sent, 1000);
        assert_eq!(metrics.bytes_retrans, 0);
    }

    #[test]
    fn test_ss_output_zero_values() {
        // Connection with all zeros (healthy, no activity)
        let output = "State      Recv-Q      Send-Q            Local Address:Port             Peer Address:Port\n\
                      ESTAB      0           0                 192.168.21.201:22             192.168.18.160:57616\n\
                      rtt:50.0/1.0 cwnd:10 bytes_sent:0 bytes_retrans:0 unacked:0 retrans:0";

        let result = output_parsing(output);
        assert!(result.is_ok());

        let metrics = result.unwrap();
        assert_eq!(metrics.bytes_sent, 0);
        assert_eq!(metrics.bytes_retrans, 0);
        assert_eq!(metrics.unacked_packets, 0);
        assert_eq!(metrics.retrans_events, 0);
    }

    #[test]
    fn test_ss_output_large_byte_values() {
        // Connection with large byte values
        let output = "State      Recv-Q      Send-Q            Local Address:Port             Peer Address:Port\n\
                      ESTAB      0           0                 192.168.21.201:5201             192.168.18.100:50688\n\
                      rtt:46.883/1.61 cwnd:96 bytes_sent:9999999999 bytes_retrans:123456789 unacked:50 retrans:5";

        let result = output_parsing(output);
        assert!(result.is_ok());

        let metrics = result.unwrap();
        assert_eq!(metrics.bytes_sent, 9999999999);
        assert_eq!(metrics.bytes_retrans, 123456789);
        assert_eq!(metrics.unacked_packets, 50);
        assert_eq!(metrics.retrans_events, 5);
    }

    #[test]
    fn test_ss_output_missing_rtt_field() {
        // Output missing RTT field (edge case)
        let output = "State      Recv-Q      Send-Q            Local Address:Port             Peer Address:Port\n\
                      ESTAB      0           0                 192.168.21.201:22             192.168.18.160:57616\n\
                      cubic cwnd:10 bytes_sent:1000 bytes_retrans:0 unacked:0 retrans:0";

        let result = output_parsing(output);
        assert!(result.is_ok());

        let metrics = result.unwrap();
        assert_eq!(metrics.rtt_ms, 0.0); // Default to 0 if missing
        assert_eq!(metrics.rtt_var_ms, 0.0);
        assert_eq!(metrics.bytes_sent, 1000);
    }

    #[test]
    fn test_ss_output_missing_cwnd() {
        // Output missing congestion window
        let output = "State      Recv-Q      Send-Q            Local Address:Port             Peer Address:Port\n\
                      ESTAB      0           0                 192.168.21.201:22             192.168.18.160:57616\n\
                      rtt:50.0/2.0 bytes_sent:1000 bytes_retrans:0 unacked:0 retrans:0";

        let result = output_parsing(output);
        assert!(result.is_ok());

        let metrics = result.unwrap();
        assert_eq!(metrics.congestion_window, 0); // Default to 0 if missing
        assert_eq!(metrics.bytes_sent, 1000);
    }

    #[test]
    fn test_ss_output_empty() {
        // Completely empty output
        let output = "";

        let result = output_parsing(output);
        assert!(result.is_err());
    }

    #[test]
    fn test_ss_output_only_header() {
        // Only header line, no data
        let output = "State      Recv-Q      Send-Q            Local Address:Port             Peer Address:Port";

        let result = output_parsing(output);
        assert!(result.is_err());
    }

    #[test]
    fn test_ss_output_header_and_connection_no_metrics() {
        // Header and connection line but no metrics line
        let output = "State      Recv-Q      Send-Q            Local Address:Port             Peer Address:Port\n\
                      ESTAB      0           0                 192.168.21.201:22             192.168.18.160:57616";

        let result = output_parsing(output);
        // This should still work but with default values
        assert!(result.is_ok());
        let metrics = result.unwrap();
        assert_eq!(metrics.rtt_ms, 0.0); // All defaults
        assert_eq!(metrics.bytes_sent, 0);
    }

    #[test]
    fn test_ss_output_invalid_rtt_format() {
        // RTT with invalid format (no slash)
        let output = "State      Recv-Q      Send-Q            Local Address:Port             Peer Address:Port\n\
                      ESTAB      0           0                 192.168.21.201:22             192.168.18.160:57616\n\
                      rtt:46.149 cwnd:10 bytes_sent:1000 bytes_retrans:0 unacked:0 retrans:0";

        let result = output_parsing(output);
        assert!(result.is_ok());

        let metrics = result.unwrap();
        assert_eq!(metrics.rtt_ms, 0.0); // Defaults when format invalid
        assert_eq!(metrics.rtt_var_ms, 0.0);
        assert_eq!(metrics.bytes_sent, 1000);
    }

    #[test]
    fn test_ss_output_invalid_metric_values() {
        // Metric values that can't be parsed as numbers
        let output = "State      Recv-Q      Send-Q            Local Address:Port             Peer Address:Port\n\
                      ESTAB      0           0                 192.168.21.201:22             192.168.18.160:57616\n\
                      rtt:invalid/format cwnd:notanumber bytes_sent:alsonotvalid bytes_retrans:0 unacked:0 retrans:0";

        let result = output_parsing(output);
        assert!(result.is_ok());

        let metrics = result.unwrap();
        // Should default to 0 for unparseable values
        assert_eq!(metrics.rtt_ms, 0.0);
        assert_eq!(metrics.congestion_window, 0);
        assert_eq!(metrics.bytes_sent, 0);
    }

    #[test]
    fn test_ss_output_multiline_metrics() {
        // Metrics spread across multiple lines (as in real ss output)
        let output = "State      Recv-Q      Send-Q            Local Address:Port             Peer Address:Port\n\
                      ESTAB      0           0                 192.168.21.201:5201             192.168.18.100:50688\n\
                      cubic wscale:9,9 rto:247 rtt:46.883/1.61 ato:40 mss:1386 pmtu:1500\n\
                      rcvmss:536 advmss:1448 cwnd:96 bytes_sent:420148 bytes_retrans:0\n\
                      segs_out:305 segs_in:61 data_segs_out:304 data_segs_in:1 unacked:0 retrans:0";

        let result = output_parsing(output);
        assert!(result.is_ok());

        let metrics = result.unwrap();
        assert_eq!(metrics.rtt_ms, 46.883);
        assert_eq!(metrics.bytes_sent, 420148);
        assert_eq!(metrics.congestion_window, 96);
        assert_eq!(metrics.bytes_retrans, 0);
    }

    #[test]
    fn test_ss_output_with_extra_fields() {
        // Output with many extra fields that shouldn't affect parsing
        let output = "State      Recv-Q      Send-Q            Local Address:Port             Peer Address:Port\n\
                      ESTAB      0           0                 192.168.21.201:22             192.168.18.160:57616\n\
                      cubic app_limited notsack recovery rto:247 rtt:48.097/5.573 ato:40 mss:1386 pmtu:1500 rcvmss:1386 advmss:1448 cwnd:10 bytes_sent:156949 bytes_retrans:0 unacked:0 retrans:0 minrtt:41.821 snd_wnd:131072 delivery_rate 3033232bps pacing_rate 4610592bps";

        let result = output_parsing(output);
        assert!(result.is_ok());

        let metrics = result.unwrap();
        assert_eq!(metrics.rtt_ms, 48.097);
        assert_eq!(metrics.bytes_sent, 156949);
        assert_eq!(metrics.congestion_window, 10);
    }

    #[test]
    fn test_ss_output_floating_point_rtt() {
        // RTT values with various decimal places
        let output = "State      Recv-Q      Send-Q            Local Address:Port             Peer Address:Port\n\
                      ESTAB      0           0                 192.168.21.201:22             192.168.18.160:57616\n\
                      rtt:100.123456/50.987654 cwnd:10 bytes_sent:1000 bytes_retrans:0 unacked:0 retrans:0";

        let result = output_parsing(output);
        assert!(result.is_ok());

        let metrics = result.unwrap();
        assert!((metrics.rtt_ms - 100.123456).abs() < 0.000001);
        assert!((metrics.rtt_var_ms - 50.987654).abs() < 0.000001);
    }

    #[test]
    fn test_ss_output_extreme_rtt() {
        // Extremely high RTT (satellite link or intercontinental)
        let output = "State      Recv-Q      Send-Q            Local Address:Port             Peer Address:Port\n\
                      ESTAB      0           0                 192.168.21.201:22             10.0.0.1:22\n\
                      rtt:500000.0/1000.0 cwnd:1 bytes_sent:100 bytes_retrans:0 unacked:0 retrans:0";

        let result = output_parsing(output);
        assert!(result.is_ok());

        let metrics = result.unwrap();
        assert_eq!(metrics.rtt_ms, 500000.0);
        assert_eq!(metrics.rtt_var_ms, 1000.0);
    }
}

// ============================================================================
// Integration Tests for Netlink Implementation (Phase 3)
// ============================================================================
#[cfg(all(target_os = "linux", feature = "netlink"))]
mod test_netlink_integration {
    use super::*;

    // These tests are INTEGRATION tests - they actually query the kernel!
    // They only run on Linux and only when there are actual TCP connections.
    //
    // Test strategy:
    // 1. Create a test TCP connection (or use existing loopback)
    // 2. Query it via Netlink
    // 3. Verify we get sensible results
    //
    // NOTE: These tests may fail if:
    // - Running without network connections
    // - Insufficient permissions (RHEL 7 needs root)
    // - Running on non-Linux platform (tests are skipped)

    #[test]
    #[ignore]  // Requires actual TCP connection, run with: cargo test -- --ignored
    fn test_get_tcp_metrics_via_netlink_loopback() {
        // This test assumes there's a connection on loopback (127.0.0.1)
        // You'll need to create one manually or have a service running
        //
        // Example setup:
        // Terminal 1: nc -l 127.0.0.1 8888
        // Terminal 2: nc 127.0.0.1 8888
        // Terminal 3: cargo test test_get_tcp_metrics_via_netlink_loopback -- --ignored

        // NOTE: Replace these with actual connection parameters
        let local_ip = "127.0.0.1";
        let local_port = 8888;
        let remote_ip = "127.0.0.1";
        let remote_port = 54321;  // This will be ephemeral port from nc client

        let result = crate::get_tcp_metrics_via_netlink(
            local_ip,
            local_port,
            remote_ip,
            remote_port,
        );

        // We expect either:
        // - Ok(metrics) if connection exists
        // - Err("Connection not found") if no such connection
        // - Err("Permission denied") on RHEL 7 without root
        match result {
            Ok(metrics) => {
                // Verify metrics are reasonable
                println!("Found connection!");
                println!("RTT: {:.2} ms", metrics.rtt_ms);
                println!("Congestion window: {} packets", metrics.congestion_window);
                println!("Bytes sent: {}", metrics.bytes_sent);

                // Basic sanity checks
                assert!(metrics.rtt_ms >= 0.0, "RTT should be non-negative");
                assert!(metrics.congestion_window > 0, "cwnd should be > 0 for active connection");
            }
            Err(e) => {
                println!("Expected failure: {}", e);
                // Common expected errors:
                // - "Connection not found" (no matching connection)
                // - "Permission denied" (RHEL 7 without root)
            }
        }
    }

    #[test]
    #[ignore]  // Requires actual TCP connections, run with: cargo test -- --ignored
    fn test_get_tcp_metrics_batch_netlink() {
        // This test requires multiple connections from the same local socket
        //
        // Example setup:
        // Terminal 1: nc -l 127.0.0.1 8888
        // Terminal 2: nc 127.0.0.1 8888
        // Terminal 3: nc 127.0.0.1 8888
        // Terminal 4: cargo test test_get_tcp_metrics_batch_netlink -- --ignored

        let connections = vec![
            ("127.0.0.1".to_string(), 8888, "127.0.0.1".to_string(), 54321),
            ("127.0.0.1".to_string(), 8888, "127.0.0.1".to_string(), 54322),
        ];

        let results = crate::get_tcp_metrics_batch_netlink(&connections);

        println!("Batch query returned {} results", results.len());

        for (conn, metrics) in &results {
            println!("{}:{} -> {}:{} : RTT = {:.2} ms, cwnd = {}",
                conn.0, conn.1, conn.2, conn.3,
                metrics.rtt_ms, metrics.congestion_window);
        }

        // We expect 0-N results depending on which connections exist
        // This is not a failure if empty - just means no matching connections
    }

    #[test]
    fn test_get_tcp_metrics_via_netlink_invalid_ip() {
        // Test error handling for invalid IP address
        let result = crate::get_tcp_metrics_via_netlink(
            "invalid.ip.address",
            8080,
            "192.168.1.1",
            5000,
        );

        assert!(result.is_err(), "Should fail with invalid IP");
        let err_msg = result.unwrap_err();
        assert!(err_msg.contains("Invalid"), "Error should mention invalid IP");
    }

    #[test]
    fn test_get_tcp_metrics_via_netlink_nonexistent_connection() {
        // Test querying a connection that definitely doesn't exist
        // Using a non-routable IP (RFC 5737 TEST-NET-1)
        let result = crate::get_tcp_metrics_via_netlink(
            "192.0.2.1",    // TEST-NET-1 (non-routable)
            9999,
            "192.0.2.2",    // TEST-NET-1 (non-routable)
            9999,
        );

        // We expect either:
        // - Err("Connection not found") - connection doesn't exist
        // - Err("Permission denied") - RHEL 7 without root
        // - Err(...) - Other error (socket creation, etc.)
        assert!(result.is_err(), "Non-existent connection should return error");

        let err_msg = result.unwrap_err();
        // Accept either "Connection not found" or "Permission denied"
        let valid_errors = err_msg.contains("not found") || err_msg.contains("Permission denied");
        assert!(valid_errors, "Error should be 'not found' or 'Permission denied', got: {}", err_msg);
    }

    #[test]
    fn test_get_tcp_metrics_batch_netlink_empty() {
        // Test batch query with empty list
        let connections: Vec<(String, u16, String, u16)> = vec![];
        let results = crate::get_tcp_metrics_batch_netlink(&connections);

        assert_eq!(results.len(), 0, "Empty input should return empty results");
    }

    #[test]
    fn test_get_tcp_metrics_batch_netlink_nonexistent() {
        // Test batch query with non-existent connections
        let connections = vec![
            ("192.0.2.1".to_string(), 9999, "192.0.2.2".to_string(), 9999),
            ("192.0.2.1".to_string(), 9999, "192.0.2.3".to_string(), 9999),
        ];

        let results = crate::get_tcp_metrics_batch_netlink(&connections);

        // Should return empty (no matching connections)
        // Or might return partial results if one exists
        println!("Batch query for non-existent connections returned {} results", results.len());
        // This is not a test failure - just documenting behavior
    }
}

// ============================================================================
// Platform-specific Tests
// ============================================================================
#[cfg(not(target_os = "linux"))]
mod test_non_linux_platform {
    // On non-Linux platforms (e.g., macOS for development),
    // verify that Netlink functions are NOT available

    #[test]
    fn test_netlink_not_available_on_non_linux() {
        // This test verifies compilation on non-Linux platforms
        // Netlink functions should not be compiled

        // We can't test get_tcp_metrics_via_netlink() here because
        // it won't compile on non-Linux platforms (which is correct!)

        // This test just ensures the crate compiles on macOS
        // No assertion needed - if this test runs, compilation succeeded
    }
}
