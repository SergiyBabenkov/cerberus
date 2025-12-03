# Cerberus

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust Version](https://img.shields.io/badge/rust-1.85%2B-blue.svg)](https://www.rust-lang.org)
[![Platform](https://img.shields.io/badge/platform-Linux-lightgrey.svg)](https://www.kernel.org)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)](#)

Lightweight TCP connection health monitor for systems that require fast detection of degraded, stale, or silently dead network paths. Cerberus evaluates connection stability using an application event-driven sampling model, applying statistical metrics over a sliding window of recent observations. The primary goal is to detect early symptoms of failure within one to two seconds when possible, while maintaining a minimal monitoring footprint.

## Why This Matters

Traditional TCP monitoring surfaces only coarse indicators such as connection up/down state or kernel-level retransmissions. These signals often lag behind real degradations. Cerberus provides a higher-resolution, application-level view of connection quality by computing derived metrics from message-level timing and behavior. This enables early detection of latency spikes, stalls, zombie connections, and silent failure modes that kernel TCP does not surface quickly enough.

## Key Features

- **Dynamic Socket Monitoring** - Specify monitoring targets per API request (no restart needed)
- **Sub-10ms Response Time** - Fast enough for real-time decision making
- **Zero Dependencies** - Standalone binary with embedded HTTP server
- **Multi-Factor Health Scoring** - Queue analysis, RTT, retransmissions, trend detection
- **No Root Required** - Uses `/proc/net/tcp`, `/proc/net/tcp6`, and Linux INET_DIAG protocol via Netlink

## Use Cases

### Message Delivery Systems
Perfect for systems sending 1-2KB messages where:
- Every message matters (payment processing, trading systems)
- Latency is critical (<200ms expected delivery)
- Connection health directly impacts reliability

### When to Use Cerberus
- Nginx reverse proxy to external clients  
- Message queue producers checking broker connections  
- API gateways sending to microservices  
- Real-time notification delivery systems
- Real-time monitoring of TCP connections in low-latency applications

### When NOT to Use
- Large file transfers (use different thresholds)
- Connections with expected high buffering
- Non-TCP protocols

## Prerequisites

Before building and running Cerberus, ensure you have:

### Required

- **Rust**: Version 1.85 or higher
  ```bash
  # Check your version
  cargo --version
  ```

- **Operating System**: Linux with kernel 3.10+ (RHEL 7+)
  - **RHEL 7** (kernel 3.10): May require root or CAP_NET_ADMIN for netlink features
  - **RHEL 8/9** (kernel 4.18+): No root required, all features work
  - **macOS**: Code compiles but monitoring features are disabled (development/testing only)

### Dependencies

All Rust dependencies are automatically handled by Cargo:
- `serde` + `serde_json` - JSON serialization
- `parking_lot` - Fast RwLock implementation for concurrency
- `threadpool` - HTTP server worker thread management
- `ctrlc` - Graceful shutdown handling
- `libc` - Linux syscalls (Netlink, socket operations)

### For Testing

- Active TCP connections required for functional testing
- `iperf3` recommended for local testing (see [Development Setup](#development-setup))

## Quick Start

### Rust Version
```bash
cd cerberus
cargo build --release

# Run on default port 8888
./target/release/cerberus

# Run on custom port
./target/release/cerberus 9000
```

## API Usage

### Check Single Connection (Specific 4-tuple)
```bash
curl -X POST http://localhost:8888/monitor \
  -H "Content-Type: application/json" \
  -d '{
    "local_ip": "10.0.1.5",
    "local_port": 80,
    "remote_ip": "93.184.216.34",
    "remote_port": 443
  }'
```

**Response:**

```json
{
  "timestamp": 1764639861743,
  "found": true,
  "connection": {
    "local_address": "192.168.21.201:5201",
    "remote_address": "192.168.18.100:51555",
    "state": "ESTABLISHED",
    "state_code": 1,
    "send_queue_bytes": 612612,
    "recv_queue_bytes": 0
  },
  "tcp_metrics": {
    "rtt_ms": 48.186,
    "rtt_var_ms": 1.8,
    "bytes_sent": 238591584,
    "bytes_retrans": 84546,
    "congestion_window": 53,
    "unacked_packets": 53,
    "retrans_events": 0,
    "min_rtt_ms": 41.595,
    "delivery_rate_bps": 1553220,
    "rwnd_limited_us": 55000,
    "busy_time_us": 116154000,
    "total_retrans": 61,
    "snd_ssthresh": 48,
    "pmtu": 1500
  },
  "health": {
    "status": "STALE",
    "score": 23,
    "safe_to_send": false,
    "reasons": "CRITICAL: Send queue >= 4KB (2+ messages stuck); Active retransmissions detected; Retransmit rate: 0.04%; Data queued with unacked packets (stalling); Unacked > 70% of cwnd (congestion); Queue growing trend detected; Queue already elevated + growing; Queue persistently high for 10 consecutive samples; Queue accelerating (967 bytes/sec²)",
    "trend_metrics": {
      "send_queue_velocity": 2400.479290592875,
      "recv_queue_velocity": 0.0,
      "send_queue_acceleration": 967.495327955306,
      "recv_queue_acceleration": 0.0,
      "send_queue_variance": 82158.8253606393,
      "recv_queue_variance": 0.0,
      "send_queue_ma_short": 474936.0,
      "send_queue_ma_long": 474843.6,
      "send_queue_persistent": true,
      "send_queue_high_count": 10,
      "queue_growing": true,
      "queue_shrinking": false,
      "high_volatility": false,
      "sample_count": 10,
      "stale_suspect_send": {
        "value": false,
        "explanation": "Send-side active (0ms since last data sent, threshold: 1500ms)"
      },
      "stale_suspect_recv": {
        "value": false,
        "explanation": "Recv-side active (1ms since last ACK, threshold: 1500ms)"
      },
      "stale_confirmed_send": {
        "value": false,
        "explanation": "Send-side OK (0ms since last data sent, threshold: 3000ms)"
      },
      "stale_confirmed_recv": {
        "value": false,
        "explanation": "Recv-side OK (1ms since last ACK, threshold: 3000ms)"
      },
      "half_open_suspect": {
        "value": false,
        "explanation": "Connection responsive (last ACK: 1ms ago, 53 unacked bytes)"
      },
      "half_open_confirmed": {
        "value": false,
        "explanation": "Connection not half-open (ACKs being received normally)"
      },
      "loss_detected": {
        "value": true,
        "explanation": "CRITICAL: 1 packet retransmission(s) detected in window. For ~1KB messages, this adds RTT delay and indicates connection issues."
      },
      "loss_rate_pct": {
        "value": 0.0697350069735007,
        "explanation": "Loss rate 0.07% (1386 bytes lost of 1987524 sent, threshold: 1.0%)"
      },
      "rtt_drift": {
        "value": 1.1584565452578435,
        "explanation": "RTT drift 1.2x baseline (48.19ms current vs 41.59ms min, threshold: 3.0x)"
      },
      "jitter_index": {
        "value": 0.03735524841240194,
        "explanation": "Jitter 0.04 (1.80ms variance / 48.19ms RTT, threshold: 0.35)"
      },
      "recv_limited_pct": {
        "value": 0.0,
        "explanation": "Receiver OK: 0.0% rwnd-limited (threshold: 40%)"
      },
      "sender_limited_pct": {
        "value": 0.0,
        "explanation": "Sender OK: 0.0% sndbuf-limited (threshold: 40%)"
      },
      "congestion_suspected": {
        "value": true,
        "explanation": "Congestion suspected (early warning): cwnd decreased from 60 to 53 segments, 1 retransmissions in window. Watch connection closely."
      },
      "congestion_confirmed": {
        "value": false,
        "explanation": "Not congested (cwnd 53 >= ssthresh 48)"
      },
      "rto_inflation": {
        "value": 5.167476030382269,
        "explanation": "RTO INFLATED: 5.2x RTT (249ms RTO vs 48.19ms RTT, threshold: 4.0x). TCP expects packet loss - connection near failure."
      }
    }
  }
}
```

### Monitor All Connections to Remote IP (Any Port)
```bash
curl -X POST http://localhost:8888/monitor \
  -H "Content-Type: application/json" \
  -d '{
    "local_ip": "10.0.1.5",
    "local_port": 80,
    "remote_ip": "93.184.216.34"
  }'
```

Returns array of all connections from local_ip:local_port to remote_ip, sorted by health (worst first).

## Architecture
```
┌─────────────┐      ┌──────────────┐      ┌─────────────┐
│  Upstream   │─────▶│    Nginx     │─────▶│   Client    │
│     App     │      │   (Proxy)    │      │ (External)  │
└──────┬──────┘      └──────────────┘      └─────────────┘
       │
       │ HTTP API
       ▼
┌─────────────────────────────────────────┐
│         Cerberus                        │
│  ┌─────────────┐    ┌────────────────┐  │
│  │ /proc/net/  │◀───│  Health        │  │
│  │    tcp      │    │  Assessor      │  │
│  └─────────────┘    └────────────────┘  │
│  ┌─────────-----────┐                   │
│  │ Linux INET_DIAG  │                   │
│  └──────────-----───┘                   │
└─────────────────────────────────────────┘
```

Cerberus consists of three layers: event ingestion, metrics engine, and API.
```
     +-----------------------------+
     |    External Application     |
     |  Emits message-level events |
     +--------------+--------------+
                    |
                    v
     +-----------------------------+
     |     Event Ingestion Layer   |
     | Parses samples and updates  |
     | the sliding window          |
     +--------------+--------------+
                    |
                    v
     +-----------------------------+
     |    Sliding Window Engine    |
     | Maintains last N samples,   |
     | computes all derived metrics|
     +--------------+--------------+
                    |
                    v
     +-----------------------------+
     |         Metrics API         |
     | Query current metrics, JSON |
     | output, thresholds, alerts  |
     +-----------------------------+
```

## Configuration

### Startup
```bash
# Default port 8888
./cerberus

# Custom HTTP port
./cerberus 9000
```

### Request Parameters
All API requests to `/monitor` must specify the monitoring target:

```json
{
  "local_ip": "10.0.1.5",          // REQUIRED - Local IP to monitor
  "local_port": 80,                // REQUIRED - Local port to monitor
  "remote_ip": "93.184.216.34",    // REQUIRED - Remote IP to match
  "remote_port": 443,              // optional - omit to match all ports
  "established_only": true,        // optional, default: true
  "sort_by_health": true           // optional, default: true
}
```

## Health Status

| Status   | Score | Safe to Send | Description           | Common Causes                                           |
|----------|-------|--------------|-----------------------|---------------------------------------------------------|
| HEALTHY  |  0-1  |     Yes      | Normal operation      | All metrics optimal                                     |
| CAUTION  |  1-2  |     Yes      | Monitor closely       | Slight RTT elevation, minor queue buildup               |
| SUSPECT  |  3-4  |    Maybe     | Potential issues      | Moderate RTT or queue, retransmission events            |
| DEGRADED |  5-6  |     No       | Connection struggling | Send queue ≥2KB, high unacked ratio                     |
| STALE    |  7+   |     No       | Connection broken     | Critical send queue, active retransmissions, severe RTT |

### Health Assessment Factors

Cerberus evaluates multiple factors:

#### Basic Connection Info

- **Send Queue Size** - Bytes stuck in kernel send buffer (indicates bottleneck)
  - HEALTHY: <1KB
  - CAUTION: 1-2KB (partial message stuck)
  - SUSPECT: 2KB+ (full message stuck)
  - DEGRADED: 4KB+ (2+ messages stuck)

- **Round Trip Time (RTT)** - Network latency to remote peer
  - HEALTHY: <200ms
  - CAUTION: 200-500ms
  - SUSPECT: 500ms-1s
  - STALE: >1s

- **Retransmissions** - Packet loss and recovery attempts
  - Active retransmissions → STALE (no data flowing)
  - Recent retransmission events → SUSPECT (network unreliable)

- **Unacked Packet Ratio** - Congestion window utilization
  - >70% of CWND → DEGRADED (severe congestion)
  - >50% of CWND → CAUTION (moderate congestion)

#### Extended TCP connection information and Trend Analysis

| Metric              | Field              | Unit         | Available Since        | What It Tells You        |
|---------------------|--------------------|--------------|------------------------|--------------------------|
| RTT                 | tcpi_rtt           | microseconds | Kernel 3.10+ (RHEL 7+) | Network latency to peer  |
| RTT Variance        | tcpi_rttvar        | microseconds | Kernel 3.10+ (RHEL 7+) | Latency stability/jitter |
| Bytes Sent          | tcpi_bytes_sent    | bytes        | Kernel 5.5+ (RHEL 9+)  | Total data transmitted   |
| Bytes Retransmitted | tcpi_bytes_retrans | bytes        | Kernel 5.5+ (RHEL 9+)  | Data loss amount         |
| Congestion Window   | tcpi_snd_cwnd      | packets      | Kernel 3.10+ (RHEL 7+) | Send capacity            |
| Unacked Packets     | tcpi_unacked       | packets      | Kernel 3.10+ (RHEL 7+) | In-flight data           |
| Retrans Events      | tcpi_retrans       | count        | Kernel 3.10+ (RHEL 7+) | Current retransmits      |

### Detailed TCP Metrics

**Performance & Throughput Metrics**

| Metric              | Field                | Unit         | Available Since       | Why You'd Want This                                       |
|---------------------|----------------------|--------------|-----------------------|-----------------------------------------------------------|
| Minimum RTT         | tcpi_min_rtt         | microseconds | Kernel 4.6+ (RHEL 8+) | Baseline latency - best possible performance to this peer |
| Delivery Rate       | tcpi_delivery_rate   | bytes/sec    | Kernel 4.6+ (RHEL 8+) | Actual throughput - real data delivery speed              |
| Pacing Rate         | tcpi_pacing_rate     | bytes/sec    | Kernel 4.2+ (RHEL 8+) | Send rate limit - how fast kernel is pacing sends         |
| Max Pacing Rate     | tcpi_max_pacing_rate | bytes/sec    | Kernel 4.2+ (RHEL 8+) | Maximum allowed send rate.                                |
| Bytes Acked         | tcpi_bytes_acked     | bytes        | Kernel 4.2+ (RHEL 8+) | Successfully delivered data.                              |
| Bytes Received      | tcpi_bytes_received  | bytes        | Kernel 4.2+ (RHEL 8+) | Total data received                                       |


**Bottleneck Detection Metrics**

| Metric              | Field                | Unit         | Available Since       | Why You'd Want This                                       |
|---------------------|----------------------|--------------|-----------------------|-----------------------------------------------------------|
| Busy Time           | tcpi_busy_time       | microseconds | Kernel 4.9+ (RHEL 8+) | Time with data in flight - % utilization                  |
| RWND Limited Time   | tcpi_rwnd_limited    | microseconds | Kernel 4.9+ (RHEL 8+) | Receiver bottleneck - peer can't keep up                  |
| SNDBUF Limited Time | tcpi_sndbuf_limited  | microseconds | Kernel 4.9+ (RHEL 8+) | Application bottleneck - you're not sending fast enough   |
| Not Sent Bytes      | tcpi_notsent_bytes   | bytes        | Kernel 4.6+ (RHEL 8+) | Queued but not sent - internal buffering                  |

**Loss & Recovery Metrics**

| Metric               | Field              | Unit    | Available Since        | Why You'd Want This                          |
|----------------------|--------------------|---------|------------------------|----------------------------------------------|
| Lost Packets         | tcpi_lost          | packets | Kernel 3.10+ (RHEL 7+) | Packet loss count                            |
| SACKed Packets       | tcpi_sacked        | packets | Kernel 3.10+ (RHEL 7+) | Selective ACK'd packets - partial recovery   |
| Total Retrans        | tcpi_total_retrans | count   | Kernel 3.10+ (RHEL 7+) | Lifetime retransmissions                     |
| Reordering           | tcpi_reordering    | packets | Kernel 3.10+ (RHEL 7+) | Packet reorder metric                        |
| Reordering Seen      | tcpi_reord_seen    | count   | Kernel 5.5+ (RHEL 9+)  | Reordering events                            |
| Out-of-Order Packets | tcpi_rcv_ooopack   | packets | Kernel 5.8+ (RHEL 9+)  | Receive side reordering                      |
| DSACK Duplicates     | tcpi_dsack_dups    | packets | Kernel 5.5+ (RHEL 9+)  | Duplicate SACKs - spurious retrans detection |


**Congestion Control Metrics**

| Metric            | Field             | Unit       | Available Since        | Why You'd Want This                                              |
|-------------------|-------------------|------------|------------------------|------------------------------------------------------------------|
| CA State          | tcpi_ca_state     | enum       | Kernel 3.10+ (RHEL 7+) | Congestion state (0=Open, 1=Disorder, 2=CWR, 3=Recovery, 4=Loss) |
| Send Threshold    | tcpi_snd_ssthresh | packets    | Kernel 3.10+ (RHEL 7+) | Slow start threshold                                             |
| Receive Threshold | tcpi_rcv_ssthresh | packets    | Kernel 3.10+ (RHEL 7+) | Receive slow start threshold                                     |
| Backoff           | tcpi_backoff      | multiplier | Kernel 3.10+ (RHEL 7+) | Exponential backoff level                                        |

**Segment & MSS Metrics**

| Metric            | Field              | Unit  | Available Since        | Why You'd Want This             |
|-------------------|--------------------|-------|------------------------|---------------------------------|
| Send MSS          | tcpi_snd_mss       | bytes | Kernel 3.10+ (RHEL 7+) | Max segment size - MTU related  |
| Receive MSS       | tcpi_rcv_mss       | bytes | Kernel 3.10+ (RHEL 7+) | Peer's max segment size         |
| Path MTU          | tcpi_pmtu          | bytes | Kernel 3.10+ (RHEL 7+) | Path MTU discovery result       |
| Advertised MSS    | tcpi_advmss        | bytes | Kernel 3.10+ (RHEL 7+) | MSS advertised to peer          |
| Segments Out      | tcpi_segs_out      | count | Kernel 4.2+ (RHEL 8+)  | Total segments sent             |
| Segments In       | tcpi_segs_in       | count | Kernel 4.2+ (RHEL 8+)  | Total segments received         |
| Data Segments Out | tcpi_data_segs_out | count | Kernel 4.6+ (RHEL 8+)  | Data-carrying segments sent     |
| Data Segments In  | tcpi_data_segs_in  | count | Kernel 4.6+ (RHEL 8+)  | Data-carrying segments received |

**Timing & Timeout Metrics**

| Metric             | Field               | Unit         | Available Since        | Why You'd Want This                   |
|--------------------|---------------------|--------------|------------------------|---------------------------------------|
| RTO                | tcpi_rto            | microseconds | Kernel 3.10+ (RHEL 7+) | Retransmit timeout                    |
| ATO                | tcpi_ato            | microseconds | Kernel 3.10+ (RHEL 7+) | ACK timeout                           |
| Last Data Sent     | tcpi_last_data_sent | milliseconds | Kernel 3.10+ (RHEL 7+) | Time since last data - idle detection |
| Last ACK Received  | tcpi_last_ack_recv  | milliseconds | Kernel 3.10+ (RHEL 7+) | Time since last ACK                   |
| Last Data Received | tcpi_last_data_recv | milliseconds | Kernel 3.10+ (RHEL 7+) | Time since peer sent data             |

**Window & Buffer Metrics**

| Metric         | Field          | Unit         | Available Since        | Why You'd Want This     |
|----------------|----------------|--------------|------------------------|-------------------------|
| Receive Window | tcpi_rcv_space | bytes        | Kernel 3.10+ (RHEL 7+) | Receive buffer size     |
| Receive RTT    | tcpi_rcv_rtt   | microseconds | Kernel 3.10+ (RHEL 7+) | Receiver's RTT estimate |
| Send Window    | tcpi_snd_wnd   | bytes        | Kernel 5.8+ (RHEL 9+)  | Advertised send window  |

**ECN & Delivery Metrics**

| Metric            | Field             | Unit    | Available Since       | Why You'd Want This          |
|-------------------|-------------------|---------|-----------------------|------------------------------|
| Delivered Packets | tcpi_delivered    | packets | Kernel 5.5+ (RHEL 9+) | Data packets delivered       |
| Delivered CE      | tcpi_delivered_ce | packets | Kernel 5.5+ (RHEL 9+) | ECN-marked packets delivered |

**State & Options**

| Metric        | Field                             | Unit   | Available Since        | Why You'd Want This                              |
|---------------|-----------------------------------|--------|------------------------|--------------------------------------------------|
| TCP State     | tcpi_state                        | enum   | Kernel 3.10+ (RHEL 7+) | Connection state (1=ESTABLISHED, etc.)           |
| TCP Options   | tcpi_options                      | bitmap | Kernel 3.10+ (RHEL 7+) | Enabled options (timestamps, SACK, window scale) |
| Window Scales | tcpi_snd_wscale / tcpi_rcv_wscale | bits   | Kernel 3.10+ (RHEL 7+) | Window scaling factors                           |
| Probes        | tcpi_probes                       | count  | Kernel 3.10+ (RHEL 7+) | Zero-window probes sent                          |
| Retransmits   | tcpi_retransmits                  | count  | Kernel 3.10+ (RHEL 7+) | Number of retransmit attempts

### Other API Endpoints

**Health Check** - Verify service is running
```bash
curl http://localhost:8888/health
# Response: {"status": "ok"}
```

**Configuration** - Show server info
```bash
curl http://localhost:8888/config
# Response: {
#   "http_server_info": "Cerberus TCP Monitor vx.x.x - Dynamic socket monitoring per request",
#   "monitor_per_request": true
# }
```

### Development Setup
```bash
git clone https://github.com/SergiyBabenkov/cerberus.git
cd cerberus

# Development build (default, uses netlink)
cargo build

# Release build with optimizations
cargo build --release

# Run tests
cargo test

# Run linter
cargo clippy

# Format code
cargo fmt
```

### Running
```bash
# Run with default port (8888)
cargo run

# Run with custom port
cargo run -- 9000

# Run release build
./target/release/cerberus

# Production deployment with custom port
./target/release/cerberus 9000
```

## Acknowledgments

Built for high-frequency message delivery systems where reliability matters.
Inspired by the need for sub-second stale connection detection in financial transaction processing.