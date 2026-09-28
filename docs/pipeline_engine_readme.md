# Diode-Sentinel: Ingestion, Feature Pipeline & Data Generation
### NTRO Problem Statement 26145 — Person 2 Architecture & Build Spec

> **Prime Directive**: **Read-only, one direction, never write back.**
> If any code opens an outbound socket, sends an active probe, or completes a handshake back toward the traffic source, that is a critical architectural violation.

---

## 1. Architectural Philosophy & Physical Diode Model

In critical infrastructure environments (e.g. power grids, telecommunications, defense command networks), gateways and peering links are observed via **passive optical TAPs** or **hardware data diodes** that mirror traffic into an isolated monitoring enclave in one direction only.

```
                           PROTECTED PRODUCTION NETWORK
                       [ Gateway / Core Peering Router ]
                                      |
                     [ Passive Optical Full-Duplex TAP ]
                             | (Rx)              | (Tx)
                             +---------+---------+
                                       |
                       +-------------------------------+
                       | Physical Hardware Data Diode  |
                       | (Tx fiber physically removed) |
                       +-------------------------------+
                                       | (One-Way Ingest Only)
                                       v
                     +===================================+
                     |    DIODE-SENTINEL SECURE ENCLAVE  |
                     |                                   |
                     |  [ PcapReader / Live Sniffer ]    |
                     |                 |                 |
                     |                 v                 |
                     |      [ Flow Aggregator ]          |
                     |   (5-Tuple Sliding Window)        |
                     |                 |                 |
                     |                 v                 |
                     |    [ 6 Threat Feature Engines ]   |
                     |                 |                 |
                     |                 v                 |
                     |      [ FlowFeatureRecord ]        |
                     |     (Pydantic v2 Contract)        |
                     |         /             \           |
                     |        v               v          |
                     |   [ Person 3 ]    [ Person 4 ]    |
                     |   (ML Models)     (Dashboard)     |
                     |                                   |
                     |   [ Dual Diode Watchdog ]         |
                     |   (psutil Sockets + NIC Delta)    |
                     +===================================+
```

### Full-Duplex Source Traffic over One-Way Diode
> **Official Defense Statement**:
> *"The hardware data diode enforces strict one-way data flow into the analysis enclave (the physical transmit fiber of the enclave is severed); the mirrored source traffic copied into the diode is full-duplex (an optical TAP or SPAN port aggregately mirroring both Tx and Rx directions of the gateway link into the diode's input)."*
> This is why bidirectional metrics (e.g., outbound-to-inbound byte ratio for exfiltration) are fully observable while maintaining 100% hardware diode compliance. If only a single leg is tapped, `volume_asymmetry.py` automatically engages its single-leg fallback mode.

---

## 2. Directory Structure

```
diode-sentinel/
├── schemas/
│   ├── __init__.py
│   └── flow_feature_record.py     # Authoritative Pydantic contract (Person 2 <-> 3 <-> 4)
├── ingestion/
│   ├── __init__.py
│   ├── pcap_reader.py             # Streaming PCAP reader with O(1) memory
│   ├── live_capture.py            # Read-only promiscuous live interface capture
│   └── diode_compliance.py        # Dual-check zero-egress watchdog
├── features/
│   ├── __init__.py
│   ├── flow_aggregator.py         # 5-tuple sliding-window engine + windowed GlobalContext
│   ├── volumetric.py              # Feeds (a) Volumetric DDoS
│   ├── timing.py                  # Feeds (b) Botnet C2 beaconing
│   ├── dns_lexical.py             # Feeds (c) DGA & DNS tunneling
│   ├── crypto_metadata.py         # Feeds (d) Encrypted malware (JA3/JA4, zero decryption)
│   ├── fanout.py                  # Feeds (e) Reconnaissance & port scans
│   └── volume_asymmetry.py        # Feeds (f) Asymmetric data exfiltration
├── data_generation/
│   ├── __init__.py
│   ├── benign_traffic_gen.py      # Generates steady & bursty normal traffic
│   ├── attack_traffic_gen.py      # Generates 6 labeled attack PCAPs with sidecars
│   └── README_tools.md            # Lab tools (iperf3, TRex, hping3, dnscat2) guide
├── benchmark/
│   ├── __init__.py
│   └── throughput_bench.py        # Measured prototype throughput and latency suite
├── run_pipeline.py                # Master CLI pipeline runner
└── README.md
```

---

## 3. The Standout Feature: Dual-Check Diode Watchdog

To provide mathematical and operational proof to evaluators that zero egress occurs, `ingestion/diode_compliance.py` runs a continuous background watchdog using a **dual-check architecture**:

1. **Level 1 (Process Socket Inspection)**:
   Inspects `psutil.Process().net_connections()` to ensure no socket enters `SYN_SENT`, `ESTABLISHED`, or connects to any remote IP.
2. **Level 2 (Interface I/O Counter Tracking)**:
   Monitors `psutil.net_io_counters(pernic=True)` on the capture NIC to ensure `bytes_sent` delta is **strictly 0**. This catches raw-socket transmissions (such as accidental `scapy.sendp()` calls) that bypass standard OS socket tables.

Outputs live status JSON (`diode_compliance_status.json`) polled by Person 4's dashboard:
```json
{
  "compliant": true,
  "egress_bytes": 0,
  "violations_count": 0,
  "monitored_interface": "all",
  "dual_check_status": {
    "process_socket_table": "CLEAN",
    "nic_io_counter": "CLEAN (0 bytes sent delta)"
  },
  "last_checked": "2026-09-03T18:55:00Z"
}
```

---

## 4. The Six Feature Calculators

All calculators in `features/` are pure, stateless functions receiving `Flow` state:

| Threat Category | Feature Module | Mathematical / Algorithmic Formulation |
|---|---|---|
| **(a) Volumetric DDoS** | `features/volumetric.py` | SYN:ACK ratio ($\frac{\text{SYN}}{\max(1, \text{ACK})}$), packet rate (pps), byte rate (bps), source-IP Shannon entropy ($H = -\sum p \log_2 p$). |
| **(b) Botnet C2 Beaconing** | `features/timing.py` | Inter-arrival time (IAT) mean, variance, coefficient of variation ($CV = \frac{\sigma}{\mu}$ where $CV < 0.2$ indicates beaconing), lag-1 autocorrelation periodicity score ($0.0 \to 1.0$). |
| **(c) DGA & DNS Tunnelling** | `features/dns_lexical.py` | QNAME Shannon entropy, consonant-to-vowel ratio, query length, subdomain depth, TXT/NULL record detection (e.g. dnscat2/iodine covert channels). |
| **(d) Encrypted Malware** | `features/crypto_metadata.py` | **Zero payload decryption**: JA3 MD5 digest, JA4 string, TLS version, cipher suite count, extension list, early packet-size sequence (PZX biometric). |
| **(e) Port Scanning** | `features/fanout.py` | Windowed `GlobalContext` tracking distinct destination IPs, destination ports, scan rate (pps), and half-open SYN ratio. |
| **(f) Data Exfiltration** | `features/volume_asymmetry.py` | Outbound:inbound byte ratio ($\frac{\text{fwd\_bytes}}{\max(1, \text{bwd\_bytes})}$), upload velocity (bps), exfil risk score, with automatic fallback for single-direction taps. |

---

## 5. Authoritative Data Contract (`FlowFeatureRecord`)

Agreed schema between Person 2, Person 3 (Model Training/Inference), and Person 4 (Dashboard):

```json
{
  "flow_id": "192.168.1.50:54321->45.33.22.11:443/TCP",
  "src_ip": "192.168.1.50",
  "src_port": 54321,
  "dst_ip": "45.33.22.11",
  "dst_port": 443,
  "protocol": "TCP",
  "window_start": "2026-09-03T12:51:30Z",
  "window_end": "2026-09-03T12:52:00Z",
  "window_duration_sec": 30.0,
  "volumetric": {
    "packet_count": 120,
    "packet_rate_pps": 4.0,
    "byte_rate_bps": 5600.0,
    "src_ip_entropy": 0.0,
    "syn_ack_ratio": 0.02
  },
  "timing": {
    "iat_mean_ms": 250.4,
    "iat_cv": 0.08,
    "periodicity_score": 0.89
  },
  "dns_lexical": {
    "has_dns": false
  },
  "crypto_metadata": {
    "is_tls_quic": true,
    "ja3_digest": "ada70206e40642a3e4461f35503241d5",
    "ja4_str": "t13d1512_8daaf6152771",
    "packet_size_sequence": [517, 1420, 240, 1420]
  },
  "fanout": {
    "dst_port_count": 1,
    "dst_ip_count": 1,
    "scan_rate_pps": 0.03
  },
  "volume_asymmetry": {
    "outbound_bytes": 12400,
    "inbound_bytes": 89400,
    "byte_ratio": 0.138,
    "exfil_risk_score": 0.01
  }
}
```

---

## 6. Demonstrated Prototype Throughput & Benchmark

Per NTRO requirements to **state and demonstrate throughput targets upfront**:

- **Measured Profile A**: 3,105 pure-engine packets/sec; 1,197.8 wall-clock packets/sec
- **Measured Profile B**: 2,000 concurrent-flow stress profile; 482.9 wall-clock packets/sec
- **Max Latency Bound**: $\le 2.0\text{s}$ at $P_{99}$

These are single-process Python prototype measurements. The higher 5,000
flows/sec and 50,000 packets/sec capacity remains a production scaling target,
not a demonstrated result of this repository.

Run the benchmark:
```bash
python benchmark/throughput_bench.py
```
Exports `benchmark_results.json` and `benchmark_results.csv` for Person 4's dashboard throughput graph.

---

## 7. Quickstart Commands

```bash
# 1. Generate all synthetic benign & attack PCAPs with ground-truth sidecars
python run_pipeline.py --generate-data

# 2. Run the streaming pipeline on a test PCAP with live watchdog
python run_pipeline.py --pcap data_generation/pcaps/attack_c2_beacon.pcap --output beacon_features.jsonl

# 3. Execute SLA Throughput Benchmark
python run_pipeline.py --bench
```
