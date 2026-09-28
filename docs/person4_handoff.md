# Person 4 Integration & Dashboard Handoff Specification
**System**: Diode-Sentinel — NTRO Cyber Threat Detection Engine (SIH PS 26145)  
**Audience**: Person 4 (Operations Dashboard, UI Visualization & Live Streaming)  
**Date**: September 6, 2026  

---

## 1. Executive Summary

This document specifies the integration contracts, telemetry endpoints, and streaming formats necessary for Person 4 to connect the frontend dashboard to the backend ingestion, detection, and compliance engines.

---

## 2. Schema Field Inventory

All records emitted by the backend adhere strictly to Pydantic v2 schemas located in `schemas/`.

### 2.1 Alert Schema (`schemas.alert_record.Alert`)

| Field | Type | Description |
| :--- | :--- | :--- |
| `alert_id` | `str` | Unique generated identifier (e.g. `ALT-ABC12345`) |
| `timestamp` | `datetime` | UTC timestamp of alert promotion |
| `flow_identifier` | `str` | Canonical 5-tuple string (`src_ip:src_port->dst_ip:dst_port/protocol`) |
| `src_ip` | `str` | Source IPv4 / IPv6 address |
| `dst_ip` | `str` | Destination IPv4 / IPv6 address |
| `threat_class` | `ThreatClass` | Enum values defined in `schemas.alert_record.ThreatClass` |
| `confidence_score` | `float` | Corroborated confidence $[0.0, 1.0]$ |
| `supporting_evidence` | `str` | Human-readable evidence with feature values |
| `corroboration_count` | `int` | Number of independent signals accepted |
| `persistence_windows` | `int` | Number of windows observed before promotion |
| `incident_id` | `Optional[str]` | Associated correlated incident ID (if linked by `ChainMatcher`) |
| `host` | `Optional[str]` | Source host alias; normalized with `src_ip` |

### 2.2 Incident Schema (`schemas.incident_record.IncidentRecord`)

| Field | Type | Description |
| :--- | :--- | :--- |
| `incident_id` | `str` | Unique Incident identifier (e.g. `INC-RECON-EXFIL-001`) |
| `chain_pattern` | `str` | Pattern: `recon_to_c2_to_exfil`, `dga_to_c2`, or `ddos_smokescreen` |
| `constituent_alert_ids` | `List[str]` | List of `alert_id`s that make up this multi-stage incident |
| `severity_multiplier` | `float` | Risk escalation multiplier (e.g. `1.8x` for full kill-chain) |
| `narrative` | `str` | Detailed natural language synthesis explaining the intrusion progression |

---

## 3. Sample Alert Feed (`docs/sample_alert_feed.jsonl`)

A pre-generated sample feed capturing Alert and Incident objects is available at:
`docs/sample_alert_feed.jsonl`

This feed is an explicit demo fallback only. Normal dashboard operation is live mode:
start the dashboard and call `POST /api/runtime/start` with `{"pcap": "<path>"}` or
`{"interface": "<capture-interface>"}`. Set `DIODE_DASHBOARD_MODE=fixture` only when
deliberately replaying the curated fallback.

### Parsing Example in Python:
```python
import json
from schemas.alert_record import Alert
from schemas.incident_record import IncidentRecord

with open("docs/sample_alert_feed.jsonl", "r", encoding="utf-8") as f:
    for line in f:
        item = json.loads(line)
        if item["type"] == "ALERT":
            alert = Alert.model_validate(item["data"])
            print(f"[ALERT] {alert.threat_class.value} on {alert.flow_identifier}")
        elif item["type"] == "INCIDENT":
            incident = IncidentRecord.model_validate(item["data"])
            print(f"[INCIDENT] {incident.title} (Severity: {incident.severity_multiplier}x)")
```

---

## 4. Live Dashboard Telemetry Endpoints

### 4.1 Zero-Egress Diode Compliance Badge
- **Module**: `ingestion/diode_compliance.py`
- **Telemetry File**: `diode_compliance_status.json` (emitted in working directory during pipeline runs)
- **Status Object Properties**:
  ```python
  from ingestion.diode_compliance import DiodeComplianceWatchdog

  # Direct in-memory access or parse diode_compliance_status.json
  status = watchdog.get_status()
  print(status.is_compliant)            # bool: True / False
  print(status.egress_bytes_sent)       # int: Strictly 0
  print(status.process_socket_table)    # str: "CLEAN" or "VIOLATION_DETECTED"
  print(status.nic_io_counter)          # str: "CLEAN" or "RAW_EGRESS_DETECTED"
  ```
- **UI Element**: Display a green badge with "Zero Egress (Verified 0 Bytes)" when `is_compliant == True`.

### 4.2 Throughput & Latency Chart
- **Module**: `benchmark/throughput_bench.py`
- **Output JSON**: `benchmark/benchmark_results.json`
- **Key Metrics**:
  - `packet_rate_pps`: Measured prototype packet rate from the benchmark artifact
  - `flow_rate_fps`: Measured prototype flow rate from the benchmark artifact
  - `p50_latency_ms`: Median processing latency ($< 1.5\text{ ms}$)
  - `p95_latency_ms`: 95th percentile latency ($< 2.5\text{ ms}$)
  - `p99_latency_ms`: 99th percentile tail latency ($< 8.0\text{ ms} \ll 2{,}000\text{ ms}$ SLA)

---

## 5. Live Pipeline Invocation Guide

### 5.1 Real-Time Live Interface Sniffing (Rx-Only)
```bash
python run_pipeline.py --interface eth0 --output live_flows.jsonl --alerts-output live_alerts.jsonl
```

### 5.2 Deterministic PCAP Replay
```bash
python run_pipeline.py --pcap data_generation/pcaps/attack_portscan.pcap --output flows.jsonl --alerts-output alerts.jsonl --replay-speed 1.0
```
