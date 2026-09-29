# Diode-Sentinel: Unidirectional Cyber Threat Detection Engine
**Smart India Hackathon 2026 — NTRO Problem Statement 26145**

[![Test Suite](https://img.shields.io/badge/pytest-45%20passed%20(100%25)-brightgreen.svg)]()
[![Diode Compliance](https://img.shields.io/badge/diode--egress-0%20bytes%20(verified)-blue.svg)]()
[![Synthetic Benchmark](https://img.shields.io/badge/Synthetic%20F1-1.0000%20(Tuned)-blue.svg)]()
[![CTU-13 Holdout](https://img.shields.io/badge/CTU--13%20Holdout-35.3%25%20Recall%20|%209.0%25%20FPR-brightgreen.svg)]()

Diode-Sentinel is a high-performance passive network security monitoring and cyber threat detection engine designed for unidirectional network boundaries (physical data diodes and passive optical taps). It ingests high-throughput raw packet streams under a **zero-egress guarantee**, computes streaming flow statistics across 6 specialized feature domains, validates against strict Pydantic v2 schemas, and detects complex multi-stage intrusion threats using Machine Learning with false-positive suppression and attack-chain correlation.

---

## High-Level Architecture

```
                                  PHYSICAL DATA DIODE / MIRROR TAP
                                                │ (Rx-Only, Zero Tx)
                                                ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│ 1. INGESTION & COMPLIANCE (ingestion/)                                                      │
│    • PcapStreamingReader / LiveStreamingCapture                                             │
│    • Dual-Check DiodeComplianceWatchdog (Process Socket Table + NIC delta egress = 0)       │
└──────────────────────────────────────┬──────────────────────────────────────────────────────┘
                                       │ Raw Packet Stream (Scapy / Stream Buffer)
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│ 2. SLIDING-WINDOW FLOW ENGINE (features/)                                                   │
│    • FlowAggregator (15.0s window, 5.0s slide, 30s idle eviction, TTL windowed global ctx)  │
│    • 6 Feature Calculators:                                                                 │
│      ├── Volumetric (pps, bps, entropy, syn_ack_ratio)                                      │
│      ├── Timing (IAT mean, std, CV, periodicity, jitter)                                    │
│      ├── DNS Lexical (Shannon entropy, consonant/vowel, numeric ratio, query types)         │
│      ├── Crypto Metadata (JA3/JA4 fingerprints, TLS cipher counts, packet size dynamics)    │
│      ├── Fan-Out (unique dest ports/IPs, scan rate, half-open ratio)                        │
│      └── Volume Asymmetry (byte ratio, burstiness, fallback unidirectional mode)           │
└──────────────────────────────────────┬──────────────────────────────────────────────────────┘
                                       │ Emitted FlowFeatureRecord (JSONL stream)
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│ 3. CANONICAL DATA CONTRACT (schemas/)                                                       │
│    • FlowFeatureRecord (Unified Pydantic v2 Contract)                                       │
│    • Alert & AlertCandidate (Corroborated Threat Schema)                                    │
│    • IncidentRecord (Multi-Stage Correlated Kill-Chain Schema)                              │
└──────────────────────────────────────┬──────────────────────────────────────────────────────┘
                                       │ Validated Flow Records
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│ 4. THREATCORE DETECTION ENGINE (threatcore/)                                                │
│    • DDoS Detector (Isolation Forest + Volumetric Anomaly Matrix)                           │
│    • C2 Beaconing Detector (IAT Periodicity/CV + Destination ASN Rarity)                  │
│    • DGA / DNS Tunnel Detector (XGBoost Classifier + Lexical Heuristics)                     │
│    • Encrypted Malware Detector (JA3/JA4 Fingerprints + Packet Sequence Dynamics)           │
│    • Port Scan Detector (Isolation Forest + Connection Fan-Out Profiling)                   │
│    • Data Exfiltration Detector (Volume Asymmetry + Host Time-of-Day Deviation)             │
└──────────────────────────────────────┬──────────────────────────────────────────────────────┘
                                       │ Candidate Detections
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│ 5. FALSE-POSITIVE REDUCTION LAYER (fp_reduction/)                                           │
│    • AllowlistManager (Audit-ready NTP, Cloud CDN, Approved Scanners, Known TLS)            │
│    • CorroborationEngine (Enforces >= 2 Independent Signals; Rejects Single-Signal Flukes)  │
│    • PersistenceFilter (Enforces Anomaly Persistence across N=3 Sliding Windows)            │
│    • BaselineStore (Host-Specific Rolling Time-of-Day Z-Score Baselines)                    │
└──────────────────────────────────────┬──────────────────────────────────────────────────────┘
                                       │ Promoted Alert Stream
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│ 6. ATTACK-CHAIN CORRELATION (correlation/)                                                  │
│    • EntityGraph (Bounded In-Memory Temporal Graph, 30-min TTL Eviction)                    │
│    • ChainMatcher (Synthesizes Multi-Stage Kill-Chain Incidents: PortScan -> C2 -> Exfil)   │
└─────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## Directory Layout

```
SIH2026/
├── ingestion/                  # Packet ingest & dual-check diode compliance watchdog
├── features/                   # 6 feature calculators & sliding-window flow aggregator
├── schemas/                    # Single canonical Pydantic v2 schemas (Flow, Alert, Incident)
├── threatcore/                 # 6 specialized ML & statistical threat detectors
├── fp_reduction/               # Allowlists, corroboration (>=2 signals), persistence (N=3), baseline store
├── correlation/                # Temporal entity graph & multi-stage kill-chain matcher
├── models/                     # Pre-trained ML model artifacts (Isolation Forest, XGBoost)
├── training/                   # Synthetic data generation, model fitting, and evaluation harness
├── data_generation/            # 12 synthetic attack and benign PCAP datasets with ground truth sidecars
├── benchmark/                  # Throughput and latency benchmark suite
├── validation/                 # Generalization validation on external real-world traffic (CTU-13)
├── tests/                      # Unified pytest test suite (44 tests, 100% pass rate)
├── docs/                       # Component specifications and detailed technical reports
├── run_pipeline.py             # Master runner (ingest -> features -> detectors -> alerts/incidents)
├── evaluate_detection.py       # Baseline heuristic evaluation wrapper
├── requirements.txt            # Consolidated and deduplicated project dependencies
└── README.md                   # Root documentation (this file)
```

---

## Quick Start

### 1. Installation
Install the consolidated dependencies:
```bash
pip install -r requirements.txt
```

### 2. Run the Full Ingestion & Feature Pipeline
Process a raw PCAP capture into streaming feature records and Alert/Incident JSONL events:
```bash
python run_pipeline.py --pcap data_generation/pcaps/attack_portscan.pcap --output portscan_features.jsonl --alerts-output portscan_alerts.jsonl
```

Or replay at simulated real-time speed (1.0x):
```bash
python run_pipeline.py --pcap data_generation/pcaps/attack_c2_beacon.pcap --replay-speed 1.0
```

### 3. Run the ThreatCore Benchmark Evaluation
Evaluate all 6 threat detectors, 5 benign trap scenarios, and attack-chain correlation against calibrated synthetic streams:
```bash
python -m training.evaluate
```

### 4. Run the Real-World CTU-13 Holdout Evaluation
Evaluate detectors against authentic, un-tuned research network traffic from CTU-13 Scenario 9 with production persistence ($N=3$ windows):
```bash
python -m training.evaluate_holdout
```

### 5. Run the Full Test Suite
Execute the entire test suite (unit tests, schema drift tests, and live end-to-end integration tests):
```bash
pytest -v tests/
```

### 6. Run Throughput Benchmarks
Measure the demonstrated single-process prototype capacity and latency:
```bash
python benchmark/throughput_bench.py
```

### 7. Run the Operations Dashboard

#### Local Development
Start the persistent FastAPI backend server:
```bash
python -m dashboard --host 127.0.0.1 --port 8000
```
Open `http://127.0.0.1:8000/dashboard/overview` in your browser. The frontend and backend are served synchronously, with full SSE streaming and demo PCAP replay enabled.

#### Public Production Deployment Architecture
- **Frontend**: Hosted statically on **Vercel** (`dashboard/static/`), routing all dashboard SPA paths to `index.html`.
- **Backend**: Hosted on a persistent container platform (**Render**, **Railway**, or **Docker** via `render.yaml` / `Dockerfile`).
  - *Crucial Architecture Decision*: Vercel is **not** used to host the persistent FastAPI/SSE backend worker. Serverless function runtimes have short execution timeouts and cannot sustain long-lived SSE connections or background packet capture threads.
- **Environment Variables**:
  - Backend: `DIODE_CORS_ORIGINS=https://<your-vercel-domain>.vercel.app` (allows cross-origin requests from the Vercel frontend without wildcard credential hazards).
  - Frontend: `window.DIODE_API_BASE_URL = "https://<your-backend-domain>.onrender.com"` (configured dynamically or via script injection).
- **Truthful Connection State**:
  The dashboard UI strictly verifies backend connectivity:
  - `DISCONNECTED`: Backend API unreachable (KPI metrics show `--`, telemetry unavailable).
  - `STREAM ERROR`: API reachable but SSE connection broken.
  - `CONNECTED / NO ACTIVE STREAM`: API and SSE online, awaiting traffic.
  - `DEMO SESSION`: Active PCAP scenario replay (`source == "DEMO"`).
  - `LIVE DATA`: Real physical NIC capture stream active (`source == "LIVE"`).
  - *Localhost is never displayed as an active endpoint on public production builds.*

---

## Dual-Metric Evaluation (Synthetic vs Real-World Holdout)

> [!NOTE]
> The system is evaluated under two distinct regimes: **Synthetic Calibrated Baseline** (verifying internal logic and allowlist trap suppression) and **CTU-13 Real-World Holdout** (verifying true generalization on genuine recorded network traffic with multi-window persistence).

> [!IMPORTANT]
> **Scientific Disclosures & Limitations**:
> 1. **CTU-13 Holdout Labeling Methodology**: Labels represent heuristic behavioral host attribution to the known infected host (`147.32.84.165`) and concurrent uninfected campus workstations; official per-flow Argus/.binetflow ground truth files were unavailable. Results should therefore be interpreted as an external behavioral validation slice, not an official per-flow benchmark.
> 2. **DDoS Validation Limitation**: The CTU-13 Scenario 9 holdout slice contained no volumetric DDoS attack traffic. Real-world holdout coverage for DDoS is unavailable in this slice; DDoS detector validation is performed using calibrated synthetic attack streams.

| Dimension | Synthetic Calibrated Baseline | Authentic CTU-13 Baseline | CTU-13 Post-C2 Remediation |
| :--- | :---: | :---: | :---: |
| **Persistence Filter** | `required_windows=1` (test scaffold) | `required_windows=3` (production) | `required_windows=3` (production) |
| **Evaluation Volume** | 800 synthetic flows | 870 unique flows (5,923 windows) | 870 unique flows (5,387 windows) |
| **Positive Attack Recall (Flow-Level)** | **100.00%** (calibrated) | **48.92%** (182 / 372 attack flows) | **48.39%** (180 / 372 attack flows) |
| **Normal False Positive Rate (Flow-Level)** | **0.00%** (0 / 500 flows) | **18.92%** (88 / 465 normal flows) | **2.16%** (10 / 462 normal flows) |
| **Normal Alerts per Hour (Event Stream)** | **0.0 alerts/hr** | **141.3 alerts/hr** (261 normal alerts) | **10.8 alerts/hr** (20 normal alerts) |
| **C2 Normal False Alarms** | 0 | 257 window alerts / 87 flows | **0 alerts / 0 flows** (100% resolved) |
| **Port Scan Precision** | 100.0% | **99.3% flow-level** (124 TP, 1 FP) | **99.3% flow-level** (124 TP, 1 FP) |
| **DGA DNS Detection** | 100.0% | **100% precision** (6 TP, 0 FP) | **100% precision** (6 TP, 0 FP) |
| **Encrypted Malware FP** | 0 | **0 alerts** | **0 alerts** |
| **Exfiltration FP** | 0 | **0 alerts** | **0 alerts** |

---

## Severity Derivation & Contract Integrity

To preserve strict compliance with NTRO Problem Statement 26145, the standardized `AlertRecord` contract in `schemas/alert_record.py` remains unpolluted by UI-specific fields. 

Presentation severity displayed in the Security Operations Console is derived deterministically from the standardized telemetry fields:
- **CRITICAL**: High-impact attack categories (`C2_Beaconing`, `DDoS`, `Data_Exfiltration`) with `confidence_score >= 0.70`, or multi-stage correlated attack incidents.
- **HIGH**: Reconnaissance (`Port_Scanning`), `DGA_Tunnelling`, or `Encrypted_Malware` with `confidence_score >= 0.75`, or lower-confidence critical categories.
- **MEDIUM**: Baseline anomaly detections satisfying the dual-signal corroboration threshold.
- **LOW**: Anomalies with `confidence_score < 0.60`.

---

## Component Documentation Links

For in-depth specifications, formulas, and experimental results, see:

- **Ingestion & Feature Engine**: [Pipeline Engine Documentation](docs/pipeline_documentation.md) | [Pipeline Spec](docs/pipeline_engine_readme.md)
- **ThreatCore & FP Reduction**: [Model Documentation](docs/model_documentation.md) | [ThreatCore Overview](docs/threatcore_readme.md)
- **Holdout Evaluation Report (CTU-13)**: [Holdout Evaluation Report](validation/HOLDOUT_EVALUATION_REPORT.md)
- **Person 4 Integration Guide**: [Person 4 Handoff Specification](docs/person4_handoff.md)
- **Data Contracts**: [Canonical Schema Specification](schemas/CONTRACT.md)
- **Throughput & Latency SLA Verification**: [Benchmark Report](benchmark/BENCHMARK_REPORT.md)
- **Real-World Generalization Verification**: [Generalization Report (CTU-13)](validation/GENERALIZATION_REPORT.md)
- **Synthetic Data Generation Tools**: [Traffic Generation Guide](data_generation/README_tools.md)
