# Diode Sentinel — ThreatCore, FP-Reduction & Correlation Engine (Person 3)

Backend module for **Diode Sentinel** — a passive threat intelligence monitoring system for SIH 2026 (NTRO Problem Statement 26145 on unidirectional/data-diode network monitoring).

## Key Components

- **Data Contracts (`schemas/`)**: Strict Pydantic v2 schemas (`FlowFeatureRecord`, `Alert`, `AlertCandidate`, `IncidentRecord`).
- **False-Positive Reduction (`fp_reduction/`)**:
  - `baseline_store.py`: Rolling per-host feature statistics and time-of-day host baselines.
  - `corroboration.py`: Central engine enforcing a minimum of 2 independent corroborating signals per candidate. Single-signal candidates are rejected.
  - `persistence_filter.py`: Requires anomaly candidates to persist across $N=3$ consecutive sliding windows before promoting to `Alert`.
  - `allowlists.py`: Audit-ready allowlists for periodic services (NTP/cloud updates), benign TLS fingerprints, scanner IPs, and top domains.
- **ThreatCore Detectors (`threatcore/`)**:
  - `ddos_detector.py`: Isolation Forest + threshold matrix on volumetric rate & source IP entropy.
  - `c2_beacon_detector.py`: IAT periodicity/CV heuristics with destination ASN rarity corroboration.
  - `dga_dns_detector.py`: XGBoost classifier + character entropy/lexical ratios + DNS tunnelling record-type heuristics.
  - `encrypted_malware_detector.py`: JA3/JA4 TLS fingerprinting + packet sequence dynamics.
  - `portscan_detector.py`: Isolation Forest + fan-out metric analysis.
  - `exfiltration_detector.py`: Volume asymmetry + host time-of-day baseline deviation.
- **Attack-Chain Correlation (`correlation/`)**:
  - `entity_graph.py`: Bounded in-memory graph tracking host/IP entity relations with rolling 30-min TTL window.
  - `chain_matcher.py`: Matches 3 multi-stage attack patterns (`recon_to_c2_to_exfil`, `dga_to_c2`, `ddos_smokescreen`), emitting `IncidentRecord` objects with calculated severity multipliers and natural language narratives.
- **Training & Evaluation (`training/`)**:
  - `synthetic_data.py`: Generator producing clean and malicious traffic flow records.
  - `train_classifiers.py`: Fits and serializes scikit-learn Isolation Forest and XGBoost model artifacts to `models/`.
  - `evaluate.py`: Evaluates full engine pipeline and prints Precision, Recall, F1, and False-Positive rate per hour.
- **Documentation & Tests (`docs/` & `tests/`)**:
  - `docs/model_documentation.md`: Detailed documentation for all 6 detectors.
  - `tests/`: Pytest suite with 100% test pass rate.

## Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Train Models
```bash
python -m training.train_classifiers
```

### 3. Run Benchmark Evaluation (Synthetic Calibrated Baseline)
```bash
python -m training.evaluate
```

### 4. Run Real-World Holdout Evaluation (CTU-13 Authentic Traffic)
Runs full pipeline with production persistence ($N=3$ consecutive sliding windows) against authentic CTU-13 Scenario 9 botnet and normal background traffic:
```bash
python -m training.evaluate_holdout
```
See formal report at [`validation/HOLDOUT_EVALUATION_REPORT.md`](../validation/HOLDOUT_EVALUATION_REPORT.md).

### 5. Run Pytest Suite
```bash
pytest -v tests/
```
