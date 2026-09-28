"""
Live End-to-End Pipeline-to-ThreatCore Integration Test.
SIH 2026 Problem Statement 26145 (NTRO).

Proves that:
1. Person 2's real ingestion pipeline (run_pipeline.py) runs on real PCAPs
2. Emits valid streaming FlowFeatureRecord JSONL
3. Feeds directly into Person 3's ThreatCore detection & FP reduction engines
4. Produces correctly-shaped Alert records with proper ThreatClass values
5. Validates benign traffic passes through with 0 false alerts.
"""

import os
import sys
import tempfile
import pytest
from pathlib import Path

# Ensure repo root is in sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from run_pipeline import run_pipeline
from schemas.flow_feature_record import FlowFeatureRecord
from schemas.alert_record import Alert, ThreatClass
from fp_reduction.allowlists import AllowlistManager
from fp_reduction.baseline_store import BaselineStore
from fp_reduction.corroboration import CorroborationEngine
from fp_reduction.persistence_filter import PersistenceFilter
from threatcore.portscan_detector import PortScanDetector
from threatcore.c2_beacon_detector import C2BeaconDetector
from threatcore.dga_dns_detector import DGADNSDetector


def _run_pipeline_and_collect_records(pcap_filename: str) -> list[FlowFeatureRecord]:
    pcap_path = REPO_ROOT / "data_generation" / "pcaps" / pcap_filename
    assert pcap_path.exists(), f"PCAP not found: {pcap_path}"

    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as tf:
        out_jsonl = tf.name

    try:
        # 1. Run live ingestion pipeline (Person 2)
        run_pipeline(pcap_path=str(pcap_path), output_records_file=out_jsonl, run_watchdog=False)
        assert os.path.exists(out_jsonl), "Pipeline did not produce output JSONL"

        records: list[FlowFeatureRecord] = []
        with open(out_jsonl, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                # 2. Strict canonical schema validation
                rec = FlowFeatureRecord.model_validate_json(line)
                records.append(rec)

        assert len(records) > 0, f"Zero records generated from {pcap_filename}"
        return records
    finally:
        if os.path.exists(out_jsonl):
            try:
                os.remove(out_jsonl)
            except OSError:
                pass


def test_live_e2e_portscan_attack():
    """Live E2E test on attack_portscan.pcap -> PortScanDetector -> Alert."""
    records = _run_pipeline_and_collect_records("attack_portscan.pcap")

    allowlists = AllowlistManager()
    baseline = BaselineStore()
    detector = PortScanDetector(allowlist_manager=allowlists)
    corroborator = CorroborationEngine(default_min_signals=2)
    persistence = PersistenceFilter(required_windows=1, min_window_interval_sec=0.0)

    alerts: list[Alert] = []
    for rec in records:
        cand = detector.detect(rec, baseline)
        if cand:
            passed, c_count, _ = corroborator.evaluate_candidate(cand)
            if passed:
                promoted, _, alert = persistence.process_candidate(cand, c_count)
                if promoted and alert:
                    alerts.append(alert)

    assert len(alerts) > 0, "No alerts generated for Port Scanning attack"
    first_alert = alerts[0]

    # Validate Alert contract
    assert isinstance(first_alert, Alert)
    assert first_alert.threat_class == ThreatClass.PORT_SCANNING
    assert first_alert.confidence_score > 0.0
    assert first_alert.alert_id.startswith("ALT-")
    assert first_alert.src_ip is not None
    assert first_alert.dst_ip is not None
    assert "fan-out" in first_alert.supporting_evidence.lower() or "scan" in first_alert.supporting_evidence.lower()


def test_live_e2e_c2_beacon_attack():
    """Live E2E test on attack_c2_beacon.pcap -> C2BeaconDetector -> Alert."""
    records = _run_pipeline_and_collect_records("attack_c2_beacon.pcap")

    allowlists = AllowlistManager()
    baseline = BaselineStore()
    detector = C2BeaconDetector(allowlist_manager=allowlists)
    corroborator = CorroborationEngine(default_min_signals=2)
    persistence = PersistenceFilter(required_windows=1, min_window_interval_sec=0.0)

    alerts: list[Alert] = []
    for rec in records:
        cand = detector.detect(rec, baseline)
        if cand:
            passed, c_count, _ = corroborator.evaluate_candidate(cand)
            if passed:
                promoted, _, alert = persistence.process_candidate(cand, c_count)
                if promoted and alert:
                    alerts.append(alert)

    assert len(alerts) > 0, "No alerts generated for C2 Beaconing attack"
    first_alert = alerts[0]

    # Validate Alert contract
    assert isinstance(first_alert, Alert)
    assert first_alert.threat_class == ThreatClass.C2_BEACONING
    assert first_alert.confidence_score > 0.0
    assert first_alert.alert_id.startswith("ALT-")
    assert "beacon" in first_alert.supporting_evidence.lower() or "iat" in first_alert.supporting_evidence.lower() or "periodicity" in first_alert.supporting_evidence.lower()


def test_live_e2e_dga_dns_attack():
    """Live E2E test on attack_dga.pcap -> DGADNSDetector -> Alert."""
    records = _run_pipeline_and_collect_records("attack_dga.pcap")

    allowlists = AllowlistManager()
    baseline = BaselineStore()
    detector = DGADNSDetector(allowlist_manager=allowlists)
    corroborator = CorroborationEngine(default_min_signals=2)
    persistence = PersistenceFilter(required_windows=1, min_window_interval_sec=0.0)

    alerts: list[Alert] = []
    for rec in records:
        cand = detector.detect(rec, baseline)
        if cand:
            passed, c_count, _ = corroborator.evaluate_candidate(cand)
            if passed:
                promoted, _, alert = persistence.process_candidate(cand, c_count)
                if promoted and alert:
                    alerts.append(alert)

    assert len(alerts) > 0, "No alerts generated for DGA DNS attack"
    first_alert = alerts[0]

    assert isinstance(first_alert, Alert)
    assert first_alert.threat_class == ThreatClass.DGA_TUNNELLING
    assert first_alert.confidence_score > 0.0
    assert first_alert.alert_id.startswith("ALT-")
    assert "dns" in first_alert.supporting_evidence.lower() or "entropy" in first_alert.supporting_evidence.lower()


def test_live_e2e_benign_traffic_suppression():
    """Live E2E test on benign traffic proving 0 false alerts."""
    # 1. Test benign periodic heartbeat traffic vs C2 Beacon detector
    hb_records = _run_pipeline_and_collect_records("benign_periodic_heartbeat.pcap")
    allowlists = AllowlistManager()
    baseline = BaselineStore()
    c2_detector = C2BeaconDetector(allowlist_manager=allowlists)
    corroborator = CorroborationEngine(default_min_signals=2)
    persistence = PersistenceFilter(required_windows=1, min_window_interval_sec=0.0)

    hb_alerts: list[Alert] = []
    for rec in hb_records:
        cand = c2_detector.detect(rec, baseline)
        if cand:
            passed, c_count, _ = corroborator.evaluate_candidate(cand)
            if passed:
                promoted, _, alert = persistence.process_candidate(cand, c_count)
                if promoted and alert:
                    hb_alerts.append(alert)

    assert len(hb_alerts) == 0, f"Benign heartbeat triggered false C2 alerts: {hb_alerts}"

    # 2. Test benign vulnerability scanner vs Port Scan detector
    scan_records = _run_pipeline_and_collect_records("benign_vulnerability_scanner.pcap")
    portscan_detector = PortScanDetector(allowlist_manager=allowlists)

    scan_alerts: list[Alert] = []
    for rec in scan_records:
        cand = portscan_detector.detect(rec, baseline)
        if cand:
            passed, c_count, _ = corroborator.evaluate_candidate(cand)
            if passed:
                promoted, _, alert = persistence.process_candidate(cand, c_count)
                if promoted and alert:
                    scan_alerts.append(alert)

    assert len(scan_alerts) == 0, f"Benign scanner triggered false PortScan alerts: {scan_alerts}"
