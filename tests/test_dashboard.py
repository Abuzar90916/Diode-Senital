import pytest
from fastapi.testclient import TestClient
import dashboard.server

@pytest.fixture
def client():
    return TestClient(dashboard.server.app)

def test_dashboard_index_serves_html(client):
    res = client.get("/")
    assert res.status_code == 200
    assert "DIODE-SENTINEL" in res.text
    assert "HARDWARE DIODE: RX-ONLY" in res.text

def test_telemetry_endpoint_uses_honest_measured_metrics(client):
    res = client.get("/api/telemetry")
    assert res.status_code == 200
    data = res.json()
    # Verified benchmark numbers across both profiles
    assert data["engine_pps"] == 3105
    assert data["sustained_streaming_pps"] == 1198
    assert data["p99_latency_ms"] == 1.389
    assert data["p99_stress_latency_ms"] == 3.161
    assert data["sla_target_ms"] == 2000.0
    assert data["sla_headroom_multiplier"] == 1440
    assert data["egress_bytes_sent"] == 0
    assert data["diode_mode"] == "HARDWARE_RX_ONLY"
    assert "4 / 4" in data["watchdog_tests_passed"]

def test_validation_endpoint_contains_ctu13_census(client):
    res = client.get("/api/validation")
    assert res.status_code == 200
    data = res.json()
    # Verified holdout census numbers
    assert data["dataset_evaluated"]["total_evaluated_flows"] == 870
    assert data["headline_metrics"]["real_world_recall_pct"] == 48.92
    assert data["headline_metrics"]["real_world_fpr_pct"] == 18.92
    assert data["headline_metrics"]["alert_census_accounting_pct"] == 99.84
    # Verified per-detector holdout breakdown (flow-level and window-level)
    assert "per_detector_holdout_breakdown" in data
    # PortScan: 124 flows TP / 1 flow FP / 533 windows TP
    assert data["per_detector_holdout_breakdown"]["PortScanDetector"]["flow_tp"] == 124
    assert data["per_detector_holdout_breakdown"]["PortScanDetector"]["flow_fp"] == 1
    assert data["per_detector_holdout_breakdown"]["PortScanDetector"]["tp_alerts"] == 533
    # DGADNS: 6 flows TP / 0 flows FP / 48 windows TP
    assert data["per_detector_holdout_breakdown"]["DGADNSDetector"]["flow_tp"] == 6
    assert data["per_detector_holdout_breakdown"]["DGADNSDetector"]["flow_fp"] == 0
    assert data["per_detector_holdout_breakdown"]["DGADNSDetector"]["fp_alerts"] == 0
    # C2Beacon: 130 flows TP / 87 flows FP / 289 windows TP
    assert data["per_detector_holdout_breakdown"]["C2BeaconDetector"]["flow_tp"] == 130
    assert data["per_detector_holdout_breakdown"]["C2BeaconDetector"]["flow_fp"] == 87
    assert data["per_detector_holdout_breakdown"]["C2BeaconDetector"]["tp_alerts"] == 289
    # Exfiltration: 12 flows TP / 0 flows FP / 55 windows TP
    assert data["per_detector_holdout_breakdown"]["ExfiltrationDetector"]["flow_tp"] == 12
    assert data["per_detector_holdout_breakdown"]["ExfiltrationDetector"]["flow_fp"] == 0
    assert data["per_detector_holdout_breakdown"]["ExfiltrationDetector"]["window_tp"] == 55
    # System Aggregate: 182 flows TP / 88 flows FP
    assert data["per_detector_holdout_breakdown"]["SystemAggregate"]["flow_tp"] == 182
    assert data["per_detector_holdout_breakdown"]["SystemAggregate"]["flow_fp"] == 88
    # Verified 4/4 Watchdog assurance
    assert data["hardware_diode_assurance"]["total_watchdog_tests"] == "4 / 4 PASSED"
    # Verified IOC disclosure
    assert "nucleardiscover_com" in data["ioc_forensics"]
    assert "mail7_digitalwaves_co_nz" in data["ioc_forensics"]
    assert "spam-module outbound" in data["ioc_forensics"]["mail7_digitalwaves_co_nz"]["status"]

def test_replay_control_api(client):
    # Set speed 5x
    res = client.post("/api/replay/control", json={"action": "set_speed", "speed": 5.0})
    assert res.status_code == 200
    assert res.json()["speed"] == 5.0

    # Pause
    res = client.post("/api/replay/control", json={"action": "pause"})
    assert res.status_code == 200
    assert res.json()["is_playing"] is False

    # Play
    res = client.post("/api/replay/control", json={"action": "play"})
    assert res.status_code == 200
    assert res.json()["is_playing"] is True

    # Reset
    res = client.post("/api/replay/control", json={"action": "reset"})
    assert res.status_code == 200
    assert res.json()["current_index"] == 0

def test_compliance_audit_api(client):
    res = client.get("/api/compliance/audit")
    assert res.status_code == 200
    data = res.json()
    assert "NTRO-DIODE-CERT-" in data["certificate_id"]
    assert data["architecture_mandate"] == "NTRO PS ID26145 / Zero-Egress Passive Diode"
    assert data["diode_mode"] == "PHYSICAL_UNIDIRECTIONAL_ENFORCED"
    assert data["compliance_status"] == "COMPLIANT"
    assert data["total_egress_bytes_detected"] == 0
    assert len(data["cryptographic_integrity_sha256"]) == 64


def test_compliance_reset_api(client):
    res = client.post("/api/compliance/reset")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
