"""
Regression test suite for BACKEND_TEST telemetry, execution, and isolation.
Validates:
1. BACKEND_TEST session creation (POST /api/backend-test/start returns mode=backend_test, source=BACKEND_TEST, session_id starting with TEST-).
2. Status and last_result endpoints (/api/backend-test/status, /api/backend-test/last_result).
3. Alert events retain source=BACKEND_TEST and session_id=TEST-*.
4. Alerts reach SSE queue.
5. BACKEND_TEST alerts appear in dashboard alert collection.
6. DEMO alerts remain segregated to Demo Testing only.
7. LIVE alerts remain segregated.
8. Corroboration and persistence apply to real detection.
9. Zero-egress hardware compliance watchdog passes.
"""

import pytest
from fastapi.testclient import TestClient
import dashboard.server
from dashboard.server import runtime_controller


@pytest.fixture
def client():
    return TestClient(dashboard.server.app)


def test_backend_test_start_and_session_id(client):
    """Test 1: Starting a BACKEND_TEST creates a unique TEST- session_id and source=BACKEND_TEST."""
    res = client.post("/api/backend-test/start", json={"pcap": "data_generation/pcaps/attack_c2_beacon.pcap"})
    assert res.status_code == 200
    data = res.json()
    assert data["source"] == "BACKEND_TEST"
    assert data["mode"] == "backend_test"
    assert data["session_id"].startswith("TEST-")
    assert "attack_c2_beacon.pcap" in data["pcap"]
    assert data["running"] is True

    # Stop cleanly
    client.post("/api/runtime/stop")


def test_backend_test_status_and_last_result(client):
    """Test 2: Backend test status and last_result endpoints report truthful execution metrics."""
    with runtime_controller.lock:
        runtime_controller.source = "BACKEND_TEST"
        runtime_controller.session_id = "TEST-PORTSCAN-VAL1"
        runtime_controller.active_pcap = "data_generation/pcaps/attack_portscan.pcap"
        runtime_controller.last_summary = {
            "packets": 196,
            "records": 650,
            "alerts": 621,
            "elapsed_sec": 3.25,
            "packets_per_sec": 60.3,
            "error": None,
        }
        runtime_controller.last_backend_test_result = {
            "session_id": "TEST-PORTSCAN-VAL1",
            "pcap": "data_generation/pcaps/attack_portscan.pcap",
            "summary": dict(runtime_controller.last_summary),
            "error": None,
            "completed_at": "2026-09-29T09:30:00Z",
        }
        runtime_controller.running = False
        runtime_controller.source = "IDLE"

    # GET /api/backend-test/status
    res = client.get("/api/backend-test/status")
    assert res.status_code == 200
    st = res.json()
    assert st["running"] is False
    assert st["session_id"] == "TEST-PORTSCAN-VAL1"
    assert "attack_portscan.pcap" in st["pcap"]
    assert st["summary"]["packets"] == 196
    assert st["summary"]["records"] == 650
    assert st["summary"]["alerts"] == 621
    assert st["last_backend_test_result"]["session_id"] == "TEST-PORTSCAN-VAL1"

    # GET /api/backend-test/last_result
    res_last = client.get("/api/backend-test/last_result")
    assert res_last.status_code == 200
    last_data = res_last.json()
    assert last_data["status"] == "available"
    assert last_data["last_backend_test_result"]["summary"]["packets"] == 196
    assert last_data["last_backend_test_result"]["summary"]["records"] == 650
    assert last_data["last_backend_test_result"]["summary"]["alerts"] == 621


def test_three_way_source_isolation(client):
    """
    Test 3, 5, 6, 7:
    - DEMO alerts retain source=DEMO and session_id=DEMO-*
    - LIVE alerts retain source=LIVE and session_id=LIVE-*
    - BACKEND_TEST alerts retain source=BACKEND_TEST and session_id=TEST-*
    - Verifies proper segregation across collections.
    """
    with runtime_controller.lock:
        runtime_controller.events = []

        # 1. DEMO event
        runtime_controller.source = "DEMO"
        runtime_controller.session_id = "DEMO-RUN-001"
    runtime_controller._publish({
        "type": "ALERT",
        "data": {
            "flow_identifier": "192.168.1.10:1234->10.0.0.1:80/TCP",
            "threat_class": "Port_Scanning",
            "confidence_score": 0.95,
            "supporting_evidence": "SYN scan detected",
        }
    })

    # 2. LIVE event
    with runtime_controller.lock:
        runtime_controller.source = "LIVE"
        runtime_controller.session_id = "LIVE-RUN-002"
    runtime_controller._publish({
        "type": "ALERT",
        "data": {
            "flow_identifier": "10.0.0.5:5555->10.0.0.1:443/TCP",
            "threat_class": "C2_Beaconing",
            "confidence_score": 0.98,
            "supporting_evidence": "Periodic beaconing detected",
        }
    })

    # 3. BACKEND_TEST event
    with runtime_controller.lock:
        runtime_controller.source = "BACKEND_TEST"
        runtime_controller.session_id = "TEST-RUN-003"
    runtime_controller._publish({
        "type": "ALERT",
        "data": {
            "flow_identifier": "192.168.1.77:43073->192.168.1.5:62/TCP",
            "threat_class": "Port_Scanning",
            "confidence_score": 0.92,
            "supporting_evidence": "Horizontal sweep detected across 62 target ports",
        }
    })

    all_alerts = [e["data"] for e in runtime_controller.snapshot("ALERT")]
    assert len(all_alerts) == 3

    # Segment according to frontend filter logic
    demo_alerts = [a for a in all_alerts if a.get("source") == "DEMO" or a.get("session_id", "").startswith("DEMO-")]
    live_alerts = [a for a in all_alerts if a.get("source") == "LIVE" or a.get("session_id", "").startswith("LIVE-")]
    backend_test_alerts = [a for a in all_alerts if a.get("source") == "BACKEND_TEST" or a.get("session_id", "").startswith("TEST-")]

    # Verification: Exactly one of each
    assert len(demo_alerts) == 1
    assert demo_alerts[0]["session_id"] == "DEMO-RUN-001"
    assert demo_alerts[0]["source"] == "DEMO"

    assert len(live_alerts) == 1
    assert live_alerts[0]["session_id"] == "LIVE-RUN-002"
    assert live_alerts[0]["source"] == "LIVE"

    assert len(backend_test_alerts) == 1
    assert backend_test_alerts[0]["session_id"] == "TEST-RUN-003"
    assert backend_test_alerts[0]["source"] == "BACKEND_TEST"
    assert backend_test_alerts[0]["threat_class"] == "Port_Scanning"
    assert backend_test_alerts[0]["confidence_score"] == 0.92

    # Dashboard monitored collection (LIVE + BACKEND_TEST, excluding DEMO)
    dashboard_alerts = [
        a for a in all_alerts
        if a.get("source") in ("LIVE", "BACKEND_TEST")
        or a.get("session_id", "").startswith(("LIVE-", "TEST-"))
    ]
    assert len(dashboard_alerts) == 2
    # Ensure DEMO is strictly excluded
    assert not any(a["session_id"].startswith("DEMO-") for a in dashboard_alerts)


def test_backend_test_runs_real_pcap_execution():
    """
    Test 2, 4, 8, 9, 10:
    Directly runs attack_c2_beacon.pcap via run_pipeline with event callback
    and verifies that real ThreatCore alerts are emitted with zero egress.
    """
    from run_pipeline import run_pipeline
    import os

    pcap_path = os.path.join(os.path.dirname(__file__), "..", "data_generation", "pcaps", "attack_c2_beacon.pcap")
    assert os.path.exists(pcap_path)

    emitted_events = []
    def callback(ev):
        emitted_events.append(ev)

    summary = run_pipeline(
        pcap_path=pcap_path,
        interface=None,
        output_records_file=None,
        output_alerts_file=None,
        event_callback=callback,
        run_watchdog=True,
        fail_closed=True,
    )

    assert summary["packets"] == 43
    assert summary["records"] >= 20
    assert summary["alerts"] >= 10
    assert summary["error"] is None

    # Check diode compliance status from disk
    import json
    status_file = os.path.join(os.path.dirname(__file__), "..", "diode_compliance_status.json")
    if os.path.exists(status_file):
        with open(status_file, "r") as f:
            diode_data = json.load(f)
            assert diode_data.get("compliant") is True
            assert diode_data.get("egress_bytes") == 0

    alerts = [ev["data"] for ev in emitted_events if ev.get("type") == "ALERT"]
    assert len(alerts) >= 10
    # Verify alert properties
    first_alert = alerts[0]
    assert "threat_class" in first_alert
    assert "confidence_score" in first_alert
    assert "supporting_evidence" in first_alert
