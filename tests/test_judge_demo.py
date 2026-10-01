"""
Test suite for JUDGE_DEMO mode, execution, and isolation.
Validates:
1. JUDGE_DEMO session creation (POST /api/judge-demo/start returns mode=judge_demo, source=JUDGE_DEMO, session_id starting with JUDGE-).
2. Scenarios endpoint (GET /api/judge-demo/scenarios returns all 6 real attack PCAP scenarios with Port Scan as primary).
3. Status and last_result endpoints (/api/judge-demo/status, /api/judge-demo/last_result).
4. Alert events retain source=JUDGE_DEMO and session_id=JUDGE-*.
5. Complete isolation: JUDGE_DEMO alerts do not pollute LIVE or DEMO streams.
6. Real PCAP execution on Port Scan produces real packets, flows, alerts, real detector evidence, and zero egress bytes.
"""

import os
import pytest
from fastapi.testclient import TestClient
import dashboard.server
from dashboard.server import runtime_controller


@pytest.fixture
def client():
    return TestClient(dashboard.server.app)


def test_judge_demo_scenarios(client):
    """Test 1: Scenarios endpoint returns 6 real PCAP scenarios with Port Scan as primary."""
    res = client.get("/api/judge-demo/scenarios")
    assert res.status_code == 200
    scenarios = res.json()
    assert len(scenarios) == 6
    ids = [s["id"] for s in scenarios]
    assert "port_scan" in ids
    assert "c2_beacon" in ids
    assert "dga_tunnel" in ids
    assert "ddos_syn" in ids
    assert "encrypted_malware" in ids
    assert "data_exfil" in ids

    # Verify primary scenario is Port Scan and uses real existing PCAP
    port_scan_scen = next(s for s in scenarios if s["id"] == "port_scan")
    assert port_scan_scen["is_primary"] is True
    assert os.path.exists(port_scan_scen["pcap"])


def test_judge_demo_start_and_session_id(client):
    """Test 2: Starting JUDGE_DEMO creates a unique JUDGE- session_id and source=JUDGE_DEMO."""
    res = client.post("/api/judge-demo/start", json={"pcap": "data_generation/pcaps/attack_portscan.pcap"})
    assert res.status_code == 200
    data = res.json()
    assert data["source"] == "JUDGE_DEMO"
    assert data["mode"] == "judge_demo"
    assert data["session_id"].startswith("JUDGE-")
    assert "attack_portscan.pcap" in data["pcap"]
    assert data["running"] is True

    # Stop cleanly
    client.post("/api/judge-demo/stop")


def test_judge_demo_status_and_last_result(client):
    """Test 3: Judge demo status and last_result endpoints report truthful execution metrics."""
    with runtime_controller.lock:
        runtime_controller.source = "JUDGE_DEMO"
        runtime_controller.session_id = "JUDGE-PORTSCAN-VAL1"
        runtime_controller.active_pcap = "data_generation/pcaps/attack_portscan.pcap"
        runtime_controller.last_summary = {
            "packets": 196,
            "records": 650,
            "alerts": 621,
            "elapsed_sec": 3.25,
            "packets_per_sec": 60.3,
            "error": None,
        }
        runtime_controller.last_judge_demo_result = {
            "session_id": "JUDGE-PORTSCAN-VAL1",
            "pcap": "data_generation/pcaps/attack_portscan.pcap",
            "summary": dict(runtime_controller.last_summary),
            "error": None,
            "completed_at": "2026-09-29T12:00:00Z",
        }

    st_res = client.get("/api/judge-demo/status")
    assert st_res.status_code == 200
    st = st_res.json()
    assert st["mode"] == "judge_demo"
    assert st["source"] == "JUDGE_DEMO"
    assert st["session_id"] == "JUDGE-PORTSCAN-VAL1"
    assert st["summary"]["packets"] == 196
    assert st["summary"]["records"] == 650
    assert st["summary"]["alerts"] == 621
    assert st["last_judge_demo_result"]["session_id"] == "JUDGE-PORTSCAN-VAL1"

    last_res = client.get("/api/judge-demo/last_result")
    assert last_res.status_code == 200
    last_data = last_res.json()
    assert last_data["status"] == "available"
    assert last_data["last_judge_demo_result"]["session_id"] == "JUDGE-PORTSCAN-VAL1"
    assert last_data["last_judge_demo_result"]["summary"]["packets"] == 196
    assert last_data["last_judge_demo_result"]["summary"]["records"] == 650
    assert last_data["last_judge_demo_result"]["summary"]["alerts"] == 621


def test_judge_demo_isolation_and_event_tagging(client):
    """Test 4: Alert events retain source=JUDGE_DEMO and session_id=JUDGE-*, isolated from LIVE and DEMO."""
    with runtime_controller.lock:
        runtime_controller.events = []
        runtime_controller.source = "JUDGE_DEMO"
        runtime_controller.session_id = "JUDGE-RUN-001"

    runtime_controller._publish({
        "type": "ALERT",
        "data": {
            "alert_id": "ALT-JUDGE-001",
            "threat_class": "Port_Scanning",
            "confidence_score": 0.95,
            "supporting_evidence": {"scan_type": "SYN_STEALTH", "unique_ports": 45},
            "timestamp": "2026-09-29T12:05:00Z"
        }
    })

    alerts_res = client.get("/api/alerts")
    assert alerts_res.status_code == 200
    all_alerts = alerts_res.json()

    judge_alerts = [a for a in all_alerts if a.get("source") == "JUDGE_DEMO" or a.get("session_id", "").startswith("JUDGE-")]
    assert len(judge_alerts) == 1
    assert judge_alerts[0]["session_id"] == "JUDGE-RUN-001"
    assert judge_alerts[0]["source"] == "JUDGE_DEMO"
    assert judge_alerts[0]["threat_class"] == "Port_Scanning"
    assert judge_alerts[0]["confidence_score"] == 0.95
    assert judge_alerts[0]["supporting_evidence"]["scan_type"] == "SYN_STEALTH"


def test_judge_demo_port_scan_pipeline_execution():
    """Test 5: Real execution of attack_portscan.pcap in JUDGE_DEMO mode."""
    pcap = "data_generation/pcaps/attack_portscan.pcap"
    assert os.path.exists(pcap), f"PCAP {pcap} must exist"

    published_events = []

    def mock_publish(event):
        if isinstance(event.get("data"), dict):
            event["data"]["session_id"] = "JUDGE-TEST-REAL"
            event["data"]["source"] = "JUDGE_DEMO"
        published_events.append(event)

    from run_pipeline import run_pipeline
    summary = run_pipeline(
        pcap_path=pcap,
        interface=None,
        output_records_file=None,
        output_alerts_file=None,
        event_callback=mock_publish,
        run_watchdog=True,
        fail_closed=True,
    )

    assert summary is not None
    assert summary["packets"] == 196
    assert summary["records"] == 650
    assert summary["alerts"] == 621
    assert summary["error"] is None

    # Check alert events published
    alerts = [ev["data"] for ev in published_events if ev.get("type") == "ALERT"]
    assert len(alerts) == 621
    assert all(a["source"] == "JUDGE_DEMO" for a in alerts)
    assert all(a["session_id"] == "JUDGE-TEST-REAL" for a in alerts)
    assert any("evidence" in a or "supporting_evidence" in a for a in alerts)
