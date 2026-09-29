"""
Regression test suite for Demo Testing execution, result retention, and isolation.
Validates:
A. Starting a DEMO session creates DEMO session_id.
B. Completion preserves a completed result.
C. Runtime may return to idle without destroying the last completed demo result.
D. Demo result contains actual: pcap, packets, flow records, alerts, elapsed time, session_id.
E. Demo events do not enter LIVE alert collections.
F. LIVE events do not enter DEMO result collections.
G. Starting a new demo replaces the previous completed demo result only when the new demo actually starts.
"""

import pytest
from fastapi.testclient import TestClient
import dashboard.server
from dashboard.server import runtime_controller


@pytest.fixture
def client():
    return TestClient(dashboard.server.app)


def test_starting_demo_creates_demo_session_id(client):
    """Test A: Starting a DEMO session creates a unique DEMO session_id."""
    res = client.post("/api/runtime/start", json={"pcap": "data_generation/pcaps/attack_c2_beacon.pcap"})
    assert res.status_code == 200
    data = res.json()
    assert data["source"] == "DEMO"
    assert data["session_id"].startswith("DEMO-")
    assert "attack_c2_beacon.pcap" in data["active_pcap"]
    assert data["pcap"] == data["active_pcap"]

    # Stop runtime cleanly
    client.post("/api/runtime/stop")


def test_completion_preserves_completed_result_and_metrics(client):
    """Tests B, C, D: Completion preserves last completed demo result even when idle."""
    with runtime_controller.lock:
        runtime_controller.source = "DEMO"
        runtime_controller.session_id = "DEMO-DDOS-VAL1"
        runtime_controller.active_pcap = "data_generation/pcaps/attack_ddos_syn.pcap"
        runtime_controller.last_summary = {
            "packets": 1000,
            "records": 4665,
            "alerts": 4236,
            "elapsed_sec": 26.25,
            "packets_per_sec": 38.1,
            "error": None,
        }
        runtime_controller.last_demo_result = {
            "session_id": "DEMO-DDOS-VAL1",
            "pcap": "data_generation/pcaps/attack_ddos_syn.pcap",
            "summary": dict(runtime_controller.last_summary),
            "error": None,
            "completed_at": "2026-09-29T08:00:00Z",
        }
        runtime_controller.running = False
        runtime_controller.source = "IDLE"

    # Runtime is now IDLE, but status must preserve the last completed demo result
    res = client.get("/api/runtime/status")
    assert res.status_code == 200
    st = res.json()
    assert st["running"] is False
    assert st["session_id"] == "DEMO-DDOS-VAL1"
    assert "attack_ddos_syn.pcap" in st["active_pcap"]
    assert "attack_ddos_syn.pcap" in st["pcap"]
    assert st["summary"]["packets"] == 1000
    assert st["summary"]["records"] == 4665
    assert st["summary"]["alerts"] == 4236
    assert st["summary"]["elapsed_sec"] == 26.25
    assert st["last_demo_result"] is not None
    assert st["last_demo_result"]["session_id"] == "DEMO-DDOS-VAL1"

    # Dedicated /api/demo/last_result endpoint
    res_last = client.get("/api/demo/last_result")
    assert res_last.status_code == 200
    last_data = res_last.json()
    assert last_data["status"] == "available"
    assert last_data["last_demo_result"]["summary"]["packets"] == 1000
    assert last_data["last_demo_result"]["summary"]["records"] == 4665
    assert last_data["last_demo_result"]["summary"]["alerts"] == 4236


def test_demo_and_live_event_isolation(client):
    """Tests E, F: Demo events do not enter LIVE collections and LIVE runs do not overwrite DEMO results."""
    with runtime_controller.lock:
        runtime_controller.events = []
        runtime_controller.source = "DEMO"
        runtime_controller.session_id = "DEMO-ISOLATION-1"
        runtime_controller.last_demo_result = {
            "session_id": "DEMO-ISOLATION-1",
            "pcap": "attack_portscan.pcap",
            "summary": {"packets": 196, "records": 820, "alerts": 750, "elapsed_sec": 4.5},
            "error": None,
        }

    # Publish a DEMO event
    runtime_controller._publish({
        "type": "ALERT",
        "data": {
            "flow_id": "192.168.1.50:1234->10.0.0.1:80/TCP",
            "threat_class": "PORT_SCAN",
            "confidence": 0.95,
        }
    })

    # Switch to LIVE
    with runtime_controller.lock:
        runtime_controller.source = "LIVE"
        runtime_controller.session_id = "LIVE-ISOLATION-2"

    # Publish a LIVE event
    runtime_controller._publish({
        "type": "ALERT",
        "data": {
            "flow_id": "10.0.0.99:5555->10.0.0.1:443/TCP",
            "threat_class": "C2_BEACON",
            "confidence": 0.98,
        }
    })

    events = runtime_controller.snapshot()
    assert len(events) == 2

    demo_events = [e for e in events if e.get("data", {}).get("source") == "DEMO" or e.get("data", {}).get("session_id", "").startswith("DEMO-")]
    live_events = [e for e in events if e.get("data", {}).get("source") == "LIVE" or e.get("data", {}).get("session_id", "").startswith("LIVE-")]

    assert len(demo_events) == 1
    assert demo_events[0]["data"]["session_id"] == "DEMO-ISOLATION-1"
    assert len(live_events) == 1
    assert live_events[0]["data"]["session_id"] == "LIVE-ISOLATION-2"

    # Verify LIVE operation did not overwrite the completed DEMO result
    assert runtime_controller.last_demo_result["session_id"] == "DEMO-ISOLATION-1"
    assert runtime_controller.last_demo_result["summary"]["packets"] == 196


def test_starting_new_demo_replaces_previous_only_when_new_starts(client):
    """Test G: Starting a new demo replaces the previous completed demo result only when the new demo actually starts."""
    with runtime_controller.lock:
        runtime_controller.last_demo_result = {
            "session_id": "DEMO-OLD-1",
            "pcap": "attack_old.pcap",
            "summary": {"packets": 50, "records": 100, "alerts": 10, "elapsed_sec": 1.0},
            "error": None,
        }
        runtime_controller.running = False
        runtime_controller.source = "IDLE"

    # Prior to starting new demo, old result is preserved
    res_before = client.get("/api/demo/last_result")
    assert res_before.json()["last_demo_result"]["session_id"] == "DEMO-OLD-1"

    # Start new demo session
    res_start = client.post("/api/runtime/start", json={"pcap": "data_generation/pcaps/attack_dga.pcap"})
    assert res_start.status_code == 200
    new_sess = res_start.json()["session_id"]
    assert new_sess.startswith("DEMO-")
    assert new_sess != "DEMO-OLD-1"

    # Clean up
    client.post("/api/runtime/stop")
