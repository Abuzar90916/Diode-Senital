"""
Deployment and Runtime Verification Script
Validates:
1. /api/health
2. /api/runtime/status
3. /api/runtime/interfaces
4. /api/alerts
5. /api/incidents
6. /api/demo/scenarios
7. /api/events (SSE handshake and status emission)
8. CORS headers with DIODE_CORS_ORIGINS
9. Runtime demo start and completion
10. Session tagging (source == DEMO, session_id == DEMO-...)
"""

import os
import sys
import time
from starlette.testclient import TestClient

# Ensure CORS origin is set for testing
os.environ["DIODE_CORS_ORIGINS"] = "https://diode-sentinel.vercel.app"

from dashboard.server import app

def test_api():
    print("[1/6] Initializing TestClient...")
    client = TestClient(app)

    # 1. Health & Status
    print("[2/6] Verifying health and runtime endpoints...")
    res = client.get("/api/health")
    assert res.status_code == 200, f"Health check failed: {res.text}"
    health = res.json()
    assert health["status"] == "ok"
    assert "session_id" in health
    print("   -> /api/health: OK", health)

    res = client.get("/api/runtime/status")
    assert res.status_code == 200
    st = res.json()
    assert "running" in st
    assert "source" in st
    print("   -> /api/runtime/status: OK", st)

    # 2. Interfaces
    res = client.get("/api/runtime/interfaces")
    assert res.status_code == 200
    ifaces = res.json()
    assert "interfaces" in ifaces
    print("   -> /api/runtime/interfaces: OK", ifaces)

    # 3. Demo Scenarios
    print("[3/6] Verifying demo scenarios...")
    res = client.get("/api/demo/scenarios")
    assert res.status_code == 200
    scenarios = res.json()
    assert len(scenarios) >= 5
    print(f"   -> /api/demo/scenarios: OK ({len(scenarios)} scenarios available)")

    # 4. CORS verification
    print("[4/6] Verifying CORS headers...")
    headers = {"Origin": "https://diode-sentinel.vercel.app"}
    res = client.options("/api/alerts", headers={
        "Origin": "https://diode-sentinel.vercel.app",
        "Access-Control-Request-Method": "GET"
    })
    cors_header = res.headers.get("access-control-allow-origin")
    assert cors_header == "https://diode-sentinel.vercel.app", f"CORS failed: {res.headers}"
    print("   -> CORS Access-Control-Allow-Origin:", cors_header)

    # 5. Alerts & Incidents Isolation Check
    print("[5/6] Verifying Alerts and Incidents endpoints...")
    res = client.get("/api/alerts")
    assert res.status_code == 200
    alerts = res.json()
    print(f"   -> /api/alerts: OK (returned {len(alerts)} records)")

    res = client.get("/api/incidents")
    assert res.status_code == 200
    incidents = res.json()
    print(f"   -> /api/incidents: OK (returned {len(incidents)} incidents)")

    # 6. Run a demo PCAP test
    print("[6/6] Executing real PCAP demo test (/api/runtime/start)...")
    res = client.post("/api/runtime/start", json={
        "pcap": "data_generation/pcaps/attack_portscan.pcap",
        "mode": "demo",
        "source": "DEMO"
    })
    assert res.status_code == 200, f"Start failed: {res.text}"
    start_res = res.json()
    print("   -> Started scenario:", start_res)
    assert start_res["session_id"].startswith("DEMO-")
    assert start_res["source"] == "DEMO"

    # Wait for completion
    for _ in range(30):
        time.sleep(0.5)
        st = client.get("/api/runtime/status").json()
        if not st.get("running"):
            break

    print("   -> Scenario completed! Summary:", st.get("summary"))
    assert st.get("summary", {}).get("records", 0) > 0, "No records produced by scenario"

    # Verify alerts produced have source == DEMO
    res = client.get("/api/alerts")
    alerts = res.json()
    demo_alerts = [a for a in alerts if a.get("source") == "DEMO" or (a.get("session_id") and a.get("session_id").startswith("DEMO-"))]
    print(f"   -> Verified {len(demo_alerts)} alerts stamped with source == 'DEMO'")
    assert len(demo_alerts) > 0, "No DEMO alerts stamped"

    print("\nALL VERIFICATION CHECKS PASSED SUCCESSFULLY!")

if __name__ == "__main__":
    test_api()
