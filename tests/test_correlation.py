from datetime import datetime, timedelta
from schemas.alert_record import Alert, ThreatClass
from correlation.chain_matcher import ChainMatcher
from correlation.entity_graph import EntityGraph


def test_recon_c2_exfil_chain():
    graph = EntityGraph()
    matcher = ChainMatcher(entity_graph=graph)
    now = datetime.now()

    alt1 = Alert(
        timestamp=now - timedelta(minutes=15),
        flow_identifier="192.168.10.50 -> 45.33.22.11 (TCP)",
        threat_class=ThreatClass.PORT_SCANNING,
        confidence_score=0.85,
        supporting_evidence="High fanout",
        corroboration_count=2,
        persistence_windows=3,
        src_ip="192.168.10.50",
    )
    alt2 = Alert(
        timestamp=now - timedelta(minutes=10),
        flow_identifier="192.168.10.50 -> 198.51.100.77 (TCP)",
        threat_class=ThreatClass.C2_BEACONING,
        confidence_score=0.90,
        supporting_evidence="High periodicity",
        corroboration_count=2,
        persistence_windows=3,
        src_ip="192.168.10.50",
    )
    alt3 = Alert(
        timestamp=now - timedelta(minutes=2),
        flow_identifier="192.168.10.50 -> 203.0.113.5 (TCP)",
        threat_class=ThreatClass.DATA_EXFILTRATION,
        confidence_score=0.92,
        supporting_evidence="Byte ratio anomaly",
        corroboration_count=2,
        persistence_windows=3,
        src_ip="192.168.10.50",
    )

    incidents = matcher.process_new_alerts([alt1, alt2, alt3])
    assert len(incidents) == 1
    inc = incidents[0]
    assert inc.chain_pattern == "recon_to_c2_to_exfil"
    assert inc.severity_multiplier == 2.5
    assert set(inc.constituent_alert_ids) == {alt1.alert_id, alt2.alert_id, alt3.alert_id}
    assert alt1.incident_id == inc.incident_id


def test_dga_to_c2_chain():
    graph = EntityGraph()
    matcher = ChainMatcher(entity_graph=graph)
    now = datetime.now()

    dga = Alert(
        timestamp=now - timedelta(minutes=5),
        flow_identifier="192.168.10.25 -> 8.8.8.8 (UDP)",
        threat_class=ThreatClass.DGA_TUNNELLING,
        confidence_score=0.88,
        supporting_evidence="High entropy query",
        corroboration_count=2,
        persistence_windows=3,
        src_ip="192.168.10.25",
    )
    c2 = Alert(
        timestamp=now - timedelta(minutes=3),
        flow_identifier="192.168.10.25 -> 198.51.100.99 (TCP)",
        threat_class=ThreatClass.C2_BEACONING,
        confidence_score=0.89,
        supporting_evidence="Periodicity score 0.98",
        corroboration_count=2,
        persistence_windows=3,
        src_ip="192.168.10.25",
    )

    incidents = matcher.process_new_alerts([dga, c2])
    assert len(incidents) == 1
    assert incidents[0].chain_pattern == "dga_to_c2"
    assert incidents[0].severity_multiplier == 1.8


def test_ddos_smokescreen_chain():
    graph = EntityGraph()
    matcher = ChainMatcher(entity_graph=graph)
    now = datetime.now()

    ddos = Alert(
        timestamp=now - timedelta(minutes=2),
        flow_identifier="192.168.10.10 -> 45.33.22.11 (TCP)",
        threat_class=ThreatClass.DDOS,
        confidence_score=0.98,
        supporting_evidence="Volumetric rate spike",
        corroboration_count=2,
        persistence_windows=3,
        src_ip="192.168.10.10",
    )
    exfil = Alert(
        timestamp=now - timedelta(minutes=1),
        flow_identifier="192.168.10.88 -> 203.0.113.99 (TCP)",
        threat_class=ThreatClass.DATA_EXFILTRATION,
        confidence_score=0.91,
        supporting_evidence="High outward ratio",
        corroboration_count=2,
        persistence_windows=3,
        src_ip="192.168.10.88",
    )

    incidents = matcher.process_new_alerts([ddos, exfil])
    assert len(incidents) == 1
    assert incidents[0].chain_pattern == "ddos_smokescreen"
    assert incidents[0].severity_multiplier == 2.0
