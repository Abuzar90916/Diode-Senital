from datetime import datetime, timedelta
from schemas.alert_record import AlertCandidate, ThreatClass
from fp_reduction.corroboration import CorroborationEngine
from fp_reduction.persistence_filter import PersistenceFilter
from fp_reduction.allowlists import AllowlistManager
from fp_reduction.baseline_store import BaselineStore


def test_corroboration_engine_single_signal_rejection():
    engine = CorroborationEngine(default_min_signals=2)

    # Candidate with only 1 signal
    single_cand = AlertCandidate(
        timestamp=datetime.now(),
        flow_identifier="192.168.10.50 -> 45.33.22.11",
        src_ip="192.168.10.50",
        threat_class=ThreatClass.DDOS,
        confidence_score=0.5,
        raw_evidence=["Elevated rate 1500 pps"],
        signals=["elevated_volumetric_rate"],
    )

    passed, count, reason = engine.evaluate_candidate(single_cand)
    assert passed is False
    assert count == 1
    assert "REJECTED_SINGLE_SIGNAL" in reason


def test_corroboration_engine_dual_signal_approval():
    engine = CorroborationEngine(default_min_signals=2)

    dual_cand = AlertCandidate(
        timestamp=datetime.now(),
        flow_identifier="192.168.10.50 -> 45.33.22.11",
        src_ip="192.168.10.50",
        threat_class=ThreatClass.DDOS,
        confidence_score=0.8,
        raw_evidence=["Elevated rate 1500 pps", "High source entropy 4.2 bits"],
        signals=["elevated_volumetric_rate", "high_source_ip_entropy"],
    )

    passed, count, reason = engine.evaluate_candidate(dual_cand)
    assert passed is True
    assert count == 2
    assert "PASSED_CORROBORATION" in reason


def test_persistence_filter():
    p_filter = PersistenceFilter(required_windows=3, min_window_interval_sec=1.0)
    now = datetime.now()

    cand = AlertCandidate(
        timestamp=now,
        flow_identifier="192.168.10.50 -> 45.33.22.11",
        src_ip="192.168.10.50",
        threat_class=ThreatClass.C2_BEACONING,
        confidence_score=0.85,
        raw_evidence=["Low IAT CV: 0.02s", "Rarity: Unresolved ASN"],
        signals=["low_iat_variance", "unresolved_public_asn_rarity"],
    )

    # Window 1: Should NOT promote
    promoted1, count1, alert1 = p_filter.process_candidate(cand, corroboration_count=2)
    assert promoted1 is False
    assert count1 == 1
    assert alert1 is None

    # Window 2: Should NOT promote
    cand.timestamp = now + timedelta(seconds=10)
    promoted2, count2, alert2 = p_filter.process_candidate(cand, corroboration_count=2)
    assert promoted2 is False
    assert count2 == 2

    # Window 3: SHOULD promote to Alert
    cand.timestamp = now + timedelta(seconds=20)
    promoted3, count3, alert3 = p_filter.process_candidate(cand, corroboration_count=2)
    assert promoted3 is True
    assert count3 == 3
    assert alert3 is not None
    assert alert3.persistence_windows == 3
    assert alert3.threat_class == ThreatClass.C2_BEACONING


def test_allowlist_manager():
    mgr = AllowlistManager()
    assert mgr.is_known_periodic_dest("pool.ntp.org") is True
    assert mgr.is_known_periodic_dest("arbitrary.c2.server", port=123) is True
    assert mgr.is_internal_scanner("192.168.10.250") is True
    assert mgr.is_trusted_cloud_asn(16509) is True  # AWS
    assert mgr.is_trusted_cloud_asn(15169) is True  # Google
    assert mgr.is_trusted_cloud_asn(63949) is False # Linode C2
    assert mgr.is_top_domain("google.com") is True
    assert mgr.is_top_domain("unknown-malicious-dga.biz") is False


def test_baseline_store_tod_and_poisoning_protection():
    store = BaselineStore()
    now = datetime.now()

    # Normal warmup updates
    store.update("192.168.10.50", "byte_ratio", 0.5, timestamp=now, is_warmup=True)
    store.update("192.168.10.50", "byte_ratio", 0.6, timestamp=now, is_warmup=True)
    store.update("192.168.10.50", "byte_ratio", 0.4, timestamp=now, is_warmup=True)

    # Time-of-day baseline deviation
    z = store.deviation_score("192.168.10.50", "byte_ratio", 8.0, use_tod=True, timestamp=now)
    assert z > 3.0

    # Poisoning protection test: extreme anomaly (byte_ratio = 50.0) during live streaming should be rejected
    store.update("192.168.10.50", "byte_ratio", 50.0, timestamp=now, is_warmup=False)
    mean, std = store.get_baseline("192.168.10.50", "byte_ratio")
    assert mean < 1.0  # Poisonous 50.0 value was ignored!
