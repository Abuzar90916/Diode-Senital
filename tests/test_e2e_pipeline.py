from datetime import datetime, timedelta
from typing import List, Optional
from schemas.flow_feature_record import (
    FlowFeatureRecord,
    VolumetricFeatures,
    TimingFeatures,
    DnsLexicalFeatures,
    CryptoMetadataFeatures,
    FanoutFeatures,
    VolumeAsymmetryFeatures,
)
from schemas.alert_record import Alert, AlertCandidate, ThreatClass
from schemas.incident_record import IncidentRecord
from fp_reduction.allowlists import AllowlistManager
from fp_reduction.baseline_store import BaselineStore
from fp_reduction.corroboration import CorroborationEngine
from fp_reduction.persistence_filter import PersistenceFilter
from threatcore.ddos_detector import DDoSDetector
from threatcore.c2_beacon_detector import C2BeaconDetector
from threatcore.dga_dns_detector import DGADNSDetector
from threatcore.encrypted_malware_detector import EncryptedMalwareDetector
from threatcore.portscan_detector import PortScanDetector
from threatcore.exfiltration_detector import ExfiltrationDetector
from correlation.entity_graph import EntityGraph
from correlation.chain_matcher import ChainMatcher


def create_mock_flow(
    threat_class_str: str,
    timestamp: datetime,
    src_ip: str = "192.168.10.50",
    dst_ip: str = "198.51.100.77",
    dst_port: int = 443,
    dst_asn: Optional[int] = None,
    is_unidirectional: bool = False,
) -> FlowFeatureRecord:
    w_end = timestamp
    w_start = timestamp - timedelta(seconds=30)
    src_port = 54321

    # Default clean sub-objects
    vol = VolumetricFeatures(packet_count=20, packet_rate_pps=5.0, byte_rate_bps=10000.0, src_ip_entropy=0.5, syn_ack_ratio=1.0)
    timing = TimingFeatures(packet_count=20, iat_mean_ms=100.0, iat_cv=0.7, periodicity_score=0.1)
    dns = DnsLexicalFeatures(has_dns=False)
    crypto = CryptoMetadataFeatures(is_tls_quic=False)
    fanout = FanoutFeatures(dst_port_count=1, dst_ip_count=1, scan_rate_pps=0.1, half_open_ratio=0.0)
    asym = VolumeAsymmetryFeatures(outbound_bytes=2000, inbound_bytes=3000, byte_ratio=0.67, is_unidirectional_fallback=is_unidirectional)

    if threat_class_str == "DDoS":
        vol = VolumetricFeatures(
            packet_count=3500, byte_count=2500000, packet_rate_pps=2500.0, byte_rate_bps=4000000.0,
            src_ip_entropy=4.35, syn_ack_ratio=4.5, syn_count=3000, ack_count=100, zero_window_count=10
        )
    elif threat_class_str == "C2_Beaconing":
        timing = TimingFeatures(
            packet_count=40, iat_mean_ms=10000.0, iat_cv=0.02, periodicity_score=0.96, jitter_pct=1.5
        )
        crypto = CryptoMetadataFeatures(
            is_tls_quic=True, ja4_str="ja4_browser_profile", packet_size_sequence=[180, 180, 180, 180]
        )
        dst_asn = None
    elif threat_class_str == "DGA_Tunnelling":
        dns = DnsLexicalFeatures(
            has_dns=True,
            query_name="cxzkj83921kmd.9382103kmd9102ks.biz", query_length=38, shannon_entropy=4.42,
            consonant_vowel_ratio=3.8, numeric_char_ratio=0.35, subdomain_count=3,
            record_type="TXT", is_txt_or_null=True, is_tunnel_candidate=True
        )
    elif threat_class_str == "Encrypted_Malware":
        crypto = CryptoMetadataFeatures(
            is_tls_quic=True, ja4_str="ja4_malicious_stub_1", ja3_digest="72a589da586844d7f0818ce684948eea",
            cipher_suites_count=3, extensions_count=2, packet_size_sequence=[160, 160, 160, 160]
        )
        dst_asn = None
    elif threat_class_str == "Port_Scanning":
        vol = VolumetricFeatures(packet_count=100, packet_rate_pps=5.0, syn_ack_ratio=1.0)
        fanout = FanoutFeatures(
            dst_port_count=45, dst_ip_count=15, scan_rate_pps=12.0, half_open_ratio=0.75,
            horizontal_scan_score=0.75, vertical_scan_score=1.0
        )
    elif threat_class_str == "Data_Exfiltration":
        if is_unidirectional:
            asym = VolumeAsymmetryFeatures(
                outbound_bytes=1500000, inbound_bytes=0, byte_ratio=1.0,
                duration_sec=30.0, outbound_byte_rate_bps=400000.0, is_unidirectional_fallback=True, exfil_risk_score=0.95
            )
        else:
            asym = VolumeAsymmetryFeatures(
                outbound_bytes=1500000, inbound_bytes=50000, byte_ratio=30.0,
                duration_sec=30.0, outbound_byte_rate_bps=400000.0, exfil_risk_score=0.95
            )
        dst_asn = None

    # Benign Traps
    elif threat_class_str == "trap_flash_sale":
        dst_ip = "198.51.100.50"
        dst_asn = 13335
        vol = VolumetricFeatures(packet_count=2500, packet_rate_pps=2500.0, byte_rate_bps=4000000.0, src_ip_entropy=0.85, syn_ack_ratio=1.0)
    elif threat_class_str == "trap_ntp":
        dst_ip = "216.239.35.0"
        dst_port = 123
        dst_asn = 15169
        timing = TimingFeatures(packet_count=4, iat_mean_ms=8000.0, iat_cv=0.015, periodicity_score=0.98)
    elif threat_class_str == "trap_s3_backup":
        dst_ip = "52.216.100.1"
        dst_asn = 16509
        asym = VolumeAsymmetryFeatures(outbound_bytes=350000, inbound_bytes=23000, byte_ratio=15.2, outbound_byte_rate_bps=93333.0)
    elif threat_class_str == "trap_scanner":
        src_ip = "192.168.10.250"
        dst_asn = 0
        fanout = FanoutFeatures(dst_port_count=13, dst_ip_count=10, scan_rate_pps=15.0, half_open_ratio=0.6)
    elif threat_class_str == "trap_diverse_ja4":
        crypto = CryptoMetadataFeatures(is_tls_quic=True, ja4_str="ja4_curl_cli_profile")
        dst_asn = 13335

    return FlowFeatureRecord(
        flow_id=f"{src_ip}:{src_port} -> {dst_ip}:{dst_port} (TCP)",
        src_ip=src_ip,
        src_port=src_port,
        dst_ip=dst_ip,
        dst_port=dst_port,
        protocol="TCP",
        window_start=w_start,
        window_end=w_end,
        window_duration_sec=30.0,
        src_asn=0,
        dst_asn=dst_asn,
        src_country="PRIVATE",
        dst_country="US" if dst_asn is not None and dst_asn != 0 else "PRIVATE",
        volumetric=vol,
        timing=timing,
        dns_lexical=dns,
        crypto_metadata=crypto,
        fanout=fanout,
        volume_asymmetry=asym,
    )


def test_end_to_end_pipeline():
    allowlists = AllowlistManager()
    baseline = BaselineStore()
    corroborator = CorroborationEngine(default_min_signals=2)
    persistence = PersistenceFilter(required_windows=3, min_window_interval_sec=5.0)
    graph = EntityGraph()
    matcher = ChainMatcher(entity_graph=graph)

    detectors = [
        DDoSDetector(allowlist_manager=allowlists),
        C2BeaconDetector(allowlist_manager=allowlists),
        DGADNSDetector(allowlist_manager=allowlists),
        EncryptedMalwareDetector(allowlist_manager=allowlists),
        PortScanDetector(allowlist_manager=allowlists),
        ExfiltrationDetector(allowlist_manager=allowlists),
    ]

    base_time = datetime.now()

    # 1. Warm up baseline for normal host
    for i in range(10):
        t = base_time - timedelta(seconds=(20 - i) * 30)
        baseline.update("192.168.10.50", "volumetric_rate", 10.0, timestamp=t, is_warmup=True)
        baseline.update("192.168.10.50", "byte_ratio", 0.5, timestamp=t, is_warmup=True)
        baseline.update("192.168.10.50", "outbound_byte_rate_bps", 500.0, timestamp=t, is_warmup=True)

    # 2. Test Benign Trap Traffic (Expected: 0 Alerts)
    trap_scenarios = ["trap_flash_sale", "trap_ntp", "trap_s3_backup", "trap_scanner", "trap_diverse_ja4"]
    promoted_trap_alerts = []

    for trap_name in trap_scenarios:
        for w in range(3):
            t = base_time + timedelta(seconds=w * 10)
            flow = create_mock_flow(trap_name, timestamp=t)
            for d in detectors:
                cand = d.detect(flow, baseline)
                if cand:
                    passed, c_count, _ = corroborator.evaluate_candidate(cand)
                    if passed:
                        promoted, _, alt = persistence.process_candidate(cand, c_count)
                        if promoted and alt:
                            promoted_trap_alerts.append(alt)

    assert len(promoted_trap_alerts) == 0, f"Benign trap generated false alerts: {promoted_trap_alerts}"

    # 3. Test 6 Attack Scenarios across 3 sliding windows (Demonstrating Flow -> Detectors -> Candidate -> Corroboration -> Persistence -> Alert)
    attack_classes = ["DDoS", "C2_Beaconing", "DGA_Tunnelling", "Encrypted_Malware", "Port_Scanning", "Data_Exfiltration"]
    promoted_attack_alerts: List[Alert] = []

    for atk_name in attack_classes:
        for w in range(3):
            t = base_time + timedelta(minutes=10 + attack_classes.index(atk_name) * 5, seconds=w * 10)
            flow = create_mock_flow(atk_name, timestamp=t, is_unidirectional=(atk_name == "Data_Exfiltration"))
            for d in detectors:
                cand = d.detect(flow, baseline)
                if cand:
                    passed, c_count, reason = corroborator.evaluate_candidate(cand)
                    assert passed is True
                    assert c_count >= 2
                    promoted, p_count, alt = persistence.process_candidate(cand, c_count)
                    if promoted and alt:
                        promoted_attack_alerts.append(alt)

    # Verify that all 6 attacks resulted in promoted Alert objects with 3 persistence windows
    assert len(promoted_attack_alerts) == 6
    alert_threat_classes = {a.threat_class.value for a in promoted_attack_alerts}
    for atk_name in attack_classes:
        assert atk_name in alert_threat_classes

    # 4. Feed alerts into Attack Chain Correlation Engine -> IncidentRecord
    # Create a 3-stage intrusion stream on host 192.168.10.50 (Port Scan -> C2 Beacon -> Data Exfiltration)
    recon_alt = next(a for a in promoted_attack_alerts if a.threat_class == ThreatClass.PORT_SCANNING)
    c2_alt = next(a for a in promoted_attack_alerts if a.threat_class == ThreatClass.C2_BEACONING)
    exfil_alt = next(a for a in promoted_attack_alerts if a.threat_class == ThreatClass.DATA_EXFILTRATION)

    # Correlate alerts
    incidents = matcher.process_new_alerts([recon_alt, c2_alt, exfil_alt])
    assert len(incidents) == 1
    inc = incidents[0]
    assert inc.chain_pattern == "recon_to_c2_to_exfil"
    assert inc.severity_multiplier == 2.5
    assert len(inc.constituent_alert_ids) == 3
    assert "Multi-stage intrusion chain identified" in inc.narrative
    assert recon_alt.incident_id == inc.incident_id
    assert c2_alt.incident_id == inc.incident_id
    assert exfil_alt.incident_id == inc.incident_id
