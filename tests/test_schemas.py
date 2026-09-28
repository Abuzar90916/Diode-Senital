from datetime import datetime
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


def test_flow_feature_record_schema():
    now = datetime.now()
    rec = FlowFeatureRecord(
        flow_id="192.168.10.50:54321 -> 142.250.190.46:443 (TCP)",
        src_ip="192.168.10.50",
        src_port=54321,
        dst_ip="142.250.190.46",
        dst_port=443,
        protocol="TCP",
        window_start=now,
        window_end=now,
        window_duration_sec=30.0,
        src_asn=0,
        dst_asn=15169,
        src_country="PRIVATE",
        dst_country="US",
        volumetric=VolumetricFeatures(
            packet_count=50, byte_count=20000, packet_rate_pps=100.0, byte_rate_bps=320000.0,
            src_ip_entropy=1.2, syn_ack_ratio=1.0, zero_window_count=0
        ),
        timing=TimingFeatures(
            packet_count=50, iat_mean_ms=500.0, iat_std_ms=200.0, iat_cv=0.8,
            periodicity_score=0.1, jitter_pct=30.0
        ),
        dns_lexical=DnsLexicalFeatures(
            query_name="www.google.com", query_length=14, shannon_entropy=2.1,
            consonant_vowel_ratio=1.0, numeric_char_ratio=0.0, subdomain_count=2, record_type="A"
        ),
        crypto_metadata=CryptoMetadataFeatures(
            is_tls_quic=True, ja4_str="t13d151600_8daaf6152771_014541793740",
            cipher_suites_count=16, extensions_count=10, packet_size_sequence=[250, 1420]
        ),
        fanout=FanoutFeatures(
            dst_port_count=1, dst_ip_count=1, scan_rate_pps=0.2, half_open_ratio=0.0
        ),
        volume_asymmetry=VolumeAsymmetryFeatures(
            outbound_bytes=5000, inbound_bytes=15000, byte_ratio=0.33,
            duration_sec=30.0, outbound_byte_rate_bps=1333.0, is_unidirectional_fallback=False
        ),
    )
    assert rec.src_ip == "192.168.10.50"
    assert rec.dst_asn == 15169
    assert rec.volumetric.packet_rate_pps == 100.0
    assert rec.timing.iat_mean_ms == 500.0

    # Test JSON serialization / deserialization
    json_data = rec.model_dump_json()
    assert "192.168.10.50" in json_data
    deserialized = FlowFeatureRecord.model_validate_json(json_data)
    assert deserialized.dst_ip == "142.250.190.46"


def test_asn_three_states():
    # 1. State 1: RFC1918 Private (ASN 0)
    rec_private = FlowFeatureRecord(
        flow_id="192.168.10.50:54321 -> 192.168.10.1:80 (TCP)",
        src_ip="192.168.10.50", src_port=54321, dst_ip="192.168.10.1", dst_port=80,
        window_start=datetime.now(), window_end=datetime.now(), src_asn=0, dst_asn=0,
        src_country="PRIVATE", dst_country="PRIVATE",
        volumetric=VolumetricFeatures(packet_count=10, packet_rate_pps=1.0),
        timing=TimingFeatures(iat_mean_ms=100.0, iat_cv=0.5, periodicity_score=0.1),
        fanout=FanoutFeatures(dst_port_count=1, dst_ip_count=1, scan_rate_pps=0.1),
        volume_asymmetry=VolumeAsymmetryFeatures(outbound_bytes=1000, inbound_bytes=1000)
    )
    assert rec_private.dst_asn == 0

    # 2. State 2: Real Public ASN (e.g. AWS 16509)
    rec_aws = FlowFeatureRecord(
        flow_id="192.168.10.50:54321 -> 52.216.100.1:443 (TCP)",
        src_ip="192.168.10.50", src_port=54321, dst_ip="52.216.100.1", dst_port=443,
        window_start=datetime.now(), window_end=datetime.now(), src_asn=0, dst_asn=16509,
        src_country="PRIVATE", dst_country="US",
        volumetric=VolumetricFeatures(packet_count=10, packet_rate_pps=1.0),
        timing=TimingFeatures(iat_mean_ms=100.0, iat_cv=0.5, periodicity_score=0.1),
        fanout=FanoutFeatures(dst_port_count=1, dst_ip_count=1, scan_rate_pps=0.1),
        volume_asymmetry=VolumeAsymmetryFeatures(outbound_bytes=1000, inbound_bytes=1000)
    )
    assert rec_aws.dst_asn == 16509

    # 3. State 3: Unresolved Public IP (None) - Rarity signal
    rec_unresolved = FlowFeatureRecord(
        flow_id="192.168.10.50:54321 -> 198.51.100.77:443 (TCP)",
        src_ip="192.168.10.50", src_port=54321, dst_ip="198.51.100.77", dst_port=443,
        window_start=datetime.now(), window_end=datetime.now(), src_asn=0, dst_asn=None,
        src_country="PRIVATE", dst_country=None,
        volumetric=VolumetricFeatures(packet_count=10, packet_rate_pps=1.0),
        timing=TimingFeatures(iat_mean_ms=100.0, iat_cv=0.5, periodicity_score=0.1),
        fanout=FanoutFeatures(dst_port_count=1, dst_ip_count=1, scan_rate_pps=0.1),
        volume_asymmetry=VolumeAsymmetryFeatures(outbound_bytes=1000, inbound_bytes=1000)
    )
    assert rec_unresolved.dst_asn is None


def test_alert_schema():
    alert = Alert(
        timestamp=datetime.now(),
        flow_identifier="192.168.10.50:54321 -> 198.51.100.77:443 (TCP)",
        threat_class=ThreatClass.DDOS,
        confidence_score=0.95,
        supporting_evidence="Elevated volumetric rate 2500 pps; high source entropy 4.35 bits",
        corroboration_count=2,
        persistence_windows=3,
        src_ip="192.168.10.50",
        dst_ip="198.51.100.77",
    )
    assert alert.threat_class == ThreatClass.DDOS
    assert alert.corroboration_count == 2
    assert alert.alert_id.startswith("ALT-")
    assert alert.host == "192.168.10.50"


def test_incident_record_schema():
    inc = IncidentRecord(
        incident_id="INC-RECON-EXFIL-001",
        chain_pattern="recon_to_c2_to_exfil",
        constituent_alert_ids=["ALT-1", "ALT-2", "ALT-3"],
        severity_multiplier=2.5,
        narrative="Multi-stage intrusion chain identified on host 192.168.10.50",
        first_seen=datetime.now(),
        last_seen=datetime.now(),
    )
    assert inc.incident_id == "INC-RECON-EXFIL-001"
    assert len(inc.constituent_alert_ids) == 3


def test_exported_jsonl_drift():
    """Validates real exported JSONL lines against canonical FlowFeatureRecord."""
    import os
    from pathlib import Path
    
    # Search for exported JSONL files in repo
    repo_root = Path(__file__).resolve().parent.parent
    jsonl_candidates = [
        repo_root / "beacon_features.jsonl",
        repo_root / "dga_features.jsonl",
        repo_root / "portscan_features.jsonl",
    ]
    checked = 0
    for jf in jsonl_candidates:
        if jf.exists():
            with open(jf, "r", encoding="utf-8") as f:
                for idx, line in enumerate(f):
                    line = line.strip()
                    if not line:
                        continue
                    rec = FlowFeatureRecord.model_validate_json(line)
                    assert rec.flow_id is not None
                    assert rec.volumetric is not None
                    assert rec.timing is not None
                    assert rec.dns_lexical is not None
                    assert rec.crypto_metadata is not None
                    assert rec.fanout is not None
                    assert rec.volume_asymmetry is not None
                    checked += 1
                    if idx >= 20:  # Validate sample from each file
                        break
    assert checked > 0, "At least one real exported JSONL record must be validated"

