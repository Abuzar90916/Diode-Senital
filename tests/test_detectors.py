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
from fp_reduction.baseline_store import BaselineStore
from fp_reduction.allowlists import AllowlistManager
from threatcore.ddos_detector import DDoSDetector
from threatcore.c2_beacon_detector import C2BeaconDetector
from threatcore.dga_dns_detector import DGADNSDetector
from threatcore.encrypted_malware_detector import EncryptedMalwareDetector
from threatcore.portscan_detector import PortScanDetector
from threatcore.exfiltration_detector import ExfiltrationDetector


def make_record(
    src_ip="192.168.10.50",
    dst_ip="198.51.100.77",
    src_port=54321,
    dst_port=443,
    dst_asn=None,
    packet_rate_pps=10.0,
    entropy=1.0,
    syn_ack=1.0,
    zero_win=0,
    iat_cv=0.8,
    periodicity=0.1,
    query_name="www.example.com",
    query_entropy=2.0,
    record_type="A",
    is_txt=False,
    is_tunnel=False,
    ja4=None,
    ja3=None,
    pkt_seq=None,
    ports=1,
    hosts=1,
    scan_rate=0.1,
    half_open=0.0,
    byte_ratio=1.0,
    outbound_bytes=1000,
    inbound_bytes=1000,
    outbound_bps=800.0,
    is_fallback=False,
):
    now = datetime.now()
    return FlowFeatureRecord(
        flow_id=f"{src_ip}:{src_port} -> {dst_ip}:{dst_port} (TCP)",
        src_ip=src_ip,
        src_port=src_port,
        dst_ip=dst_ip,
        dst_port=dst_port,
        protocol="TCP",
        window_start=now,
        window_end=now,
        window_duration_sec=30.0,
        src_asn=0,
        dst_asn=dst_asn,
        src_country="PRIVATE",
        dst_country="US" if dst_asn is not None and dst_asn != 0 else "PRIVATE",
        volumetric=VolumetricFeatures(
            packet_count=100, packet_rate_pps=packet_rate_pps, byte_rate_bps=packet_rate_pps * 800,
            src_ip_entropy=entropy, syn_ack_ratio=syn_ack, zero_window_count=zero_win
        ),
        timing=TimingFeatures(
            packet_count=100, iat_mean_ms=1000.0, iat_cv=iat_cv, periodicity_score=periodicity
        ),
        dns_lexical=DnsLexicalFeatures(
            query_name=query_name, query_length=len(query_name), shannon_entropy=query_entropy,
            record_type=record_type, is_txt_or_null=is_txt, is_tunnel_candidate=is_tunnel
        ),
        crypto_metadata=CryptoMetadataFeatures(
            is_tls_quic=True, ja4_str=ja4, ja3_digest=ja3, packet_size_sequence=pkt_seq or []
        ),
        fanout=FanoutFeatures(
            dst_port_count=ports, dst_ip_count=hosts, scan_rate_pps=scan_rate, half_open_ratio=half_open
        ),
        volume_asymmetry=VolumeAsymmetryFeatures(
            outbound_bytes=outbound_bytes, inbound_bytes=inbound_bytes, byte_ratio=byte_ratio,
            outbound_byte_rate_bps=outbound_bps, is_unidirectional_fallback=is_fallback
        ),
    )


# 1. POSITIVE THREAT DETECTION TESTS
def test_ddos_detector_fires_on_attack():
    baseline = BaselineStore()
    detector = DDoSDetector()
    malicious = make_record(packet_rate_pps=2500.0, entropy=4.5, syn_ack=4.0, zero_win=8)
    cand = detector.detect(malicious, baseline)
    assert cand is not None
    assert len(cand.signals) >= 2
    assert "elevated_volumetric_rate" in cand.signals


def test_c2_beacon_detector_fires_on_attack():
    baseline = BaselineStore()
    detector = C2BeaconDetector()
    malicious = make_record(periodicity=0.96, iat_cv=0.02, dst_asn=None, pkt_seq=[180, 180, 180])
    cand = detector.detect(malicious, baseline)
    assert cand is not None
    assert "high_periodicity_regularity" in cand.signals


def test_dga_dns_detector_fires_on_attack():
    baseline = BaselineStore()
    detector = DGADNSDetector()
    malicious = make_record(
        query_name="cxzkj83921kmd.9382103kmd9102ks.biz", query_entropy=4.5, record_type="TXT", is_txt=True
    )
    cand = detector.detect(malicious, baseline)
    assert cand is not None
    assert "high_domain_entropy" in cand.signals


def test_encrypted_malware_detector_fires_on_attack():
    baseline = BaselineStore()
    detector = EncryptedMalwareDetector()
    malicious = make_record(
        ja4="ja4_malicious_stub_1", ja3="72a589da586844d7f0818ce684948eea",
        pkt_seq=[160, 160, 160, 160], dst_asn=None
    )
    cand = detector.detect(malicious, baseline)
    assert cand is not None
    assert "malicious_tls_fingerprint_match" in cand.signals


def test_portscan_detector_fires_on_attack():
    baseline = BaselineStore()
    detector = PortScanDetector()
    malicious = make_record(ports=45, hosts=15, scan_rate=12.0, half_open=0.75, syn_ack=3.5)
    cand = detector.detect(malicious, baseline)
    assert cand is not None
    assert "high_fanout_count" in cand.signals


def test_exfiltration_detector_fires_on_attack():
    baseline = BaselineStore()
    detector = ExfiltrationDetector()
    now = datetime.now()
    # Baseline for host is small (out_in = 0.5)
    baseline.update("192.168.10.50", "byte_ratio", 0.5, timestamp=now, is_warmup=True)
    baseline.update("192.168.10.50", "byte_ratio", 0.6, timestamp=now, is_warmup=True)
    baseline.update("192.168.10.50", "byte_ratio", 0.4, timestamp=now, is_warmup=True)

    malicious = make_record(byte_ratio=25.0, outbound_bytes=1000000, dst_asn=None)
    cand = detector.detect(malicious, baseline)
    assert cand is not None
    assert "high_outward_byte_ratio" in cand.signals


# 2. EXPLICIT BENIGN TRAP PCAP TESTS (Asserts matching detector does NOT fire)
def test_trap_ddos_flash_sale_does_not_fire():
    """TRAP 1: Flash sale burst (2500 pps, but low entropy 0.85) must NOT fire DDoS."""
    baseline = BaselineStore()
    detector = DDoSDetector()
    flash_sale = make_record(packet_rate_pps=2500.0, entropy=0.85, syn_ack=1.0)
    assert detector.detect(flash_sale, baseline) is None


def test_trap_c2_ntp_heartbeat_does_not_fire():
    """TRAP 2: NTP (123/UDP) and OS auto-updater with periodicity > 0.95 must NOT fire C2."""
    allowlists = AllowlistManager()
    baseline = BaselineStore()
    detector = C2BeaconDetector(allowlist_manager=allowlists)
    
    # NTP on port 123
    ntp_flow = make_record(dst_port=123, dst_ip="216.239.35.0", periodicity=0.98, iat_cv=0.01)
    assert detector.detect(ntp_flow, baseline) is None

    # Microsoft update on 443
    updater_flow = make_record(dst_port=443, dst_ip="update.microsoft.com", periodicity=0.96, iat_cv=0.02)
    assert detector.detect(updater_flow, baseline) is None


def test_trap_exfil_s3_backup_does_not_fire():
    """TRAP 3: 350KB upload to AWS S3 (ASN 16509, 15:1 ratio) must NOT fire Exfiltration."""
    allowlists = AllowlistManager()
    baseline = BaselineStore()
    detector = ExfiltrationDetector(allowlist_manager=allowlists)
    s3_backup = make_record(
        dst_ip="52.216.100.1", dst_asn=16509, byte_ratio=15.0, outbound_bytes=350000
    )
    assert detector.detect(s3_backup, baseline) is None


def test_trap_portscan_internal_scanner_does_not_fire():
    """TRAP 4: Internal scanner appliance 192.168.10.250 probing ports must NOT fire PortScan."""
    allowlists = AllowlistManager()
    baseline = BaselineStore()
    detector = PortScanDetector(allowlist_manager=allowlists)
    scanner_probe = make_record(
        src_ip="192.168.10.250", ports=13, hosts=10, scan_rate=15.0, half_open=0.6
    )
    assert detector.detect(scanner_probe, baseline) is None


def test_trap_encrypted_malware_benign_ja4_profiles_does_not_fire():
    """TRAP 5: Uncommon benign fingerprints (curl_cli, iot_agent, python_requests) must NOT fire Malware."""
    allowlists = AllowlistManager()
    baseline = BaselineStore()
    detector = EncryptedMalwareDetector(allowlist_manager=allowlists)
    
    curl_flow = make_record(ja4="ja4_curl_cli_profile", dst_asn=13335)
    assert detector.detect(curl_flow, baseline) is None

    iot_flow = make_record(ja4="ja4_iot_agent_profile", dst_asn=13335)
    assert detector.detect(iot_flow, baseline) is None
