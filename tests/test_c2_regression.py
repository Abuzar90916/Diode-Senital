"""
C2 Beaconing Detector Regression Tests (SIH PS 26145).
Verifies the documented C2 false-positive fix:
1. 2-packet LAN DNS transaction (CV=0 artifact) does not trigger C2.
2. 2-packet NetBIOS transaction does not trigger C2.
3. 3-packet periodic sequence does not trigger periodicity-based C2.
4. 4+ packet genuinely periodic sequence triggers C2.
5. Existing positive C2 sample remains detectable.
6. Existing benign traffic remains benign.
7. Existing allowlist behavior (NTP, known periodic) remains intact.
"""

from datetime import datetime, timezone
import pytest

from schemas.flow_feature_record import (
    FlowFeatureRecord,
    VolumetricFeatures,
    TimingFeatures,
    DnsLexicalFeatures,
    CryptoMetadataFeatures,
    FanoutFeatures,
    VolumeAsymmetryFeatures,
)
from threatcore.c2_beacon_detector import C2BeaconDetector
from fp_reduction.baseline_store import BaselineStore
from fp_reduction.allowlists import AllowlistManager


def make_test_record(
    src_ip="192.168.1.50",
    src_port=49152,
    dst_ip="203.0.113.10",
    dst_port=443,
    dst_asn=None,
    packet_count=10,
    iat_mean_ms=1000.0,
    iat_cv=0.05,
    periodicity_score=0.95,
    outbound_bytes=1000,
    inbound_bytes=1000,
):
    now = datetime.now(timezone.utc)
    return FlowFeatureRecord(
        flow_id=f"{src_ip}:{src_port}->{dst_ip}:{dst_port}/TCP",
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
        volumetric=VolumetricFeatures(
            packet_count=packet_count,
            packet_rate_pps=float(packet_count) / 30.0,
            byte_count=outbound_bytes + inbound_bytes,
        ),
        timing=TimingFeatures(
            packet_count=packet_count,
            iat_mean_ms=iat_mean_ms,
            iat_cv=iat_cv,
            periodicity_score=periodicity_score,
        ),
        dns_lexical=DnsLexicalFeatures(has_dns=(dst_port == 53 or src_port == 53)),
        crypto_metadata=CryptoMetadataFeatures(),
        fanout=FanoutFeatures(),
        volume_asymmetry=VolumeAsymmetryFeatures(
            outbound_bytes=outbound_bytes,
            inbound_bytes=inbound_bytes,
            byte_ratio=float(outbound_bytes) / max(1, inbound_bytes),
        ),
    )


def test_2_packet_lan_dns_transaction_not_c2():
    """1. 2-packet LAN DNS transaction must NOT become C2 merely because CV=0."""
    detector = C2BeaconDetector()
    baseline = BaselineStore()

    # Query from host to campus/local DNS resolver 147.32.80.9:53 with 2 packets
    rec = make_test_record(
        src_ip="147.32.84.165",
        src_port=52341,
        dst_ip="147.32.80.9",
        dst_port=53,
        dst_asn=None,
        packet_count=2,
        iat_mean_ms=120.0,
        iat_cv=0.0,  # mathematical single-interval artifact
        periodicity_score=1.0,
    )
    candidate = detector.detect(rec, baseline)
    assert candidate is None, "2-packet LAN DNS transaction must not trigger C2 alert"


def test_2_packet_netbios_transaction_not_c2():
    """2. 2-packet NetBIOS transaction must NOT become C2."""
    detector = C2BeaconDetector()
    baseline = BaselineStore()

    rec = make_test_record(
        src_ip="147.32.84.165",
        src_port=137,
        dst_ip="147.32.84.255",
        dst_port=137,
        dst_asn=None,
        packet_count=2,
        iat_mean_ms=250.0,
        iat_cv=0.0,
        periodicity_score=1.0,
    )
    candidate = detector.detect(rec, baseline)
    assert candidate is None, "2-packet NetBIOS broadcast must not trigger C2 alert"


def test_3_packet_periodic_sequence_not_c2():
    """3. 3-packet periodic sequence must NOT trigger periodicity-based C2 (requires >= 4 packets)."""
    detector = C2BeaconDetector()
    baseline = BaselineStore()

    rec = make_test_record(
        src_ip="192.168.1.100",
        src_port=44122,
        dst_ip="198.51.100.99",
        dst_port=8443,
        dst_asn=None,  # unresolved external
        packet_count=3,
        iat_mean_ms=500.0,
        iat_cv=0.01,
        periodicity_score=0.98,
        outbound_bytes=150,  # low volume to avoid fallback trigger
    )
    candidate = detector.detect(rec, baseline)
    assert candidate is None, "3-packet sequence lacks sufficient observation count for periodicity"


def test_4_plus_packet_genuinely_periodic_sequence_detected():
    """4. 4+ packet genuinely periodic sequence triggers C2 detection."""
    detector = C2BeaconDetector()
    baseline = BaselineStore()

    rec = make_test_record(
        src_ip="192.168.1.100",
        src_port=44122,
        dst_ip="198.51.100.99",
        dst_port=8443,
        dst_asn=None,
        packet_count=6,
        iat_mean_ms=500.0,
        iat_cv=0.02,
        periodicity_score=0.95,
        outbound_bytes=800,
    )
    candidate = detector.detect(rec, baseline)
    assert candidate is not None, "4+ packet genuinely periodic external connection must be detected"
    assert "high_periodicity_regularity" in candidate.signals or "low_iat_variance" in candidate.signals


def test_existing_positive_c2_sample_remains_detectable():
    """5. Existing positive C2 sample remains detectable."""
    detector = C2BeaconDetector()
    baseline = BaselineStore()

    # Emulates typical periodic beaconing session to rare external ASN
    rec = make_test_record(
        src_ip="10.0.0.15",
        src_port=51234,
        dst_ip="203.0.113.88",
        dst_port=4444,
        dst_asn=63949,  # Non-cloud external ASN
        packet_count=20,
        iat_mean_ms=1000.0,
        iat_cv=0.03,
        periodicity_score=0.96,
    )
    candidate = detector.detect(rec, baseline)
    assert candidate is not None, "Legitimate C2 beaconing must remain detectable"
    assert "suspicious_external_asn" in candidate.signals


def test_existing_benign_traffic_remains_benign():
    """6. Existing benign web browsing with high jitter remains benign."""
    detector = C2BeaconDetector()
    baseline = BaselineStore()

    rec = make_test_record(
        src_ip="192.168.1.20",
        src_port=55123,
        dst_ip="142.250.190.46",  # Google
        dst_port=443,
        dst_asn=15169,  # Google Cloud/CDN ASN
        packet_count=50,
        iat_mean_ms=150.0,
        iat_cv=1.2,  # Poisson/human browsing variance
        periodicity_score=0.15,
    )
    candidate = detector.detect(rec, baseline)
    assert candidate is None, "Benign web traffic must not trigger C2 alert"


def test_existing_allowlist_behavior_remains_intact():
    """7. Existing allowlist behavior (NTP port 123, Microsoft update) remains suppressed."""
    allowlists = AllowlistManager()
    detector = C2BeaconDetector(allowlist_manager=allowlists)
    baseline = BaselineStore()

    # NTP traffic
    ntp_rec = make_test_record(
        src_ip="192.168.1.10",
        src_port=123,
        dst_ip="216.239.35.0",  # time.google.com
        dst_port=123,
        dst_asn=15169,
        packet_count=10,
        iat_mean_ms=64000.0,
        iat_cv=0.01,
        periodicity_score=0.99,
    )
    assert detector.detect(ntp_rec, baseline) is None, "NTP traffic on port 123 must be suppressed"
