from datetime import datetime, timedelta
import random
from typing import List, Tuple
from schemas.flow_feature_record import (
    FlowFeatureRecord,
    VolumetricFeatures,
    TimingFeatures,
    DnsLexicalFeatures,
    CryptoMetadataFeatures,
    FanoutFeatures,
    VolumeAsymmetryFeatures,
)
from schemas.alert_record import ThreatClass


def generate_synthetic_flows(
    num_benign: int = 300, num_malicious_per_class: int = 40, base_time: datetime = None
) -> List[Tuple[FlowFeatureRecord, float, str]]:
    """
    Generates a realistic synthetic dataset of FlowFeatureRecord instances
    conforming to the authoritative frozen contract.
    Includes the 5 deliberate benign trap scenarios.

    Returns:
        List of tuples: (FlowFeatureRecord, label [0.0=benign, 1.0=malicious], threat_class_str)
    """
    now = base_time or datetime.now()
    records = []

    hosts = ["192.168.10.10", "192.168.10.20", "192.168.10.25", "192.168.10.50", "192.168.10.88"]

    # 1. BENIGN TRAFFIC SCENARIOS (Includes the 5 Trap Cases)
    for i in range(num_benign):
        host = random.choice(hosts)
        w_end = now - timedelta(seconds=i * 5)
        w_start = w_end - timedelta(seconds=30)
        src_port = random.randint(1024, 65000)

        # Scenarios distribution:
        # - "web_steady": standard web browsing
        # - "flash_sale": bursty high rate, low entropy (Trap for DDoS)
        # - "ntp_heartbeat": periodic NTP 123/UDP / updater (Trap for C2)
        # - "s3_backup": large upload to AWS S3 ASN 16509 (Trap for Exfiltration)
        # - "internal_scanner": appliance 192.168.10.250 (Trap for PortScan)
        # - "diverse_ja4": curl_cli, python_requests, iot_agent (Trap for Malware)
        scenario = random.choice([
            "web_steady", "flash_sale", "ntp_heartbeat",
            "s3_backup", "internal_scanner", "diverse_ja4"
        ])

        if scenario == "web_steady":
            dst_ip = "142.250.190.46"  # Google
            dst_port = 443
            dst_asn = 15169
            flow_id = f"{host}:{src_port} -> {dst_ip}:{dst_port} (TCP)"
            vol = VolumetricFeatures(
                packet_count=random.randint(15, 60), byte_count=random.randint(5000, 30000),
                packet_rate_pps=random.uniform(10.0, 50.0), byte_rate_bps=random.uniform(50000.0, 200000.0),
                src_ip_entropy=1.2, syn_ack_ratio=1.0, syn_count=1, ack_count=15
            )
            timing = TimingFeatures(
                packet_count=30, iat_mean_ms=random.uniform(200.0, 800.0), iat_cv=random.uniform(0.8, 1.5),
                periodicity_score=0.15, jitter_pct=45.0
            )
            dns = DnsLexicalFeatures(
                query_name="www.google.com", query_length=14, shannon_entropy=2.2,
                consonant_vowel_ratio=1.0, numeric_char_ratio=0.0, subdomain_count=2, record_type="A"
            )
            crypto = CryptoMetadataFeatures(
                is_tls_quic=True, ja4_str="t13d151600_8daaf6152771_014541793740",
                cipher_suites_count=16, extensions_count=10,
                packet_size_sequence=[250, 1420, 1420, 520]
            )
            fanout = FanoutFeatures(dst_port_count=1, dst_ip_count=1, scan_rate_pps=0.1, half_open_ratio=0.0)
            asym = VolumeAsymmetryFeatures(
                outbound_bytes=3000, inbound_bytes=25000, byte_ratio=0.12,
                duration_sec=30.0, outbound_byte_rate_bps=800.0
            )

        elif scenario == "flash_sale":
            # TRAP FOR DDOS: Extremely high packet rate, but single source (low entropy: 0.8-1.2)
            dst_ip = "198.51.100.50"
            dst_port = 443
            dst_asn = 13335  # Cloudflare
            flow_id = f"{host}:{src_port} -> {dst_ip}:{dst_port} (TCP)"
            vol = VolumetricFeatures(
                packet_count=random.randint(1500, 3000), byte_count=random.randint(1000000, 3000000),
                packet_rate_pps=random.uniform(1500.0, 2800.0), byte_rate_bps=random.uniform(2000000.0, 5000000.0),
                src_ip_entropy=0.85, syn_ack_ratio=1.02, syn_count=50, ack_count=2000
            )
            timing = TimingFeatures(
                packet_count=2000, iat_mean_ms=0.5, iat_cv=0.9, periodicity_score=0.2, jitter_pct=60.0
            )
            dns = DnsLexicalFeatures(has_dns=False)
            crypto = CryptoMetadataFeatures(is_tls_quic=True, ja4_str="ja4_benign_browser_1", cipher_suites_count=15)
            fanout = FanoutFeatures(dst_port_count=1, dst_ip_count=1, scan_rate_pps=0.5, half_open_ratio=0.0)
            asym = VolumeAsymmetryFeatures(outbound_bytes=100000, inbound_bytes=800000, byte_ratio=0.12)

        elif scenario == "ntp_heartbeat":
            # TRAP FOR C2: Highly periodic NTP (123/UDP) and OS auto-updater (443/TCP) with periodicity > 0.95
            is_ntp = random.choice([True, False])
            dst_ip = "216.239.35.0" if is_ntp else "13.107.4.50"  # time.google.com or Microsoft Update
            dst_port = 123 if is_ntp else 443
            dst_asn = 15169 if is_ntp else 8075
            flow_id = f"{host}:{src_port} -> {dst_ip}:{dst_port} ({'UDP' if is_ntp else 'TCP'})"
            vol = VolumetricFeatures(
                packet_count=4, byte_count=400, packet_rate_pps=0.5, byte_rate_bps=100.0,
                src_ip_entropy=0.0, syn_ack_ratio=1.0, udp_count=4 if is_ntp else 0, tcp_count=0 if is_ntp else 4
            )
            timing = TimingFeatures(
                packet_count=4, iat_mean_ms=8000.0, iat_cv=0.015, periodicity_score=0.98, jitter_pct=1.2
            )
            dns = DnsLexicalFeatures(has_dns=False)
            crypto = CryptoMetadataFeatures(is_tls_quic=False) if is_ntp else CryptoMetadataFeatures(is_tls_quic=True, ja4_str="t13i151600_8daaf6152771_014541793740")
            fanout = FanoutFeatures(dst_port_count=1, dst_ip_count=1, scan_rate_pps=0.02, half_open_ratio=0.0)
            asym = VolumeAsymmetryFeatures(outbound_bytes=200, inbound_bytes=200, byte_ratio=1.0)

        elif scenario == "s3_backup":
            # TRAP FOR EXFILTRATION: 350KB upload to AWS S3 (52.216.100.1, ASN 16509), 15:1 ratio, normal for backup host
            dst_ip = "52.216.100.1"
            dst_port = 443
            dst_asn = 16509  # AWS S3
            flow_id = f"{host}:{src_port} -> {dst_ip}:{dst_port} (TCP)"
            vol = VolumetricFeatures(
                packet_count=800, byte_count=350000, packet_rate_pps=120.0, byte_rate_bps=450000.0,
                src_ip_entropy=0.0, syn_ack_ratio=1.0, ack_count=750
            )
            timing = TimingFeatures(packet_count=800, iat_mean_ms=5.0, iat_cv=0.4, periodicity_score=0.3)
            dns = DnsLexicalFeatures(has_dns=False)
            crypto = CryptoMetadataFeatures(is_tls_quic=True, ja4_str="t13d151600_8daaf6152771_014541793740")
            fanout = FanoutFeatures(dst_port_count=1, dst_ip_count=1, scan_rate_pps=0.1, half_open_ratio=0.0)
            asym = VolumeAsymmetryFeatures(
                outbound_bytes=350000, inbound_bytes=23000, byte_ratio=15.2,
                duration_sec=30.0, outbound_byte_rate_bps=93333.0
            )

        elif scenario == "internal_scanner":
            # TRAP FOR PORTSCAN: Internal vulnerability scanner appliance 192.168.10.250 probing ports/hosts
            host = "192.168.10.250"
            dst_ip = f"192.168.10.{random.randint(1, 50)}"
            dst_port = random.randint(20, 1000)
            dst_asn = 0
            flow_id = f"{host}:{src_port} -> {dst_ip}:{dst_port} (TCP)"
            vol = VolumetricFeatures(
                packet_count=500, byte_count=30000, packet_rate_pps=400.0, byte_rate_bps=120000.0,
                src_ip_entropy=0.0, syn_ack_ratio=1.5
            )
            timing = TimingFeatures(packet_count=500, iat_mean_ms=2.0, iat_cv=0.5, periodicity_score=0.2)
            dns = DnsLexicalFeatures(has_dns=False)
            crypto = CryptoMetadataFeatures(is_tls_quic=False)
            fanout = FanoutFeatures(
                dst_port_count=13, dst_ip_count=10, scan_rate_pps=15.0, half_open_ratio=0.6,
                horizontal_scan_score=0.5, vertical_scan_score=0.43
            )
            asym = VolumeAsymmetryFeatures(outbound_bytes=15000, inbound_bytes=10000, byte_ratio=1.5)

        else: # diverse_ja4
            # TRAP FOR ENCRYPTED MALWARE: Uncommon benign fingerprints (curl_cli, python_requests, iot_agent)
            client_prof = random.choice(["curl_cli", "python_requests", "iot_agent"])
            ja4_map = {
                "curl_cli": "ja4_curl_cli_profile",
                "python_requests": "ja4_python_requests_profile",
                "iot_agent": "ja4_iot_agent_profile",
            }
            dst_ip = "104.16.132.229"  # Cloudflare
            dst_port = 443
            dst_asn = 13335
            flow_id = f"{host}:{src_port} -> {dst_ip}:{dst_port} (TCP)"
            vol = VolumetricFeatures(
                packet_count=20, byte_count=5000, packet_rate_pps=5.0, byte_rate_bps=15000.0,
                src_ip_entropy=0.0, syn_ack_ratio=1.0
            )
            timing = TimingFeatures(packet_count=20, iat_mean_ms=100.0, iat_cv=0.6, periodicity_score=0.2)
            dns = DnsLexicalFeatures(has_dns=False)
            crypto = CryptoMetadataFeatures(
                is_tls_quic=True, ja4_str=ja4_map[client_prof], cipher_suites_count=8, extensions_count=6,
                packet_size_sequence=[120, 450, 1200]
            )
            fanout = FanoutFeatures(dst_port_count=1, dst_ip_count=1, scan_rate_pps=0.1, half_open_ratio=0.0)
            asym = VolumeAsymmetryFeatures(outbound_bytes=2000, inbound_bytes=3000, byte_ratio=0.67)

        rec = FlowFeatureRecord(
            flow_id=flow_id,
            src_ip=host,
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
            dst_country="US" if dst_asn != 0 else "PRIVATE",
            volumetric=vol,
            timing=timing,
            dns_lexical=dns,
            crypto_metadata=crypto,
            fanout=fanout,
            volume_asymmetry=asym,
        )
        records.append((rec, 0.0, "Clean"))

    # 2. MALICIOUS ATTACK SCENARIOS (6 Mandatory Classes)
    for tc in [
        ThreatClass.DDOS,
        ThreatClass.C2_BEACONING,
        ThreatClass.DGA_TUNNELLING,
        ThreatClass.ENCRYPTED_MALWARE,
        ThreatClass.PORT_SCANNING,
        ThreatClass.DATA_EXFILTRATION,
    ]:
        for i in range(num_malicious_per_class):
            host = "192.168.10.50"
            w_end = now - timedelta(seconds=i * 10)
            w_start = w_end - timedelta(seconds=30)
            src_port = random.randint(1024, 65000)

            if tc == ThreatClass.DDOS:
                dst_ip = "192.168.10.100"  # Target server
                dst_port = 80
                flow_id = f"{host}:{src_port} -> {dst_ip}:{dst_port} (TCP)"
                vol = VolumetricFeatures(
                    packet_count=3500, byte_count=2500000, packet_rate_pps=2500.0, byte_rate_bps=4000000.0,
                    src_ip_entropy=4.35, syn_ack_ratio=4.5, syn_count=3000, ack_count=100, zero_window_count=12
                )
                timing = TimingFeatures(packet_count=3500, iat_mean_ms=0.2, iat_cv=0.95, periodicity_score=0.1)
                dns = DnsLexicalFeatures(has_dns=False)
                crypto = CryptoMetadataFeatures(is_tls_quic=False)
                fanout = FanoutFeatures(dst_port_count=1, dst_ip_count=1, scan_rate_pps=1.0)
                asym = VolumeAsymmetryFeatures(outbound_bytes=100000, inbound_bytes=10000, byte_ratio=10.0)
                dst_asn = 0

            elif tc == ThreatClass.C2_BEACONING:
                dst_ip = "198.51.100.77"  # Unclassified C2 Linode IP
                dst_port = 8443
                flow_id = f"{host}:{src_port} -> {dst_ip}:{dst_port} (TCP)"
                vol = VolumetricFeatures(
                    packet_count=40, byte_count=4000, packet_rate_pps=15.0, byte_rate_bps=12000.0,
                    src_ip_entropy=0.0, syn_ack_ratio=1.0
                )
                timing = TimingFeatures(
                    packet_count=40, iat_mean_ms=10000.0, iat_cv=0.02, periodicity_score=0.96, jitter_pct=1.5
                )
                dns = DnsLexicalFeatures(has_dns=False)
                crypto = CryptoMetadataFeatures(
                    is_tls_quic=True, ja4_str="ja4_malicious_c2_sample",
                    packet_size_sequence=[180, 180, 180, 180]
                )
                fanout = FanoutFeatures(dst_port_count=1, dst_ip_count=1, scan_rate_pps=0.1)
                asym = VolumeAsymmetryFeatures(outbound_bytes=2500, inbound_bytes=1500, byte_ratio=1.66)
                dst_asn = None  # Unresolved public IP rarity signal

            elif tc == ThreatClass.DGA_TUNNELLING:
                dst_ip = "8.8.8.8"
                dst_port = 53
                flow_id = f"{host}:{src_port} -> {dst_ip}:{dst_port} (UDP)"
                vol = VolumetricFeatures(
                    packet_count=30, byte_count=3000, packet_rate_pps=10.0, byte_rate_bps=8000.0,
                    src_ip_entropy=0.0, syn_ack_ratio=1.0, udp_count=30
                )
                timing = TimingFeatures(packet_count=30, iat_mean_ms=1500.0, iat_cv=0.5, periodicity_score=0.25)
                dns = DnsLexicalFeatures(
                    has_dns=True,
                    query_name="cxzkj83921kmd.9382103kmd9102ks.biz", query_length=38, shannon_entropy=4.42,
                    consonant_vowel_ratio=3.8, numeric_char_ratio=0.35, subdomain_count=3,
                    record_type="TXT", is_txt_or_null=True, is_tunnel_candidate=True
                )
                crypto = CryptoMetadataFeatures(is_tls_quic=False)
                fanout = FanoutFeatures(dst_port_count=1, dst_ip_count=1, scan_rate_pps=0.2)
                asym = VolumeAsymmetryFeatures(outbound_bytes=2000, inbound_bytes=1000, byte_ratio=2.0)
                dst_asn = 15169

            elif tc == ThreatClass.ENCRYPTED_MALWARE:
                dst_ip = "203.0.113.88"
                dst_port = 443
                flow_id = f"{host}:{src_port} -> {dst_ip}:{dst_port} (TCP)"
                vol = VolumetricFeatures(
                    packet_count=60, byte_count=8000, packet_rate_pps=25.0, byte_rate_bps=20000.0,
                    src_ip_entropy=0.0, syn_ack_ratio=1.0
                )
                timing = TimingFeatures(packet_count=60, iat_mean_ms=1000.0, iat_cv=0.4, periodicity_score=0.2)
                dns = DnsLexicalFeatures(has_dns=False)
                crypto = CryptoMetadataFeatures(
                    is_tls_quic=True, ja4_str="ja4_malicious_stub_1", ja3_digest="72a589da586844d7f0818ce684948eea",
                    cipher_suites_count=3, extensions_count=2,
                    packet_size_sequence=[160, 160, 160, 160]
                )
                fanout = FanoutFeatures(dst_port_count=1, dst_ip_count=1, scan_rate_pps=0.1)
                asym = VolumeAsymmetryFeatures(outbound_bytes=5000, inbound_bytes=3000, byte_ratio=1.66)
                dst_asn = None

            elif tc == ThreatClass.PORT_SCANNING:
                dst_ip = "192.168.10.1"
                dst_port = 80
                flow_id = f"{host}:{src_port} -> {dst_ip}:{dst_port} (TCP)"
                vol = VolumetricFeatures(
                    packet_count=800, byte_count=40000, packet_rate_pps=400.0, byte_rate_bps=120000.0,
                    src_ip_entropy=0.0, syn_ack_ratio=3.5, syn_count=700, ack_count=50
                )
                timing = TimingFeatures(packet_count=800, iat_mean_ms=10.0, iat_cv=0.5, periodicity_score=0.2)
                dns = DnsLexicalFeatures(has_dns=False)
                crypto = CryptoMetadataFeatures(is_tls_quic=False)
                fanout = FanoutFeatures(
                    dst_port_count=45, dst_ip_count=15, scan_rate_pps=12.0, half_open_ratio=0.75,
                    horizontal_scan_score=0.75, vertical_scan_score=1.0
                )
                asym = VolumeAsymmetryFeatures(outbound_bytes=20000, inbound_bytes=2000, byte_ratio=10.0)
                dst_asn = 0

            else: # DATA_EXFILTRATION
                dst_ip = "198.51.100.99"  # Unverified external server
                dst_port = 443
                flow_id = f"{host}:{src_port} -> {dst_ip}:{dst_port} (TCP)"
                vol = VolumetricFeatures(
                    packet_count=4000, byte_count=1500000, packet_rate_pps=1200.0, byte_rate_bps=3500000.0,
                    src_ip_entropy=0.0, syn_ack_ratio=1.0, ack_count=3500
                )
                timing = TimingFeatures(packet_count=4000, iat_mean_ms=5.0, iat_cv=0.3, periodicity_score=0.2)
                dns = DnsLexicalFeatures(has_dns=False)
                crypto = CryptoMetadataFeatures(is_tls_quic=False)
                fanout = FanoutFeatures(dst_port_count=1, dst_ip_count=1, scan_rate_pps=0.2)
                asym = VolumeAsymmetryFeatures(
                    outbound_bytes=1500000, inbound_bytes=50000, byte_ratio=30.0,
                    duration_sec=30.0, outbound_byte_rate_bps=400000.0, exfil_risk_score=0.95
                )
                dst_asn = None  # Untrusted external public IP

            rec = FlowFeatureRecord(
                flow_id=flow_id,
                src_ip=host,
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
            records.append((rec, 1.0, tc.value))

    random.shuffle(records)
    return records
