import os
import sys
import ipaddress

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, BASE_DIR)

from schemas.flow_feature_record import FlowFeatureRecord
from fp_reduction.allowlists import AllowlistManager
from ingestion.pcap_reader import PcapStreamingReader
from features.flow_aggregator import FlowAggregator
from fp_reduction.corroboration import CorroborationEngine
from fp_reduction.persistence_filter import PersistenceFilter
from fp_reduction.baseline_store import BaselineStore
from schemas.alert_record import AlertCandidate, ThreatClass

# Check if AllowlistManager can have is_local_or_private
class GeneralizedAllowlistManager(AllowlistManager):
    def __init__(self, enterprise_subnets=None):
        super().__init__()
        # Standard private RFC subnets
        self.enterprise_networks = [
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
            ipaddress.ip_network("127.0.0.0/8"),
            ipaddress.ip_network("169.254.0.0/16"),
            ipaddress.ip_network("100.64.0.0/10"), # CGNAT
        ]
        # In CTU-13 or specific enterprise enclave, can include university/enterprise ASN or prefixes
        # But let's see if we even need 147.32!
        if enterprise_subnets:
            for s in enterprise_subnets:
                self.enterprise_networks.append(ipaddress.ip_network(s))

    def is_local_or_private(self, ip_str: str) -> bool:
        if not ip_str:
            return False
        try:
            addr = ipaddress.ip_address(ip_str)
            if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast:
                return True
            for net in self.enterprise_networks:
                if addr in net:
                    return True
        except ValueError:
            pass
        return False

# Reconstruct Generalized C2 Beacon Detector with zero hardcoded 147.32 strings
class GeneralizedC2BeaconDetector:
    def __init__(self, allowlist_manager=None, periodicity_threshold=0.75, max_iat_cv=0.15):
        self.allowlists = allowlist_manager or GeneralizedAllowlistManager()
        self.periodicity_threshold = periodicity_threshold
        self.max_iat_cv = max_iat_cv

    def detect(self, record, baseline=None):
        timing = record.timing
        signals = []
        raw_evidence = []
        dst_host = record.dst_ip
        dst_port = record.dst_port

        # 1. LOCAL / DISCOVERY / BROADCAST SUPPRESSION:
        # Routine LAN discovery (NetBIOS 137/138/139, SNMP 161/162, SSDP 1900, mDNS 5353, port 0, broadcast/multicast)
        if dst_port in (0, 137, 138, 139, 161, 162, 1900, 2869, 5353) or dst_host.endswith(".255") or dst_host.startswith(("224.", "239.")):
            return None

        # Network-Agnostic Internal Infrastructure Suppression:
        # If destination is internal (ASN 0 or RFC1918 / local private range), internal services are suppressed:
        is_dest_internal = (record.dst_asn == 0 or self.allowlists.is_local_or_private(dst_host))
        if is_dest_internal and dst_port in (1025, 2048, 2049, 3389):
            return None

        # Inbound responses from DNS resolver or RDP server are not outbound C2 channels
        if record.src_port == 53:
            return None
        if record.src_port == 3389 and dst_port > 1024:
            return None

        # Allowlist check for known periodic destinations
        if self.allowlists.is_known_periodic_dest(dst_host, port=dst_port):
            return None

        # 2. STRENGTHENED DESTINATION ASN CONTEXT & RARITY CHECK:
        dst_asn = record.dst_asn
        is_rare_destination = False
        has_non_standard_port = dst_port not in (80, 443, 53)

        if dst_asn is not None and dst_asn != 0 and not self.allowlists.is_trusted_cloud_asn(dst_asn):
            signals.append("suspicious_external_asn")
            raw_evidence.append(f"Destination ASN {dst_asn} is not in trusted infrastructure allowlist")
            is_rare_destination = True
        elif dst_asn is None and not is_dest_internal:
            if has_non_standard_port:
                signals.append("unresolved_public_asn_rarity")
                raw_evidence.append(f"Unresolved public ASN on non-standard port {dst_port}")
                is_rare_destination = True
            elif timing.periodicity_score >= 0.85 and timing.iat_cv <= 0.10:
                signals.append("unresolved_public_asn_rarity")
                raw_evidence.append("Unresolved public ASN with verified tight timing cluster")
                is_rare_destination = True
        else:
            return None

        # Signal 1: High Periodicity / Strict Regularity
        if timing.periodicity_score >= self.periodicity_threshold:
            signals.append("high_periodicity_regularity")
            raw_evidence.append(f"High IAT periodicity score: {timing.periodicity_score:.3f}")

        # Signal 2: Low IAT Variance
        if timing.iat_cv <= self.max_iat_cv and timing.iat_mean_ms > 50.0:
            signals.append("low_iat_variance")
            raw_evidence.append(f"Low IAT variance (CV: {timing.iat_cv:.4f})")

        # Signal 3: Timing Cluster Regularity Anomaly
        if timing.periodicity_score >= 0.85 and timing.iat_cv <= 0.10:
            signals.append("tight_timing_cluster_beacon")

        # Signal 4: Packet Size Sequence Pattern
        if record.crypto_metadata and record.crypto_metadata.packet_size_sequence:
            sizes = record.crypto_metadata.packet_size_sequence
            if len(sizes) >= 3 and max(sizes) < 350:
                import numpy as np
                var = float(np.var(sizes)) if len(sizes) > 1 else 0.0
                if var < 30.0:
                    signals.append("fixed_size_heartbeat_payloads")

        has_timing = ("high_periodicity_regularity" in signals or "low_iat_variance" in signals)

        if not (has_timing and is_rare_destination and len(signals) >= 2):
            # Advanced C2 Vectors:
            is_external = not is_dest_internal
            if is_external and is_rare_destination and has_non_standard_port:
                if record.volumetric.packet_count >= 6 and record.volume_asymmetry.outbound_bytes > 500:
                    signals.append("non_standard_port_c2_channel")
                    signals.append("jittered_c2_session")
                else:
                    return None
            elif is_external and (dst_asn is None or (dst_asn != 0 and not self.allowlists.is_trusted_cloud_asn(dst_asn))) and dst_port == 80:
                if record.volumetric.packet_count >= 15 and record.volume_asymmetry.outbound_bytes > 1000:
                    signals.append("unresolved_public_asn_rarity")
                    signals.append("direct_ip_http_c2_channel")
                    signals.append("sustained_dropper_session")
                else:
                    return None
            else:
                return None

        confidence = min(1.0, 0.40 + 0.18 * len(signals))
        return AlertCandidate(
            timestamp=record.window_end,
            flow_identifier=record.flow_id,
            threat_class=ThreatClass.C2_BEACONING,
            confidence_score=confidence,
            raw_evidence=raw_evidence,
            signals=signals,
            src_ip=record.src_ip,
            dst_ip=record.dst_ip,
            dst_port=record.dst_port,
        )

# Load normal CTU-13 records
normal_pcap = os.path.join(BASE_DIR, "validation", "external_samples", "ctu13_real_normal.pcap")
reader = PcapStreamingReader(normal_pcap)
aggregator = FlowAggregator(window_size_sec=30.0, slide_interval_sec=10.0)
normal_records = []
for pkt in reader.stream():
    recs = aggregator.process_packet(pkt)
    if recs:
        normal_records.extend(recs)
normal_records.extend(aggregator.flush())

gen_detector = GeneralizedC2BeaconDetector()
corroborator = CorroborationEngine(default_min_signals=2)
persistence = PersistenceFilter(required_windows=3, window_ttl_seconds=300, min_window_interval_sec=2.0)

candidates = []
promoted = []
for r in normal_records:
    c = gen_detector.detect(r)
    if c:
        candidates.append(c)
        passed, count, _ = corroborator.evaluate_candidate(c)
        if passed:
            p, pc, alt = persistence.process_candidate(c, count)
            if p and alt:
                promoted.append(alt)

print(f"[*] Generalized C2 Detector on CTU-13 Normal Traffic:")
print(f"    Candidates: {len(candidates)}")
print(f"    Promoted Alerts (FP): {len(promoted)}")
