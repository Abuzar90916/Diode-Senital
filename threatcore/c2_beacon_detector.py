from typing import Optional
import numpy as np
from schemas.flow_feature_record import FlowFeatureRecord
from schemas.alert_record import AlertCandidate, ThreatClass
from threatcore.base_detector import BaseDetector
from fp_reduction.baseline_store import BaselineStore
from fp_reduction.allowlists import AllowlistManager


class C2BeaconDetector(BaseDetector):
    """
    C2 Beaconing Detector utilizing low-variance inter-arrival times (IAT),
    periodicity analysis, and timing clustering metrics.
    
    Corroboration rule: Requires high periodicity / low IAT variance AND destination rarity
    (dst_asn is None or off-allowlist, non-standard destination).
    Checks allowlist for known periodic services (NTP, OS updates, monitoring) to prevent FP.
    """

    def __init__(
        self,
        allowlist_manager: Optional[AllowlistManager] = None,
        periodicity_threshold: float = 0.75,
        max_iat_cv: float = 0.15,
    ):
        super().__init__(allowlist_manager)
        self.periodicity_threshold = periodicity_threshold
        self.max_iat_cv = max_iat_cv

    def detect(
        self, record: FlowFeatureRecord, baseline: BaselineStore
    ) -> Optional[AlertCandidate]:
        timing = record.timing
        signals = []
        raw_evidence = []

        dst_host = record.dst_ip
        dst_port = record.dst_port

        # 1. LOCAL / DISCOVERY / BROADCAST SUPPRESSION:
        # Routine LAN discovery (NetBIOS 137/138/139, SNMP 161/162, SSDP 1900, mDNS 5353, port 0, broadcast)
        # must never be flagged as external C2 channels.
        if dst_port in (0, 137, 138, 139, 161, 162, 1900, 2869, 5353) or dst_host.endswith(".255") or dst_host.startswith(("224.", "239.")):
            return None

        # Network-agnostic internal infrastructure suppression:
        # If destination is internal (ASN 0 or RFC1918 / local private range), internal services are suppressed:
        is_dest_internal = (record.dst_asn == 0 or self.allowlists.is_local_or_private(dst_host))
        if is_dest_internal and dst_port in (1025, 2048, 2049, 3389):
            return None

        # Inbound responses from DNS resolvers or internal servers are not outbound C2 channels:
        if record.src_port == 53:
            return None
        if record.src_port == 3389 and dst_port > 1024:
            return None

        # ALLOWLIST CHECK: Suppress known legitimate periodic destinations (NTP, cloud agents, OS updaters)
        if self.allowlists.is_known_periodic_dest(dst_host, port=dst_port):
            return None

        # 2. STRENGTHENED DESTINATION ASN CONTEXT & RARITY CHECK:
        # ASN 0 = RFC1918 (internal), None = unresolved public IP, Real = known public ASN
        # Crucial: unresolved_public_asn_rarity cannot serve as a standalone corroborating signal
        # on routine web traffic. It must be paired with a non-standard port or verified tight timing cluster.
        dst_asn = record.dst_asn
        is_rare_destination = False
        has_non_standard_port = dst_port not in (80, 443, 53)

        if dst_asn is not None and dst_asn != 0 and not self.allowlists.is_trusted_cloud_asn(dst_asn):
            # Real public ASN not in trusted cloud providers (e.g. Linode 63949, Tor exit 206264)
            signals.append("suspicious_external_asn")
            raw_evidence.append(f"Destination ASN {dst_asn} is not in trusted infrastructure allowlist")
            is_rare_destination = True
        elif dst_asn is None and not is_dest_internal:
            # Unresolved public ASN: require non-standard port OR verified tight timing cluster
            if has_non_standard_port:
                signals.append("unresolved_public_asn_rarity")
                raw_evidence.append(f"Unresolved public ASN on non-standard port {dst_port}")
                is_rare_destination = True
            elif timing.periodicity_score >= 0.85 and timing.iat_cv <= 0.10:
                signals.append("unresolved_public_asn_rarity")
                raw_evidence.append("Unresolved public ASN with verified tight timing cluster")
                is_rare_destination = True
        else:
            # Destination is internal (ASN 0) or trusted cloud provider (AWS, Google, Cloudflare, Azure)
            # C2 beacon detector must NOT fire against trusted infrastructure
            return None

        # Signal 1: High Periodicity / Strict Regularity
        if timing.periodicity_score >= self.periodicity_threshold:
            signals.append("high_periodicity_regularity")
            raw_evidence.append(
                f"High IAT periodicity score: {timing.periodicity_score:.3f} (threshold: {self.periodicity_threshold:.2f})"
            )

        # Signal 2: Low IAT Variance (Coefficient of Variation)
        if timing.iat_cv <= self.max_iat_cv and timing.iat_mean_ms > 50.0:
            signals.append("low_iat_variance")
            raw_evidence.append(
                f"Low IAT variance (CV: {timing.iat_cv:.4f} over mean {timing.iat_mean_ms:.1f}ms interval)"
            )

        # Signal 3: Timing Cluster Regularity Anomaly
        if timing.periodicity_score >= 0.85 and timing.iat_cv <= 0.10:
            signals.append("tight_timing_cluster_beacon")
            raw_evidence.append(
                f"Tight timing cluster: Periodicity {timing.periodicity_score:.3f}, IAT CV {timing.iat_cv:.4f}"
            )

        # Signal 4: Packet Size Sequence Pattern (fixed small heartbeat pushes)
        if record.crypto_metadata and record.crypto_metadata.packet_size_sequence:
            sizes = record.crypto_metadata.packet_size_sequence
            if len(sizes) >= 3 and max(sizes) < 350:
                var = float(np.var(sizes)) if len(sizes) > 1 else 0.0
                if var < 30.0:
                    signals.append("fixed_size_heartbeat_payloads")
                    raw_evidence.append(f"Fixed small payload push sequence (variance: {var:.1f}, max size: {max(sizes)} bytes)")

        # Corroboration requirement: Requires periodicity/timing regularity AND destination rarity
        has_timing = ("high_periodicity_regularity" in signals or "low_iat_variance" in signals)

        # Check primary timing + rarity corroboration
        if not (has_timing and is_rare_destination and len(signals) >= 2):
            # Advanced C2 Vector 1: Jittered / Interactive C2 session on non-standard port
            # Malware frequently adds jitter to defeat simple periodicity tests.
            # External, unclassified destination on non-standard port with multi-packet activity:
            is_external = not is_dest_internal
            if is_external and is_rare_destination and has_non_standard_port:
                if record.volumetric.packet_count >= 6 and record.volume_asymmetry.outbound_bytes > 500:
                    signals.append("non_standard_port_c2_channel")
                    signals.append("jittered_c2_session")
                    raw_evidence.append(f"Sustained external connection on non-standard port {dst_port} with {record.volumetric.packet_count} packets")
                else:
                    return None
            # Advanced C2 Vector 2: Direct-IP HTTP C2 / Dropper session to unclassified external IP
            elif is_external and (dst_asn is None or (dst_asn != 0 and not self.allowlists.is_trusted_cloud_asn(dst_asn))) and dst_port == 80:
                if record.volumetric.packet_count >= 15 and record.volume_asymmetry.outbound_bytes > 1000:
                    signals.append("unresolved_public_asn_rarity")
                    signals.append("direct_ip_http_c2_channel")
                    signals.append("sustained_dropper_session")
                    raw_evidence.append(f"Direct-IP HTTP session to unclassified external IP {dst_host}:80 with {record.volumetric.packet_count} packets")
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
