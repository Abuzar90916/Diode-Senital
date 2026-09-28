from typing import Optional
from schemas.flow_feature_record import FlowFeatureRecord
from schemas.alert_record import AlertCandidate, ThreatClass
from threatcore.base_detector import BaseDetector
from fp_reduction.baseline_store import BaselineStore
from fp_reduction.allowlists import AllowlistManager


class ExfiltrationDetector(BaseDetector):
    """
    Data Exfiltration Detector analyzing volume asymmetry (byte ratio),
    outbound rates, destination ASN trust levels, and host-specific time-of-day baselines.
    
    Corroboration rule: Requires outward byte-ratio anomaly AND deviation from that specific host's
    own time-of-day baseline (plus non-trusted destination ASN).
    Mitigates composite score blind spots: catches sub-50KB leaks and suppresses trusted cloud backup uploads (AWS S3 ASN 16509).
    Safely handles unidirectional data-diode fallback mode.
    """

    def __init__(
        self,
        allowlist_manager: Optional[AllowlistManager] = None,
        ratio_threshold: float = 4.0,
        tod_z_threshold: float = 2.5,
    ):
        super().__init__(allowlist_manager)
        self.ratio_threshold = ratio_threshold
        self.tod_z_threshold = tod_z_threshold

    def detect(
        self, record: FlowFeatureRecord, baseline: BaselineStore
    ) -> Optional[AlertCandidate]:
        asym = record.volume_asymmetry
        signals = []
        raw_evidence = []

        dst_asn = record.dst_asn
        src_ip = record.src_ip

        # ALLOWLIST / CLOUD CHECK:
        # Legitimate large uploads to trusted cloud infrastructure (e.g. AWS S3 16509, Azure 8075, Cloudflare 13335)
        # must be suppressed to prevent backup upload false alarms.
        if self.allowlists.is_trusted_cloud_asn(dst_asn):
            return None

        # Handle Unidirectional Fallback Mode (pure 1-way tap with no return ACKs)
        is_fallback = asym.is_unidirectional_fallback or (asym.inbound_bytes == 0 and asym.outbound_bytes > 0)

        # Signal 1: High Outbound-to-Inbound Byte Ratio Anomaly (scored directly to catch sub-50KB leaks)
        if not is_fallback:
            if asym.byte_ratio >= self.ratio_threshold:
                signals.append("high_outward_byte_ratio")
                raw_evidence.append(
                    f"Outward byte asymmetry ratio {asym.byte_ratio:.1f}:1 exceeds threshold ({self.ratio_threshold:.1f}:1)"
                )
        else:
            # Under fallback mode, byte_ratio is unavailable (infinite).
            # To prevent false-alarming on normal unidirectional traffic (UDP, scans, broadcasts, dropped ACKs),
            # flag unidirectional outbound transfer ONLY if accompanied by significant volume or risk score.
            if asym.outbound_bytes >= 50000 or asym.exfil_risk_score >= 0.50:
                signals.append("unidirectional_outbound_data_transfer")
                raw_evidence.append(
                    f"Data diode unidirectional outbound bulk transfer ({asym.outbound_bytes} bytes sent, no return path)"
                )

        # Signal 2: Host Time-of-Day Baseline Deviation
        # Calculates Z-score against that specific host's hourly profile
        tod_z = baseline.deviation_score(
            host=src_ip,
            feature_name="byte_ratio" if not is_fallback else "outbound_byte_rate_bps",
            value=asym.byte_ratio if not is_fallback else asym.outbound_byte_rate_bps,
            use_tod=True,
            timestamp=record.window_end,
        )
        if tod_z >= self.tod_z_threshold:
            signals.append("host_tod_baseline_deviation")
            raw_evidence.append(
                f"Volume deviates from host's historical time-of-day baseline (Z-score: {tod_z:.2f}, threshold: {self.tod_z_threshold:.2f})"
            )

        # Signal 3: Destination ASN Context & Rarity
        if dst_asn is None:
            signals.append("unresolved_destination_asn")
            raw_evidence.append("Exfiltration destination IP has unclassified/unresolved public ASN (rarity indicator)")
        elif dst_asn != 0 and not self.allowlists.is_trusted_cloud_asn(dst_asn):
            signals.append("untrusted_external_asn")
            raw_evidence.append(f"Destination ASN {dst_asn} is unverified external infrastructure")

        # Signal 4: Upstream Exfil Risk Score (composite corroboration)
        if asym.exfil_risk_score >= 0.50:
            signals.append("upstream_exfil_risk_flag")
            raw_evidence.append(f"Upstream composite exfiltration risk score: {asym.exfil_risk_score:.2f}")

        # Signal 5: Sustained High Outbound Bandwidth Transfer
        # Requires meaningful volume (>=50KB) to prevent 1-packet sub-millisecond flows from dividing into huge bps
        if asym.outbound_bytes >= 50000 and (asym.outbound_byte_rate_bps > 50000.0 or asym.outbound_bytes > 100000):
            signals.append("elevated_outbound_volume")
            raw_evidence.append(f"Outbound transfer: {asym.outbound_bytes} bytes at {asym.outbound_byte_rate_bps:.0f} bps")

        # CRITICAL CORROBORATION REQUIREMENT:
        # Requires outward volume anomaly AND (host ToD baseline deviation OR untrusted ASN)
        has_asym = ("high_outward_byte_ratio" in signals or "unidirectional_outbound_data_transfer" in signals or "elevated_outbound_volume" in signals)
        has_corroborator = ("host_tod_baseline_deviation" in signals or "untrusted_external_asn" in signals or "unresolved_destination_asn" in signals)

        if not (has_asym and has_corroborator and len(signals) >= 2):
            return None

        confidence = min(1.0, 0.45 + 0.18 * len(signals))

        return AlertCandidate(
            timestamp=record.window_end,
            flow_identifier=record.flow_id,
            threat_class=ThreatClass.DATA_EXFILTRATION,
            confidence_score=confidence,
            raw_evidence=raw_evidence,
            signals=signals,
            src_ip=record.src_ip,
            dst_ip=record.dst_ip,
            dst_port=record.dst_port,
        )
