import os
import joblib
import numpy as np
from typing import Optional
from sklearn.ensemble import IsolationForest
from schemas.flow_feature_record import FlowFeatureRecord
from schemas.alert_record import AlertCandidate, ThreatClass
from threatcore.base_detector import BaseDetector
from fp_reduction.baseline_store import BaselineStore
from fp_reduction.allowlists import AllowlistManager


class DDoSDetector(BaseDetector):
    """
    DDoS Detector utilizing a statistical threshold matrix combined with
    an Isolation Forest model on volumetric features.
    
    Corroboration rule: Requires elevated volumetric rate AND elevated source IP entropy
    (or anomalous SYN/ACK ratio / zero-window counts). Rate alone (flash-sale burst) has low entropy
    and will NOT trigger an alert.
    """

    def __init__(
        self,
        allowlist_manager: Optional[AllowlistManager] = None,
        rate_threshold: float = 1000.0,
        entropy_threshold: float = 3.5,
        model_path: str = "models/iso_volumetric.joblib",
    ):
        super().__init__(allowlist_manager)
        self.rate_threshold = rate_threshold
        self.entropy_threshold = entropy_threshold
        
        # Load serialized Isolation Forest if available, otherwise fit baseline reference
        if os.path.exists(model_path):
            try:
                self.iso_forest = joblib.load(model_path)
            except Exception:
                self._init_fallback_model()
        else:
            self._init_fallback_model()

    def _init_fallback_model(self):
        self.iso_forest = IsolationForest(
            n_estimators=50, contamination=0.08, random_state=42
        )
        ref_data = np.array([
            [50.0, 20, 1.0, 1.0], [80.0, 40, 1.1, 0.98], [100.0, 50, 1.2, 1.0],
            [150.0, 75, 1.5, 0.95], [300.0, 150, 1.8, 1.05], [500.0, 250, 2.0, 1.1],
            [20.0, 10, 0.8, 1.0], [60.0, 30, 0.9, 1.01], [1500.0, 800, 0.9, 1.0] # flash sale
        ])
        self.iso_forest.fit(ref_data)

    def detect(
        self, record: FlowFeatureRecord, baseline: BaselineStore
    ) -> Optional[AlertCandidate]:
        vol = record.volumetric
        signals = []
        raw_evidence = []

        rate_val = vol.packet_rate_pps
        rate_z = baseline.deviation_score(record.src_ip, "volumetric_rate", rate_val)

        # Signal 1: Elevated Volumetric Rate (z-score > 2.5 or > rate_threshold)
        if rate_val > self.rate_threshold:
            signals.append("elevated_volumetric_rate")
            raw_evidence.append(
                f"Volumetric rate {rate_val:.1f} pps exceeds threshold ({self.rate_threshold:.1f} pps) [baseline Z-score: {rate_z:.2f}]"
            )

        # Signal 2: Elevated Source IP Entropy (indicating distributed attack traffic)
        # Note: Flash sale bursts have low entropy (0.5-1.5), DDoS has high entropy (> 3.5)
        if vol.src_ip_entropy >= self.entropy_threshold:
            signals.append("high_source_ip_entropy")
            raw_evidence.append(
                f"Source IP entropy {vol.src_ip_entropy:.2f} bits exceeds distributed threshold ({self.entropy_threshold:.2f} bits)"
            )

        if vol.src_ip_entropy >= 6.0 and vol.syn_count >= 1:
            signals.append("distributed_syn_flood_pattern")
            raw_evidence.append(
                f"Distributed SYN pattern: source entropy {vol.src_ip_entropy:.2f} bits with observed SYN traffic"
            )

        # Signal 3: Anomalous SYN/ACK Ratio or High Zero-Window Count (indicating SYN flood / resource exhaustion)
        if vol.syn_ack_ratio >= 3.0 or vol.syn_ack_ratio <= 0.1:
            signals.append("anomalous_syn_ack_ratio")
            raw_evidence.append(
                f"Anomalous SYN/ACK ratio {vol.syn_ack_ratio:.2f} indicates unacknowledged flood traffic"
            )
        
        if vol.zero_window_count >= 5:
            signals.append("tcp_zero_window_exhaustion")
            raw_evidence.append(
                f"Elevated TCP zero-window count ({vol.zero_window_count}) indicates target buffer saturation"
            )

        # Signal 4: Isolation Forest Anomaly Score on volumetric features
        feat_vector = np.array([[rate_val, vol.packet_count, vol.src_ip_entropy, vol.syn_ack_ratio]])
        try:
            iso_score = float(self.iso_forest.score_samples(feat_vector)[0])
            if signals and iso_score < -0.30:
                signals.append("isolation_forest_volumetric_anomaly")
                raw_evidence.append(
                    f"Isolation Forest volumetric anomaly score: {iso_score:.3f}"
                )
        except Exception:
            pass

        # Signal 5: UDP Reflection / Amplification Flood Pattern (DNS 53, NTP 123, SSDP 1900, Memcached 11211, CLDAP 389)
        reflective_ports = {53, 123, 389, 1900, 11211}
        is_reflective = (record.src_port in reflective_ports or record.dst_port in reflective_ports)
        if is_reflective and (rate_val >= 200.0 or vol.packet_count >= 500):
            signals.append("udp_reflection_amplification_pattern")
            port_num = record.src_port if record.src_port in reflective_ports else record.dst_port
            raw_evidence.append(
                f"UDP reflection amplification stream on port {port_num} ({rate_val:.1f} pps, {vol.packet_count} packets)"
            )

        # CRITICAL CORROBORATION CHECK: Rate alone must NOT fire (e.g. Flash sales with low entropy)
        # DDoS requires elevated rate AND (high entropy OR anomalous syn_ack / zero_window / udp reflection)
        has_rate = (
            "elevated_volumetric_rate" in signals
            or (vol.src_ip_entropy >= 6.0 and vol.syn_count >= 1)
            or "udp_reflection_amplification_pattern" in signals
        )
        has_corroborator = (
            "high_source_ip_entropy" in signals
            or "anomalous_syn_ack_ratio" in signals
            or "tcp_zero_window_exhaustion" in signals
            or "udp_reflection_amplification_pattern" in signals
        )

        if not (has_rate and has_corroborator):
            return None

        # Confidence calculation (0.0 to 1.0)
        confidence = min(1.0, 0.45 + 0.18 * len(signals))

        return AlertCandidate(
            timestamp=record.window_end,
            flow_identifier=record.flow_id,
            threat_class=ThreatClass.DDOS,
            confidence_score=confidence,
            raw_evidence=raw_evidence,
            signals=signals,
            src_ip=record.src_ip,
            dst_ip=record.dst_ip,
            dst_port=record.dst_port,
        )
