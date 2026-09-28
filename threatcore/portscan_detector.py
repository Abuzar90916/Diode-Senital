import os
import joblib
from typing import Optional
import numpy as np
from sklearn.ensemble import IsolationForest
from schemas.flow_feature_record import FlowFeatureRecord
from schemas.alert_record import AlertCandidate, ThreatClass
from threatcore.base_detector import BaseDetector
from fp_reduction.baseline_store import BaselineStore
from fp_reduction.allowlists import AllowlistManager


class PortScanDetector(BaseDetector):
    """
    Port Scanning & Reconnaissance Detector utilizing fan-out metric analysis,
    half-open connection ratios, and an Isolation Forest model.
    
    Corroboration rule: Requires elevated fan-out (ports/hosts) AND high half-open / failed connection ratio
    (real scans rarely complete handshakes).
    Suppresses known internal scanner IPs (e.g. 192.168.10.250) to avoid false alarms.
    """

    def __init__(
        self,
        allowlist_manager: Optional[AllowlistManager] = None,
        port_threshold: int = 15,
        host_threshold: int = 10,
        scan_rate_threshold: float = 5.0,
        model_path: str = "models/iso_fanout.joblib",
    ):
        super().__init__(allowlist_manager)
        self.port_threshold = port_threshold
        self.host_threshold = host_threshold
        self.scan_rate_threshold = scan_rate_threshold

        # Load serialized Isolation Forest if available, otherwise initialize reference classifier
        if os.path.exists(model_path):
            try:
                self.iso_forest = joblib.load(model_path)
            except Exception:
                self._init_fallback_model()
        else:
            self._init_fallback_model()

    def _init_fallback_model(self):
        self.iso_forest = IsolationForest(
            n_estimators=40, contamination=0.05, random_state=42
        )
        ref_fanout = np.array([
            [1, 1, 0.1], [1, 1, 0.2], [1, 1, 0.15], [2, 1, 0.1], [1, 2, 0.2],
            [1, 1, 0.05], [2, 2, 0.3], [1, 1, 0.25], [1, 1, 0.12], [2, 1, 0.18]
        ])
        self.iso_forest.fit(ref_fanout)

    def detect(
        self, record: FlowFeatureRecord, baseline: BaselineStore
    ) -> Optional[AlertCandidate]:
        fan = record.fanout
        vol = record.volumetric
        signals = []
        raw_evidence = []

        src_ip = record.src_ip

        # ALLOWLIST CHECK: Suppress authorized internal vulnerability scanners (e.g. 192.168.10.250)
        # Suppress routine UPnP LAN eventing (port 2869)
        if record.dst_port == 2869:
            return None

        if self.allowlists.is_internal_scanner(src_ip):
            return None

        # Signal 1: High Port or Host Fan-out (Vertical or Horizontal Recon)
        is_high_fanout = False
        if fan.dst_port_count >= self.port_threshold or fan.dst_ip_count >= self.host_threshold:
            signals.append("high_fanout_count")
            raw_evidence.append(
                f"High connection fan-out: {fan.dst_port_count} ports, {fan.dst_ip_count} hosts targeted"
            )
            is_high_fanout = True

        # Signal 2: High Connection Attempt / Scan Rate
        if fan.scan_rate_pps >= self.scan_rate_threshold:
            signals.append("elevated_scan_rate")
            raw_evidence.append(
                f"Scan rate {fan.scan_rate_pps:.1f} connection attempts/sec exceeds threshold ({self.scan_rate_threshold:.1f} pps)"
            )

        # Signal 3: High Half-Open / Failed Connection Ratio (SYN/ACK Ratio > 2.5 or half_open_ratio > 0.4)
        if fan.half_open_ratio >= 0.40 or vol.syn_ack_ratio >= 2.5:
            signals.append("high_unacknowledged_syn_ratio")
            raw_evidence.append(
                f"Unacknowledged connection ratio: half-open {fan.half_open_ratio:.2f}, SYN/ACK {vol.syn_ack_ratio:.2f} (indicates TCP SYN stealth scan)"
            )

        # Signal 4: Upstream Scan Composite Scores
        if fan.horizontal_scan_score >= 0.60 or fan.vertical_scan_score >= 0.50:
            signals.append("upstream_scan_score_anomaly")
            raw_evidence.append(
                f"Upstream scan scores: Horizontal {fan.horizontal_scan_score:.2f}, Vertical {fan.vertical_scan_score:.2f}"
            )

        # Signal 5: Isolation Forest Fanout Anomaly
        feat_vec = np.array([[fan.dst_port_count, fan.dst_ip_count, fan.scan_rate_pps]])
        try:
            iso_score = float(self.iso_forest.score_samples(feat_vec)[0])
            if signals and iso_score < -0.30:
                signals.append("isolation_forest_fanout_anomaly")
                raw_evidence.append(f"Isolation Forest fan-out anomaly score: {iso_score:.3f}")
        except Exception:
            pass

        # CRITICAL CORROBORATION REQUIREMENT:
        # Requires high fanout/scan rate AND high half-open / failed connection ratio (real scans rarely finish handshakes).
        has_fanout = is_high_fanout or "elevated_scan_rate" in signals
        has_half_open = "high_unacknowledged_syn_ratio" in signals

        if not (has_fanout and has_half_open and len(signals) >= 2):
            return None

        confidence = min(1.0, 0.45 + 0.18 * len(signals))

        return AlertCandidate(
            timestamp=record.window_end,
            flow_identifier=record.flow_id,
            threat_class=ThreatClass.PORT_SCANNING,
            confidence_score=confidence,
            raw_evidence=raw_evidence,
            signals=signals,
            src_ip=record.src_ip,
            dst_ip=record.dst_ip,
            dst_port=record.dst_port,
        )
