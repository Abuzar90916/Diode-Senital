import os
import sys
from collections import Counter, defaultdict

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, BASE_DIR)

from schemas.flow_feature_record import FlowFeatureRecord
from schemas.alert_record import AlertCandidate, ThreatClass
from threatcore.c2_beacon_detector import C2BeaconDetector
from fp_reduction.allowlists import AllowlistManager
from fp_reduction.corroboration import CorroborationEngine
from fp_reduction.persistence_filter import PersistenceFilter
from fp_reduction.baseline_store import BaselineStore
from ingestion.pcap_reader import PcapStreamingReader
from features.flow_aggregator import FlowAggregator
from training.evaluate_holdout import HoldoutEvaluator

botnet_pcap = os.path.join(BASE_DIR, "validation", "external_samples", "ctu13_neris_real_botnet_10k.pcap")

print("[*] Ingesting botnet records from ctu13_neris_real_botnet_10k.pcap...")
reader = PcapStreamingReader(botnet_pcap)
aggregator = FlowAggregator(window_size_sec=30.0, slide_interval_sec=10.0)
botnet_records = []
for pkt in reader.stream():
    recs = aggregator.process_packet(pkt)
    if recs:
        botnet_records.extend(recs)
botnet_records.extend(aggregator.flush())
print(f"[*] Loaded {len(botnet_records)} botnet records.")

evaluator = HoldoutEvaluator()
attack_records = [r for r in botnet_records if evaluator.is_genuine_attack_flow(r)]
print(f"[*] Identified {len(attack_records)} genuine attack records.")

# Reconstruct OLD C2 detector from commit cd03bae
class OldC2BeaconDetector:
    def __init__(self, allowlist_manager=None, periodicity_threshold=0.75, max_iat_cv=0.15):
        self.allowlists = allowlist_manager or AllowlistManager()
        self.periodicity_threshold = periodicity_threshold
        self.max_iat_cv = max_iat_cv

    def detect(self, record, baseline=None):
        timing = record.timing
        signals = []
        raw_evidence = []
        dst_host = record.dst_ip
        dst_port = record.dst_port

        if self.allowlists.is_known_periodic_dest(dst_host, port=dst_port):
            return None

        dst_asn = record.dst_asn
        is_rare_destination = False

        if dst_asn is None:
            signals.append("unresolved_public_asn_rarity")
            is_rare_destination = True
        elif dst_asn != 0 and not self.allowlists.is_trusted_cloud_asn(dst_asn):
            signals.append("suspicious_external_asn")
            is_rare_destination = True
        else:
            return None

        if timing.periodicity_score >= self.periodicity_threshold:
            signals.append("high_periodicity_regularity")
        if timing.iat_cv <= self.max_iat_cv and timing.iat_mean_ms > 50.0:
            signals.append("low_iat_variance")
        if timing.periodicity_score >= 0.85 and timing.iat_cv <= 0.10:
            signals.append("tight_timing_cluster_beacon")

        if record.crypto_metadata and record.crypto_metadata.packet_size_sequence:
            sizes = record.crypto_metadata.packet_size_sequence
            if len(sizes) >= 3 and max(sizes) < 350:
                import numpy as np
                var = float(np.var(sizes)) if len(sizes) > 1 else 0.0
                if var < 30.0:
                    signals.append("fixed_size_heartbeat_payloads")

        has_timing = ("high_periodicity_regularity" in signals or "low_iat_variance" in signals)
        if not (has_timing and is_rare_destination and len(signals) >= 2):
            return None

        return AlertCandidate(
            timestamp=record.window_end,
            flow_identifier=record.flow_id,
            threat_class=ThreatClass.C2_BEACONING,
            confidence_score=0.8,
            raw_evidence=signals,
            signals=signals,
            src_ip=record.src_ip,
            dst_ip=record.dst_ip,
            dst_port=record.dst_port,
        )

old_detector = OldC2BeaconDetector()
curr_detector = C2BeaconDetector(allowlist_manager=AllowlistManager())
corroborator = CorroborationEngine(default_min_signals=2)

# Evaluate both on attack records
def eval_detector(det, records, persistence_cls=None):
    candidates = []
    corroborated = []
    promoted = []
    detected_flows = set()
    promoted_flows = set()
    port_distribution = Counter()

    pfilter = PersistenceFilter(required_windows=3, window_ttl_seconds=300, min_window_interval_sec=2.0)

    dummy_baseline = BaselineStore()
    for r in records:
        c = det.detect(r, dummy_baseline)
        if c:
            candidates.append(c)
            detected_flows.add(r.flow_id)
            port_distribution[r.dst_port] += 1
            passed, count, _ = corroborator.evaluate_candidate(c)
            if passed:
                corroborated.append(c)
                prom, pcount, alert = pfilter.process_candidate(c, count)
                if prom and alert:
                    promoted.append(alert)
                    promoted_flows.add(r.flow_id)

    return {
        "candidates": len(candidates),
        "candidate_flows": len(detected_flows),
        "corroborated": len(corroborated),
        "promoted_windows": len(promoted),
        "promoted_flows": len(promoted_flows),
        "port_counts": port_distribution,
    }

old_res = eval_detector(old_detector, attack_records)
curr_res = eval_detector(curr_detector, attack_records)

print("=" * 60)
print("  C2 BEACON DETECTOR: BOTNET CAPTURE RECALL COMPARISON")
print("=" * 60)
print(f"OLD (cd03bae)  -> Candidate Windows: {old_res['candidates']} | Promoted Windows: {old_res['promoted_windows']} | Promoted Unique Flows (TP): {old_res['promoted_flows']}")
print(f"CURR (b127222) -> Candidate Windows: {curr_res['candidates']} | Promoted Windows: {curr_res['promoted_windows']} | Promoted Unique Flows (TP): {curr_res['promoted_flows']}")

print("\nPorts targeted in promoted flows under OLD:")
for p, cnt in old_res['port_counts'].most_common(10):
    print(f"  Port {p}: {cnt} candidate windows")

print("\nPorts targeted in promoted flows under CURRENT:")
for p, cnt in curr_res['port_counts'].most_common(10):
    print(f"  Port {p}: {cnt} candidate windows")
