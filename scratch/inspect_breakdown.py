import os
import sys
import json
from collections import Counter, defaultdict

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from schemas.flow_feature_record import FlowFeatureRecord
from schemas.alert_record import ThreatClass
from threatcore import (
    PortScanDetector,
    DDoSDetector,
    C2BeaconDetector,
    DGADNSDetector,
    EncryptedMalwareDetector,
    ExfiltrationDetector,
)
from threatcore.base_detector import BaselineStore
from fp_reduction.corroboration import CorroborationEngine
from fp_reduction.persistence_filter import PersistenceFilter
from fp_reduction.allowlists import AllowlistManager

allowlists = AllowlistManager()
baseline_store = BaselineStore()
corroborator = CorroborationEngine(default_min_signals=2)

detectors = [
    PortScanDetector(allowlist_manager=allowlists),
    DDoSDetector(allowlist_manager=allowlists),
    C2BeaconDetector(allowlist_manager=allowlists),
    DGADNSDetector(allowlist_manager=allowlists),
    EncryptedMalwareDetector(allowlist_manager=allowlists),
    ExfiltrationDetector(allowlist_manager=allowlists),
]

print("Loading botnet records...", flush=True)
with open(os.path.join(BASE_DIR, "scratch", "ctu_botnet.jsonl"), "r") as f:
    botnet_records = [FlowFeatureRecord.model_validate_json(line) for line in f]

print("Loading normal records...", flush=True)
with open(os.path.join(BASE_DIR, "scratch", "ctu_normal.jsonl"), "r") as f:
    normal_records = [FlowFeatureRecord.model_validate_json(line) for line in f]

infected_ip = "147.32.84.165"
def is_attack(r):
    is_inf = (r.src_ip == infected_ip or r.dst_ip == infected_ip)
    if not is_inf:
        return False
    peer_ip = r.dst_ip if r.src_ip == infected_ip else r.src_ip
    peer_port = r.dst_port if r.src_ip == infected_ip else r.src_port
    if peer_ip in ("147.32.80.9", "147.32.84.130") and peer_port == 53:
        return False
    if peer_ip.startswith("147.32.84.") and peer_port in (137, 138, 139):
        return False
    return True

print("Evaluating Botnet...", flush=True)
pfilter = PersistenceFilter(required_windows=3, window_ttl_seconds=300, min_window_interval_sec=2.0)
det_unique_attack_flows = defaultdict(set)
det_promoted_windows = Counter()
overall_attack_flows_detected = set()

for rec in botnet_records:
    attack = is_attack(rec)
    for d in detectors:
        name = d.__class__.__name__
        cand = d.detect(rec, baseline_store)
        if cand:
            passed, count, _ = corroborator.evaluate_candidate(cand)
            if passed:
                promoted, _, alert = pfilter.process_candidate(cand, count)
                if promoted and alert:
                    det_promoted_windows[name] += 1
                    if attack:
                        det_unique_attack_flows[name].add(rec.flow_id)
                        overall_attack_flows_detected.add(rec.flow_id)

print("\n--- BOTNET EVALUATION ---", flush=True)
print(f"Overall Unique Attack Flows Detected: {len(overall_attack_flows_detected)} / 366 ({len(overall_attack_flows_detected)/366*100:.2f}%)")
for d in detectors:
    name = d.__class__.__name__
    print(f"  {name:<24} | Unique Flows: {len(det_unique_attack_flows[name]):>4} | Promoted Windows: {det_promoted_windows[name]:>5}")

print("\nEvaluating Normal...", flush=True)
pfilter_normal = PersistenceFilter(required_windows=3, window_ttl_seconds=300, min_window_interval_sec=2.0)
det_unique_normal_flows = defaultdict(set)
det_promoted_normal_windows = Counter()
overall_normal_flows_alerted = set()

for rec in normal_records:
    for d in detectors:
        name = d.__class__.__name__
        cand = d.detect(rec, baseline_store)
        if cand:
            passed, count, _ = corroborator.evaluate_candidate(cand)
            if passed:
                promoted, _, alert = pfilter_normal.process_candidate(cand, count)
                if promoted and alert:
                    det_promoted_normal_windows[name] += 1
                    det_unique_normal_flows[name].add(rec.flow_id)
                    overall_normal_flows_alerted.add(rec.flow_id)

print("\n--- NORMAL EVALUATION ---", flush=True)
print(f"Overall Unique Normal Flows Alerted (FP): {len(overall_normal_flows_alerted)} / 465 ({len(overall_normal_flows_alerted)/465*100:.2f}%)")
for d in detectors:
    name = d.__class__.__name__
    print(f"  {name:<24} | Unique Flows (FP): {len(det_unique_normal_flows[name]):>4} | Promoted Windows (FP): {det_promoted_normal_windows[name]:>5}")
