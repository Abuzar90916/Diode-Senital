import os
import sys

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, BASE_DIR)

from threatcore.c2_beacon_detector import C2BeaconDetector
from fp_reduction.allowlists import AllowlistManager
from fp_reduction.corroboration import CorroborationEngine
from fp_reduction.persistence_filter import PersistenceFilter
from fp_reduction.baseline_store import BaselineStore
from ingestion.pcap_reader import PcapStreamingReader
from features.flow_aggregator import FlowAggregator

normal_pcap = os.path.join(BASE_DIR, "validation", "external_samples", "ctu13_real_normal.pcap")
reader = PcapStreamingReader(normal_pcap)
aggregator = FlowAggregator(window_size_sec=30.0, slide_interval_sec=10.0)
normal_records = []
for pkt in reader.stream():
    recs = aggregator.process_packet(pkt)
    if recs:
        normal_records.extend(recs)
normal_records.extend(aggregator.flush())

allowlist = AllowlistManager()
detector = C2BeaconDetector(allowlist_manager=allowlist)
corroborator = CorroborationEngine(default_min_signals=2)
persistence = PersistenceFilter(required_windows=3, window_ttl_seconds=300, min_window_interval_sec=2.0)
baseline = BaselineStore()

candidates = []
corroborated = []
promoted = []

for rec in normal_records:
    cand = detector.detect(rec, baseline)
    if cand:
        candidates.append(cand)
        passed, count, reason = corroborator.evaluate_candidate(cand)
        if passed:
            corroborated.append(cand)
            prom, pcount, alert = persistence.process_candidate(cand, count)
            if prom and alert:
                promoted.append(alert)

print(f"Candidates generated: {len(candidates)}")
print(f"Passed Corroboration: {len(corroborated)}")
print(f"Promoted by PersistenceFilter (min 3 windows, 2s interval): {len(promoted)}")
for i, c in enumerate(candidates):
    print(f"  Candidate {i+1}: host={c.src_ip} -> {c.dst_ip}:{c.dst_port} signals={c.signals}")

# Now test what if min_window_interval_sec=0.0 (the old setting in cd03bae):
old_persistence = PersistenceFilter(required_windows=3, window_ttl_seconds=300, min_window_interval_sec=0.0)
old_promoted = []
for c in corroborated:
    prom, pcount, alert = old_persistence.process_candidate(c, len(c.signals))
    if prom and alert:
        old_promoted.append(alert)
print(f"Promoted by old PersistenceFilter without 2s interval: {len(old_promoted)}")
