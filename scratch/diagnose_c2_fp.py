import os
import sys
from collections import Counter, defaultdict

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, BASE_DIR)

from schemas.flow_feature_record import FlowFeatureRecord
from threatcore.c2_beacon_detector import C2BeaconDetector
from fp_reduction.allowlists import AllowlistManager
from fp_reduction.corroboration import CorroborationEngine
from fp_reduction.persistence_filter import PersistenceFilter
from fp_reduction.baseline_store import BaselineStore
from ingestion.pcap_reader import PcapStreamingReader
from features.flow_aggregator import FlowAggregator

normal_pcap = os.path.join(BASE_DIR, "validation", "external_samples", "ctu13_real_normal.pcap")

print("[*] Ingesting normal records from ctu13_real_normal.pcap...")
reader = PcapStreamingReader(normal_pcap)
aggregator = FlowAggregator(window_size_sec=30.0, slide_interval_sec=10.0)
normal_records = []
for pkt in reader.stream():
    recs = aggregator.process_packet(pkt)
    if recs:
        normal_records.extend(recs)
normal_records.extend(aggregator.flush())
print(f"[*] Loaded {len(normal_records)} normal records.")

# Test 1: Does BaselineStore have ANY impact on C2BeaconDetector?
c2 = C2BeaconDetector(allowlist_manager=AllowlistManager())
baseline_empty = BaselineStore()
baseline_full = BaselineStore()
# Populate baseline_full with extreme values
for rec in normal_records[:500]:
    baseline_full.update(rec.src_ip, "volumetric_rate", 999999.0, rec.window_end)
    baseline_full.update(rec.src_ip, "byte_ratio", 999999.0, rec.window_end)
    baseline_full.update(rec.src_ip, "outbound_byte_rate_bps", 999999.0, rec.window_end)

diff_count = 0
for rec in normal_records:
    res_empty = c2.detect(rec, baseline_empty)
    res_full = c2.detect(rec, baseline_full)
    if (res_empty is None) != (res_full is None):
        diff_count += 1

print(f"[*] C2 detections difference between empty baseline vs extreme baseline: {diff_count}")

# Test 2: Unroll what happens to C2 candidates when removing each suppression
class UnfilteredC2BeaconDetector:
    def __init__(self, mode="original"):
        self.allowlists = AllowlistManager()
        self.mode = mode

    def detect(self, record):
        timing = record.timing
        dst_host = record.dst_ip
        dst_port = record.dst_port

        # Mode toggles
        if self.mode != "cd03bae_original":
            # 1. Local discovery suppression
            if dst_port in (0, 137, 138, 139, 161, 162, 1900, 2869, 5353) or dst_host.endswith(".255") or dst_host.startswith(("224.", "239.")):
                return None, "suppressed_local_broadcast"

            # Internal campus suppression
            if dst_host.startswith("147.32.") and dst_port in (1025, 2048, 2049, 3389):
                return None, "suppressed_campus_infra"
            if record.src_ip.startswith("147.32.80.9") and record.src_port == 53:
                return None, "suppressed_campus_dns"
            if record.src_port == 3389 and dst_port > 1024:
                return None, "suppressed_rdp"

        if self.allowlists.is_known_periodic_dest(dst_host, port=dst_port):
            return None, "suppressed_allowlist"

        dst_asn = record.dst_asn
        is_rare_destination = False
        has_non_standard_port = dst_port not in (80, 443, 53)

        if self.mode == "cd03bae_original":
            # Original logic before b127222:
            if dst_asn is None:
                is_rare_destination = True
            elif dst_asn != 0 and not self.allowlists.is_trusted_cloud_asn(dst_asn):
                is_rare_destination = True
            else:
                return None, "suppressed_trusted_asn"
        else:
            # Current logic in b127222:
            if dst_asn is not None and dst_asn != 0 and not self.allowlists.is_trusted_cloud_asn(dst_asn):
                is_rare_destination = True
            elif dst_asn is None:
                if has_non_standard_port:
                    is_rare_destination = True
                elif timing.periodicity_score >= 0.85 and timing.iat_cv <= 0.10:
                    is_rare_destination = True
            else:
                return None, "suppressed_trusted_asn"

        if not is_rare_destination:
            return None, "not_rare_destination"

        has_timing = (timing.periodicity_score >= 0.75 or (timing.iat_cv <= 0.15 and timing.iat_mean_ms > 50.0))
        if not has_timing:
            return None, "no_timing"

        return True, "CANDIDATE_FIRED"

c2_old = UnfilteredC2BeaconDetector(mode="cd03bae_original")
c2_curr = UnfilteredC2BeaconDetector(mode="current")

old_candidates = []
for rec in normal_records:
    res, _ = c2_old.detect(rec)
    if res:
        old_candidates.append(rec)

curr_candidates = []
for rec in normal_records:
    res, _ = c2_curr.detect(rec)
    if res:
        curr_candidates.append(rec)

print(f"\n[*] cd03bae_original C2 candidates fired on normal traffic: {len(old_candidates)}")
print(f"[*] current (b127222) C2 candidates fired on normal traffic: {len(curr_candidates)}")

# Break down where the old candidates were blocked in current code
blocked_breakdown = Counter()
for rec in old_candidates:
    dst_host = rec.dst_ip
    dst_port = rec.dst_port
    if dst_port in (0, 137, 138, 139, 161, 162, 1900, 2869, 5353) or dst_host.endswith(".255") or dst_host.startswith(("224.", "239.")):
        blocked_breakdown["Broadcast/NetBIOS/Local Discovery (137/138/139/255)"] += 1
    elif dst_host.startswith("147.32.") and dst_port in (1025, 2048, 2049, 3389):
        blocked_breakdown["Campus LAN Infrastructure (147.32.* ports 1025/2048/3389)"] += 1
    elif rec.src_ip.startswith("147.32.80.9") and rec.src_port == 53:
        blocked_breakdown["Campus DNS Resolver Traffic (147.32.80.9:53)"] += 1
    elif rec.dst_asn is None and dst_port in (80, 443, 53) and not (rec.timing.periodicity_score >= 0.85 and rec.timing.iat_cv <= 0.10):
        blocked_breakdown["Unresolved ASN on Standard Ports (80/443/53 web/dns rarity tightening)"] += 1
    else:
        blocked_breakdown["Other / Advanced vector guard"] += 1

print("\n[*] Per-Mechanism Breakdown of why previous C2 candidates were eliminated in b127222:")
for k, v in blocked_breakdown.items():
    print(f"    - {k}: {v} records")
