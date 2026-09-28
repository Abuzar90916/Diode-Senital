"""
Helper script to inspect and summarize FlowFeatureRecords.
Reads a .jsonl file produced by run_pipeline.py and displays a clean,
human-readable breakdown of the extracted features for each threat class.
"""

import sys
import json
from typing import Dict, Any


def inspect_file(filepath: str, max_records: int = 10):
    print(f"\n==================================================================")
    print(f"  INSPECTING FLOW FEATURE RECORDS: {filepath}")
    print(f"==================================================================")

    count = 0
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                count += 1
                rec = json.loads(line)
                _print_record_summary(count, rec)
                if count >= max_records:
                    break
    except FileNotFoundError:
        print(f"[-] File not found: {filepath}. Run the pipeline first!")
        return

    print(f"[+] Displayed {count} records from {filepath}\n")


def _print_record_summary(idx: int, r: Dict[str, Any]):
    vol = r.get("volumetric", {})
    tim = r.get("timing", {})
    dns = r.get("dns_lexical", {})
    cry = r.get("crypto_metadata", {})
    fan = r.get("fanout", {})
    asym = r.get("volume_asymmetry", {})

    print(f"\n[Record #{idx}] Flow: {r.get('flow_id')}")
    print(f"  |-- Volumetric (DDoS)     : Pkts={vol.get('packet_count')} | SYN:ACK Ratio={vol.get('syn_ack_ratio')} | Rate={vol.get('packet_rate_pps')} pps | SrcEntropy={vol.get('src_ip_entropy')}")
    print(f"  |-- Timing (C2 Beaconing) : Mean IAT={tim.get('iat_mean_ms')} ms | CV={tim.get('iat_cv')} (Low=Periodic) | Periodicity={tim.get('periodicity_score')}")
    print(f"  |-- DNS Lexical (DGA)     : HasDNS={dns.get('has_dns')} | Query={dns.get('query_name')} | Entropy={dns.get('shannon_entropy')} | TunnelCandidate={dns.get('is_tunnel_candidate')}")
    print(f"  |-- Crypto Metadata (TLS) : IsTLS={cry.get('is_tls_quic')} | JA3={cry.get('ja3_digest')} | JA4={cry.get('ja4_str')} | PZX Seq={cry.get('packet_size_sequence')[:4]}")
    print(f"  |-- Fanout (Port Scanning): DstIPs={fan.get('dst_ip_count')} | DstPorts={fan.get('dst_port_count')} | HalfOpen={fan.get('half_open_ratio')} | ScanScore={fan.get('vertical_scan_score')}")
    print(f"  \\-- Volume Asymmetry (Exf): OutBytes={asym.get('outbound_bytes')} | InBytes={asym.get('inbound_bytes')} | ByteRatio={asym.get('byte_ratio')} | ExfilRisk={asym.get('exfil_risk_score')}")


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "beacon_features.jsonl"
    inspect_file(target)
