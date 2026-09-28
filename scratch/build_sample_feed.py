import os
import sys
import json
from datetime import datetime, timedelta

sys.path.insert(0, os.path.abspath("."))
from schemas.alert_record import Alert, ThreatClass
from schemas.incident_record import IncidentRecord
from correlation.chain_matcher import ChainMatcher
from correlation.entity_graph import EntityGraph

def build_curated_feed():
    start_time = datetime(2026, 9, 3, 14, 0, 0)
    
    events = [] # list of (timestamp, type, data_dict)
    
    # 1. Host A: 192.168.1.100 - APT Intrusion Chain (Recon -> C2 -> Exfil)
    # 1a. Port Scanning (Reconnaissance)
    t1 = start_time + timedelta(seconds=10)
    alt_recon_1 = Alert(
        timestamp=t1,
        flow_identifier="192.168.1.100:44236->10.0.0.5:22/TCP",
        threat_class=ThreatClass.PORT_SCANNING,
        confidence_score=0.98,
        supporting_evidence="High connection fan-out: 151 ports, 50 hosts targeted; Unacknowledged connection ratio: half-open 1.00, SYN/ACK 1.00 (TCP SYN stealth scan); Upstream scan scores: Horizontal 1.00, Vertical 1.00; Isolation Forest fan-out anomaly score: -0.627",
        corroboration_count=4,
        persistence_windows=3,
        src_ip="192.168.1.100",
        dst_ip="10.0.0.5",
        host="192.168.1.100"
    )
    events.append((t1, "ALERT", alt_recon_1))

    t2 = start_time + timedelta(seconds=25)
    alt_recon_2 = Alert(
        timestamp=t2,
        flow_identifier="192.168.1.100:44237->10.0.0.5:80/TCP",
        threat_class=ThreatClass.PORT_SCANNING,
        confidence_score=0.96,
        supporting_evidence="Connection fan-out: rapid horizontal sweep targeting HTTP/HTTPS management ports; Isolation Forest anomaly score: -0.584",
        corroboration_count=3,
        persistence_windows=3,
        src_ip="192.168.1.100",
        dst_ip="10.0.0.5",
        host="192.168.1.100"
    )
    events.append((t2, "ALERT", alt_recon_2))

    # 1b. C2 Beaconing (Host A establishes command channel)
    t3 = start_time + timedelta(seconds=60)
    alt_c2_1 = Alert(
        timestamp=t3,
        flow_identifier="192.168.1.100:51234->147.32.84.180:80/TCP",
        threat_class=ThreatClass.C2_BEACONING,
        confidence_score=0.99,
        supporting_evidence="Documented Neris C2 rendezvous point from CTU-13 literature; Strict periodic heartbeat: interval 30.0s (Jitter 0.02s); FFT spectral peak confirmed at 0.033 Hz; Destination ASN 12348 unrated external IP",
        corroboration_count=4,
        persistence_windows=3,
        src_ip="192.168.1.100",
        dst_ip="147.32.84.180",
        host="192.168.1.100"
    )
    events.append((t3, "ALERT", alt_c2_1))

    # 1c. Data Exfiltration (Host A exfiltrates classified records)
    t4 = start_time + timedelta(seconds=95)
    alt_exfil_1 = Alert(
        timestamp=t4,
        flow_identifier="192.168.1.100:58999->198.51.100.42:443/TCP",
        threat_class=ThreatClass.DATA_EXFILTRATION,
        confidence_score=0.97,
        supporting_evidence="Massive volume asymmetry: out/in byte ratio 48.2 (12.4 MB outbound payload); Off-hours transfer window; Non-allowlisted external cloud target; Entropy of payload 7.94 bits (high-density encryption)",
        corroboration_count=4,
        persistence_windows=3,
        src_ip="192.168.1.100",
        dst_ip="198.51.100.42",
        host="192.168.1.100"
    )
    events.append((t4, "ALERT", alt_exfil_1))

    # 2. Host B: 192.168.1.105 - DGA to C2 Check-in
    # 2a. DGA DNS Tunnel
    t5 = start_time + timedelta(seconds=35)
    alt_dga_1 = Alert(
        timestamp=t5,
        flow_identifier="192.168.1.105:59574->8.8.8.8:53/UDP",
        threat_class=ThreatClass.DGA_TUNNELLING,
        confidence_score=0.96,
        supporting_evidence="High DNS query entropy: 4.33 bits (threshold: 3.60 bits); Abnormal lexical ratios: Consonant/Vowel 2.88, Numeric 0.48; DNS Tunnelling indicator: Record Type TXT, Query Length 68; Query 'dnscat.346b3776031bc35bb4bf086fe406e01f8b72f980308a4d0a.exfil-c2.net' not in top-domain trust allowlist",
        corroboration_count=5,
        persistence_windows=2,
        src_ip="192.168.1.105",
        dst_ip="8.8.8.8",
        host="192.168.1.105"
    )
    events.append((t5, "ALERT", alt_dga_1))

    # 2b. C2 check-in following DGA
    t6 = start_time + timedelta(seconds=75)
    alt_c2_2 = Alert(
        timestamp=t6,
        flow_identifier="192.168.1.105:51992->198.51.100.77:8080/TCP",
        threat_class=ThreatClass.C2_BEACONING,
        confidence_score=0.94,
        supporting_evidence="C2 check-in to dynamically resolved DGA rendezvous address; Periodicity delta 0.04s; Corroborated with preceding DNS TXT resolution",
        corroboration_count=3,
        persistence_windows=2,
        src_ip="192.168.1.105",
        dst_ip="198.51.100.77",
        host="192.168.1.105"
    )
    events.append((t6, "ALERT", alt_c2_2))

    # 3. Host C: 192.168.1.120 - Encrypted Malware (JA4 fingerprinted C2)
    t7 = start_time + timedelta(seconds=50)
    alt_malware_1 = Alert(
        timestamp=t7,
        flow_identifier="192.168.1.120:49200->104.244.42.1:443/TCP",
        threat_class=ThreatClass.ENCRYPTED_MALWARE,
        confidence_score=0.92,
        supporting_evidence="Anomalous JA4 TLS client fingerprint: t13d1516h2_8daaf6152771_b074a3875323 (known Cobalt Strike / Sliver staging profile); Self-signed untrusted CA cert; Non-standard cipher suite negotiation",
        corroboration_count=3,
        persistence_windows=2,
        src_ip="192.168.1.120",
        dst_ip="104.244.42.1",
        host="192.168.1.120"
    )
    events.append((t7, "ALERT", alt_malware_1))

    # 4. Host D: CTU-13 Real Neris Botnet Infiltration Activity
    t8 = start_time + timedelta(seconds=80)
    alt_neris_spam = Alert(
        timestamp=t8,
        flow_identifier="147.32.84.165:1087->210.55.230.7:25/TCP",
        threat_class=ThreatClass.PORT_SCANNING,
        confidence_score=0.89,
        supporting_evidence="Authentic CTU-13 Neris botnet flow: host 147.32.84.165 executing spam-module outbound activity targeting mail7.digitalwaves.co.nz MX host; Outbound port 25 fanout pattern detected",
        corroboration_count=3,
        persistence_windows=3,
        src_ip="147.32.84.165",
        dst_ip="210.55.230.7",
        host="147.32.84.165"
    )
    events.append((t8, "ALERT", alt_neris_spam))

    # 5. Additional Realistic Network Scan Probes
    for i, port in enumerate([21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 8080, 8443]):
        tp = start_time + timedelta(seconds=12 + i * 2)
        alt_probe = Alert(
            timestamp=tp,
            flow_identifier=f"192.168.1.77:{40000+i}->192.168.1.5:{port}/TCP",
            threat_class=ThreatClass.PORT_SCANNING,
            confidence_score=0.93,
            supporting_evidence=f"SYN stealth sweep targeting port {port}; Half-open connection ratio 1.0; Rapid vertical fan-out",
            corroboration_count=3,
            persistence_windows=2,
            src_ip="192.168.1.77",
            dst_ip="192.168.1.5",
            host="192.168.1.77"
        )
        events.append((tp, "ALERT", alt_probe))

    # 6. Additional DGA Tunnels
    for j in range(8):
        td = start_time + timedelta(seconds=38 + j * 4)
        alt_dga_extra = Alert(
            timestamp=td,
            flow_identifier=f"192.168.1.66:{50000+j}->8.8.8.8:53/UDP",
            threat_class=ThreatClass.DGA_TUNNELLING,
            confidence_score=0.95,
            supporting_evidence=f"DNS query entropy 4.{30+j} bits; Tunnel label length 64 bytes; TXT query 'dnscat.{j}a9f0e1.exfil-c2.net' to unlisted DGA domain",
            corroboration_count=4,
            persistence_windows=2,
            src_ip="192.168.1.66",
            dst_ip="8.8.8.8",
            host="192.168.1.66"
        )
        events.append((td, "ALERT", alt_dga_extra))

    # 7. Additional C2 Beacons across infected hosts
    for k in range(6):
        tc = start_time + timedelta(seconds=45 + k * 8)
        alt_c2_extra = Alert(
            timestamp=tc,
            flow_identifier=f"192.168.1.55:{45000+k}->147.32.84.180:80/TCP",
            threat_class=ThreatClass.C2_BEACONING,
            confidence_score=0.91,
            supporting_evidence=f"CTU-13 Neris C2 rendezvous beacon (nucleardiscover.com); Jitter index 0.0{k+1}s; Periodic interval 15.0s",
            corroboration_count=3,
            persistence_windows=2,
            src_ip="192.168.1.55",
            dst_ip="147.32.84.180",
            host="192.168.1.55"
        )
        events.append((tc, "ALERT", alt_c2_extra))

    # 8. Encrypted Malware Channels
    for m in range(4):
        tm = start_time + timedelta(seconds=55 + m * 7)
        alt_malware_extra = Alert(
            timestamp=tm,
            flow_identifier=f"192.168.1.120:{49300+m}->104.244.42.{m+2}:443/TCP",
            threat_class=ThreatClass.ENCRYPTED_MALWARE,
            confidence_score=0.90,
            supporting_evidence="Anomalous JA4 client fingerprint match t13d1516h2_8daaf6152771; TLS version mismatch (SSLv3/TLS1.0 legacy cipher downgrade attempt)",
            corroboration_count=3,
            persistence_windows=2,
            src_ip="192.168.1.120",
            dst_ip=f"104.244.42.{m+2}",
            host="192.168.1.120"
        )
        events.append((tm, "ALERT", alt_malware_extra))

    # Now let's run ChainMatcher across the alerts to produce correlated Incident records
    graph = EntityGraph()
    matcher = ChainMatcher(entity_graph=graph)
    
    # Sort alerts chronologically
    events.sort(key=lambda x: x[0])
    
    alerts_list = [e[2] for e in events if e[1] == "ALERT"]
    incidents = matcher.process_new_alerts(alerts_list)

    final_feed = []
    # Interleave incidents right after their constituent alerts occur
    # Find timestamp for each incident (e.g. at the time of its last constituent alert)
    incident_timestamps = {}
    for inc in incidents:
        incident_timestamps[inc.incident_id] = inc.last_seen + timedelta(seconds=1)

    for ts, ev_type, item in events:
        final_feed.append({"type": ev_type, "data": json.loads(item.model_dump_json()), "timestamp": ts.isoformat()})
        # Check if any incident completed at or right after this alert
        for inc in incidents:
            if inc.last_seen == item.timestamp:
                final_feed.append({
                    "type": "INCIDENT",
                    "data": json.loads(inc.model_dump_json()),
                    "timestamp": (inc.last_seen + timedelta(seconds=1)).isoformat()
                })

    out_file = "docs/sample_alert_feed.jsonl"
    with open(out_file, "w", encoding="utf-8") as f:
        for entry in final_feed:
            f.write(json.dumps(entry) + "\n")

    print(f"[+] Successfully wrote {len(final_feed)} entries ({len(alerts_list)} alerts, {len(incidents)} incidents) to {out_file}")

if __name__ == "__main__":
    build_curated_feed()
