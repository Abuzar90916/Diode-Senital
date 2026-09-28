"""
Benign Traffic Generator for Diode-Sentinel.
Generates realistic baseline normal traffic PCAPs for false-positive evaluation.
Synthesizes HTTP/HTTPS, DNS lookups to top domains, and background UDP/NTP flows.
Also produces sidecar ground-truth JSON metadata.
"""

import os
import json
import time
import random
from typing import List, Dict, Any

from scapy.config import conf
conf.verb = 0

from scapy.all import wrpcap, Ether, IP, TCP, UDP, DNS, DNSQR, DNSRR, Raw

def eth():
    return Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")


class BenignTrafficGenerator:
    """
    Synthesizes realistic benign network traffic PCAPs with ground truth.
    Provides baseline data for Person 3's ML false-positive rate minimization.
    """

    TOP_DOMAINS = [
        "google.com",
        "youtube.com",
        "wikipedia.org",
        "github.com",
        "microsoft.com",
        "cloudflare.com",
        "amazon.in",
        "ntro.gov.in",
        "python.org",
        "stackoverflow.com"
    ]

    def __init__(self, output_dir: str = "pcaps"):
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

    def _craft_dns_flow(self, client_ip: str, dns_server: str, domain: str, start_time: float) -> List[Any]:
        """Crafts a normal DNS query and response pair."""
        sport = random.randint(49152, 65535)
        txid = random.randint(1, 65535)

        # Query packet
        q_pkt = (
            eth() /
            IP(src=client_ip, dst=dns_server) /
            UDP(sport=sport, dport=53) /
            DNS(id=txid, qr=0, qd=DNSQR(qname=domain, qtype="A"))
        )
        q_pkt.time = start_time

        # Response packet (8ms later)
        r_pkt = (
            eth() /
            IP(src=dns_server, dst=client_ip) /
            UDP(sport=53, dport=sport) /
            DNS(id=txid, qr=1, qd=DNSQR(qname=domain, qtype="A"),
                an=DNSRR(rrname=domain, rdata="142.250.190.46", ttl=300))
        )
        r_pkt.time = start_time + random.uniform(0.005, 0.025)

        return [q_pkt, r_pkt]

    TLS_PROFILES = {
        "browser": {
            "ciphers": bytes([0x00, 0x08, 0xc0, 0x2f, 0xc0, 0x30, 0xcc, 0xa8, 0xcc, 0xa9]),
            "extensions": [bytes([0x00, 0x0a]), bytes([0x00, 0x0b])]  # supported groups, ec formats
        },
        "curl_cli": {
            "ciphers": bytes([0x00, 0x06, 0x13, 0x01, 0x13, 0x02, 0xc0, 0x2f]),
            "extensions": []
        },
        "python_requests": {
            "ciphers": bytes([0x00, 0x06, 0xc0, 0x2c, 0xc0, 0x30, 0x00, 0x9f]),
            "extensions": [bytes([0x00, 0x17])]  # extended master secret
        },
        "iot_agent": {
            "ciphers": bytes([0x00, 0x04, 0x00, 0x2f, 0x00, 0x35]),
            "extensions": []
        }
    }

    def _craft_tls_client_hello_payload(self, server_name: str, client_profile: str = "browser") -> bytes:
        """Constructs a realistic TLS 1.2 ClientHello with varied JA3 fingerprint by profile."""
        profile = self.TLS_PROFILES.get(client_profile, self.TLS_PROFILES["browser"])
        rec_header = bytes([0x16, 0x03, 0x03])
        rand_bytes = bytes([random.randint(0, 255) for _ in range(32)])
        
        sni_bytes = server_name.encode()
        sni_ext = (
            bytes([0x00, 0x00]) +
            (len(sni_bytes) + 5).to_bytes(2, "big") +
            (len(sni_bytes) + 3).to_bytes(2, "big") +
            bytes([0x00]) +
            len(sni_bytes).to_bytes(2, "big") +
            sni_bytes
        )
        
        ciphers = profile["ciphers"]
        comp = bytes([0x01, 0x00])
        
        all_ext_data = sni_ext
        for extra_ext in profile["extensions"]:
            all_ext_data += extra_ext + bytes([0x00, 0x02, 0x00, 0x01])
            
        extensions = (len(all_ext_data)).to_bytes(2, "big") + all_ext_data
        handshake = bytes([0x01]) + (38 + len(ciphers) + len(comp) + len(extensions)).to_bytes(3, "big") + bytes([0x03, 0x03]) + rand_bytes + bytes([0x00]) + ciphers + comp + extensions
        return rec_header + (len(handshake)).to_bytes(2, "big") + handshake

    def _craft_tcp_session(self, client_ip: str, server_ip: str, dport: int, start_time: float, is_tls: bool = False, server_name: str = "example.com", client_profile: str = "browser") -> List[Any]:
        """Crafts a complete benign TCP session (SYN, SYN-ACK, ACK, Data exchange, FIN)."""
        sport = random.randint(49152, 65535)
        client_seq = random.randint(10000, 50000)
        server_seq = random.randint(60000, 99990)
        pkts = []
        t = start_time

        # 1. TCP 3-Way Handshake
        # SYN
        p_syn = eth() / IP(src=client_ip, dst=server_ip) / TCP(sport=sport, dport=dport, flags="S", seq=client_seq)
        p_syn.time = t
        pkts.append(p_syn)
        client_seq += 1

        # SYN-ACK
        t += random.uniform(0.005, 0.015)
        p_synack = eth() / IP(src=server_ip, dst=client_ip) / TCP(sport=dport, dport=sport, flags="SA", seq=server_seq, ack=client_seq)
        p_synack.time = t
        pkts.append(p_synack)
        server_seq += 1

        # ACK
        t += random.uniform(0.001, 0.005)
        p_ack = eth() / IP(src=client_ip, dst=server_ip) / TCP(sport=sport, dport=dport, flags="A", seq=client_seq, ack=server_seq)
        p_ack.time = t
        pkts.append(p_ack)

        # 2. Data Transfer
        if is_tls:
            # ClientHello with specific client profile (JA3 diversity)
            tls_payload = self._craft_tls_client_hello_payload(server_name, client_profile=client_profile)
            t += random.uniform(0.002, 0.010)
            p_data = eth() / IP(src=client_ip, dst=server_ip) / TCP(sport=sport, dport=dport, flags="PA", seq=client_seq, ack=server_seq) / Raw(load=tls_payload)
            p_data.time = t
            pkts.append(p_data)
            client_seq += len(tls_payload)

            # Server Response (normal web browsing: inbound payload larger than outbound)
            t += random.uniform(0.010, 0.030)
            resp_payload = b"\x16\x03\x03\x00\x50" + b"\x02" + b"\x00" * 78  # ServerHello mock
            p_resp = eth() / IP(src=server_ip, dst=client_ip) / TCP(sport=dport, dport=sport, flags="PA", seq=server_seq, ack=client_seq) / Raw(load=resp_payload)
            p_resp.time = t
            pkts.append(p_resp)
            server_seq += len(resp_payload)
        else:
            # Benign HTTP GET
            http_req = f"GET / HTTP/1.1\r\nHost: {server_name}\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\n\r\n".encode()
            t += random.uniform(0.002, 0.010)
            p_data = eth() / IP(src=client_ip, dst=server_ip) / TCP(sport=sport, dport=dport, flags="PA", seq=client_seq, ack=server_seq) / Raw(load=http_req)
            p_data.time = t
            pkts.append(p_data)
            client_seq += len(http_req)

            # HTTP 200 OK Response
            http_resp = b"HTTP/1.1 200 OK\r\nContent-Length: 512\r\nContent-Type: text/html\r\n\r\n" + (b"<html><body>OK</body></html>" * 20)
            t += random.uniform(0.010, 0.030)
            p_resp = eth() / IP(src=server_ip, dst=client_ip) / TCP(sport=dport, dport=sport, flags="PA", seq=server_seq, ack=client_seq) / Raw(load=http_resp)
            p_resp.time = t
            pkts.append(p_resp)
            server_seq += len(http_resp)

        # 3. Connection Teardown (FIN-ACK)
        t += random.uniform(0.01, 0.05)
        p_fin = eth() / IP(src=client_ip, dst=server_ip) / TCP(sport=sport, dport=dport, flags="FA", seq=client_seq, ack=server_seq)
        p_fin.time = t
        pkts.append(p_fin)

        t += random.uniform(0.002, 0.01)
        p_finack = eth() / IP(src=server_ip, dst=client_ip) / TCP(sport=dport, dport=sport, flags="FA", seq=server_seq, ack=client_seq + 1)
        p_finack.time = t
        pkts.append(p_finack)

        return pkts

    def generate_steady_benign(self, filename: str = "benign_steady.pcap", num_sessions: int = 50) -> str:
        """Generates steady normal background traffic with Poisson arrival spacing."""
        all_packets = []
        base_time = time.time()
        curr_time = base_time

        client_ips = [f"192.168.10.{i}" for i in range(2, 10)]
        dns_server = "192.168.10.1"
        web_servers = ["142.250.190.46", "151.101.65.140", "104.18.26.120", "13.232.12.90"]

        flows_meta = []

        for _ in range(num_sessions):
            client = random.choice(client_ips)
            server = random.choice(web_servers)
            domain = random.choice(self.TOP_DOMAINS)

            # DNS resolution
            dns_pkts = self._craft_dns_flow(client, dns_server, domain, curr_time)
            all_packets.extend(dns_pkts)

            # HTTP or HTTPS session
            is_tls = random.choice([True, True, False])
            dport = 443 if is_tls else 80
            profile = random.choice(list(self.TLS_PROFILES.keys()))
            sess_pkts = self._craft_tcp_session(client, server, dport, curr_time + 0.05, is_tls=is_tls, server_name=domain, client_profile=profile)
            all_packets.extend(sess_pkts)

            flows_meta.append({
                "client": client,
                "server": server,
                "domain": domain,
                "protocol": "TLS" if is_tls else "HTTP",
                "tls_profile": profile if is_tls else "none",
                "start_time": curr_time
            })

            # Poisson arrival spacing between distinct user sessions
            curr_time += random.expovariate(2.0)  # average 0.5s inter-session arrival

        # Sort all packets strictly by timestamp
        all_packets.sort(key=lambda p: float(p.time))

        pcap_path = os.path.join(self.output_dir, filename)
        wrpcap(pcap_path, all_packets)

        # Write ground-truth sidecar JSON
        sidecar_path = os.path.join(self.output_dir, filename.replace(".pcap", ".json"))
        sidecar_data = {
            "pcap_file": filename,
            "label": "benign",
            "threat_class": "none",
            "total_packets": len(all_packets),
            "duration_sec": round(curr_time - base_time, 2),
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "sessions_count": len(flows_meta),
            "flows": flows_meta
        }
        with open(sidecar_path, "w", encoding="utf-8") as f:
            json.dump(sidecar_data, f, indent=2)

        return pcap_path

    def generate_bursty_benign(self, filename: str = "benign_bursty.pcap", num_bursts: int = 5) -> str:
        """Generates bursty daytime web browsing patterns with variable load and varied JA3."""
        all_packets = []
        base_time = time.time()
        curr_time = base_time

        client_ips = [f"10.0.1.{i}" for i in range(20, 60)]
        dns_server = "10.0.1.1"

        for b in range(num_bursts):
            # Dense burst of concurrent requests
            burst_size = random.randint(15, 30)
            for _ in range(burst_size):
                client = random.choice(client_ips)
                server = f"172.217.16.{random.randint(1, 254)}"
                domain = random.choice(self.TOP_DOMAINS)
                t_offset = random.uniform(0.0, 0.5)
                profile = random.choice(list(self.TLS_PROFILES.keys()))

                all_packets.extend(self._craft_dns_flow(client, dns_server, domain, curr_time + t_offset))
                all_packets.extend(self._craft_tcp_session(client, server, 443, curr_time + t_offset + 0.02, is_tls=True, server_name=domain, client_profile=profile))

            # Quiet gap between bursts
            curr_time += random.uniform(3.0, 7.0)

        all_packets.sort(key=lambda p: float(p.time))
        pcap_path = os.path.join(self.output_dir, filename)
        wrpcap(pcap_path, all_packets)

        sidecar_path = os.path.join(self.output_dir, filename.replace(".pcap", ".json"))
        with open(sidecar_path, "w", encoding="utf-8") as f:
            json.dump({
                "pcap_file": filename,
                "label": "benign",
                "threat_class": "none",
                "traffic_pattern": "bursty",
                "total_packets": len(all_packets),
                "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            }, f, indent=2)

        return pcap_path

    def generate_periodic_heartbeats(self, filename: str = "benign_periodic_heartbeat.pcap", duration_sec: float = 60.0) -> str:
        """
        Generates legitimate benign periodic heartbeat traffic (NTP, monitoring agents, auto-updaters).
        Tests that Person 3's C2 beacon detector does NOT produce false positives on regular benign pings.
        """
        all_packets = []
        base_time = time.time()

        # 1. NTP Sync: 192.168.10.15 -> 162.159.200.1:123 (pool.ntp.org) every 8.0s
        ntp_interval = 8.0
        ntp_t = base_time
        sport_ntp = random.randint(50000, 60000)
        while ntp_t < base_time + duration_sec:
            # Client NTP request (48 bytes)
            req = eth() / IP(src="192.168.10.15", dst="162.159.200.1") / UDP(sport=sport_ntp, dport=123) / Raw(load=b"\x1b" + b"\x00" * 47)
            req.time = ntp_t + random.uniform(-0.02, 0.02)
            # Server NTP reply (48 bytes)
            resp = eth() / IP(src="162.159.200.1", dst="192.168.10.15") / UDP(sport=123, dport=sport_ntp) / Raw(load=b"\x1c" + b"\x00" * 47)
            resp.time = req.time + 0.015 + random.uniform(0.001, 0.005)
            all_packets.extend([req, resp])
            ntp_t += ntp_interval

        # 2. Monitoring Agent Heartbeat: 192.168.10.20 -> 192.168.10.100:443 every 5.0s (Prometheus/Datadog agent)
        agent_interval = 5.0
        agent_t = base_time + 1.0
        while agent_t < base_time + duration_sec:
            pkts = self._craft_tcp_session("192.168.10.20", "192.168.10.100", 443, agent_t, is_tls=True, server_name="metrics.internal.local", client_profile="iot_agent")
            all_packets.extend(pkts)
            agent_t += agent_interval + random.uniform(-0.05, 0.05)

        # 3. OS Auto-Update Checker: 192.168.10.25 -> 13.107.4.52:443 every 15.0s
        update_interval = 15.0
        update_t = base_time + 2.0
        while update_t < base_time + duration_sec:
            pkts = self._craft_tcp_session("192.168.10.25", "13.107.4.52", 443, update_t, is_tls=True, server_name="update.microsoft.com", client_profile="curl_cli")
            all_packets.extend(pkts)
            update_t += update_interval + random.uniform(-0.1, 0.1)

        all_packets.sort(key=lambda p: float(p.time))
        pcap_path = os.path.join(self.output_dir, filename)
        wrpcap(pcap_path, all_packets)

        sidecar_path = os.path.join(self.output_dir, filename.replace(".pcap", ".json"))
        with open(sidecar_path, "w", encoding="utf-8") as f:
            json.dump({
                "pcap_file": filename,
                "label": "benign",
                "threat_class": "none",
                "traffic_pattern": "periodic_heartbeats",
                "description": "Legitimate NTP (123/UDP), agent health check (443/TCP), and OS auto-updater pings",
                "total_packets": len(all_packets),
                "duration_sec": duration_sec,
                "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            }, f, indent=2)

        return pcap_path

    def generate_backup_upload(self, filename: str = "benign_backup_upload.pcap", total_chunks: int = 250) -> str:
        """
        Generates legitimate scheduled backup / bulk upload session.
        High outbound volume and high byte ratio, but clean TCP state machine and standard windowing.
        Tests that Person 3's exfil detector uses host baseline / destination ASN rather than raw byte threshold.
        """
        all_packets = []
        base_time = time.time()
        client_ip = "192.168.10.40"
        backup_server = "52.216.100.1"  # AWS S3 range (ASN 16509)
        sport = random.randint(50000, 60000)
        dport = 443
        client_seq = 10000
        server_seq = 50000
        t = base_time

        # TCP 3-Way Handshake
        p_syn = eth() / IP(src=client_ip, dst=backup_server) / TCP(sport=sport, dport=dport, flags="S", seq=client_seq)
        p_syn.time = t
        client_seq += 1
        t += 0.015
        p_synack = eth() / IP(src=backup_server, dst=client_ip) / TCP(sport=dport, dport=sport, flags="SA", seq=server_seq, ack=client_seq)
        p_synack.time = t
        server_seq += 1
        t += 0.002
        p_ack = eth() / IP(src=client_ip, dst=backup_server) / TCP(sport=sport, dport=dport, flags="A", seq=client_seq, ack=server_seq)
        p_ack.time = t
        all_packets.extend([p_syn, p_synack, p_ack])

        # Large bulk upload in 1400-byte segments with standard delayed TCP ACKs
        chunk_size = 1400
        dummy_chunk = b"B" * chunk_size
        for i in range(total_chunks):
            t += random.uniform(0.001, 0.004)
            p_data = eth() / IP(src=client_ip, dst=backup_server) / TCP(sport=sport, dport=dport, flags="PA", seq=client_seq, ack=server_seq) / Raw(load=dummy_chunk)
            p_data.time = t
            all_packets.append(p_data)
            client_seq += chunk_size

            # Server ACK every 2 segments
            if (i + 1) % 2 == 0:
                t += 0.001
                p_ack = eth() / IP(src=backup_server, dst=client_ip) / TCP(sport=dport, dport=sport, flags="A", seq=server_seq, ack=client_seq)
                p_ack.time = t
                all_packets.append(p_ack)

        # Connection teardown (FIN-ACK)
        t += 0.02
        p_fin = eth() / IP(src=client_ip, dst=backup_server) / TCP(sport=sport, dport=dport, flags="FA", seq=client_seq, ack=server_seq)
        p_fin.time = t
        all_packets.append(p_fin)
        client_seq += 1
        t += 0.015
        p_finack = eth() / IP(src=backup_server, dst=client_ip) / TCP(sport=dport, dport=sport, flags="FA", seq=server_seq, ack=client_seq)
        p_finack.time = t
        all_packets.append(p_finack)

        all_packets.sort(key=lambda p: float(p.time))
        pcap_path = os.path.join(self.output_dir, filename)
        wrpcap(pcap_path, all_packets)

        sidecar_path = os.path.join(self.output_dir, filename.replace(".pcap", ".json"))
        with open(sidecar_path, "w", encoding="utf-8") as f:
            json.dump({
                "pcap_file": filename,
                "label": "benign",
                "threat_class": "none",
                "traffic_pattern": "scheduled_backup_upload",
                "description": "Legitimate enterprise high-volume backup upload to Amazon S3 (ASN 16509)",
                "total_packets": len(all_packets),
                "total_outbound_bytes": total_chunks * chunk_size,
                "duration_sec": round(t - base_time, 2),
                "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            }, f, indent=2)

        return pcap_path

    def generate_vulnerability_scanner(self, filename: str = "benign_vulnerability_scanner.pcap") -> str:
        """
        Generates authorized internal vulnerability scanner traffic (Qualys/Nessus fanout).
        Tests that Person 3's port-scan detector supports an appliance allowlist or scanner behavioral tag.
        """
        all_packets = []
        base_time = time.time()
        scanner_ip = "192.168.10.250"  # Authorized internal vulnerability scanner
        internal_targets = [f"192.168.10.{i}" for i in range(2, 12)]
        ports_to_scan = [21, 22, 25, 80, 443, 8080, 8443, 3389, 445, 1433, 3306, 8000, 9200]

        t = base_time
        for target in internal_targets:
            for dport in ports_to_scan:
                sport = random.randint(40000, 65000)
                seq = random.randint(1000, 90000)
                
                # Scanner SYN probe
                p_syn = eth() / IP(src=scanner_ip, dst=target) / TCP(sport=sport, dport=dport, flags="S", seq=seq)
                p_syn.time = t
                all_packets.append(p_syn)
                
                # Mock response: closed ports reply with RST, web ports (80, 443, 8080) reply with SYN-ACK
                t_resp = t + random.uniform(0.001, 0.004)
                if dport in (80, 443, 8080):
                    p_synack = eth() / IP(src=target, dst=scanner_ip) / TCP(sport=dport, dport=sport, flags="SA", seq=1000, ack=seq+1)
                    p_synack.time = t_resp
                    all_packets.append(p_synack)
                    # Scanner immediately sends RST to close probe cleanly
                    p_rst = eth() / IP(src=scanner_ip, dst=target) / TCP(sport=sport, dport=dport, flags="R", seq=seq+1)
                    p_rst.time = t_resp + 0.001
                    all_packets.append(p_rst)
                else:
                    p_rst = eth() / IP(src=target, dst=scanner_ip) / TCP(sport=dport, dport=sport, flags="RA", seq=0, ack=seq+1)
                    p_rst.time = t_resp
                    all_packets.append(p_rst)

                t += random.uniform(0.005, 0.015)

        all_packets.sort(key=lambda p: float(p.time))
        pcap_path = os.path.join(self.output_dir, filename)
        wrpcap(pcap_path, all_packets)

        sidecar_path = os.path.join(self.output_dir, filename.replace(".pcap", ".json"))
        with open(sidecar_path, "w", encoding="utf-8") as f:
            json.dump({
                "pcap_file": filename,
                "label": "benign",
                "threat_class": "none",
                "traffic_pattern": "vulnerability_scanner",
                "description": "Authorized internal security appliance (192.168.10.250) vulnerability sweep",
                "scanner_ip": scanner_ip,
                "targets_count": len(internal_targets),
                "ports_scanned_count": len(ports_to_scan),
                "total_packets": len(all_packets),
                "duration_sec": round(t - base_time, 2),
                "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            }, f, indent=2)

        return pcap_path


if __name__ == "__main__":
    out_dir = os.path.join(os.path.dirname(__file__), "pcaps")
    gen = BenignTrafficGenerator(output_dir=out_dir)
    print("[+] Generating enhanced benign datasets...")
    p1 = gen.generate_steady_benign()
    print(f"    - Steady: {p1}")
    p2 = gen.generate_bursty_benign()
    print(f"    - Bursty: {p2}")
    p3 = gen.generate_periodic_heartbeats()
    print(f"    - Periodic Heartbeats (NTP/Agents): {p3}")
    p4 = gen.generate_backup_upload()
    print(f"    - Scheduled Backup Upload: {p4}")
    p5 = gen.generate_vulnerability_scanner()
    print(f"    - Vulnerability Scanner (Qualys/Nessus): {p5}")
    print("[+] All 5 benign PCAP datasets generated successfully.")
