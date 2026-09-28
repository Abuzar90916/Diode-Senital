"""
Attack Traffic Generator for Diode-Sentinel.
Generates labeled PCAPs for all six NTRO threat classes (a through f)
along with ground-truth sidecar JSONs for Person 3's ML training and evaluation.
"""

import os
import json
import time
import random
import string
from typing import List, Dict, Any

from scapy.config import conf
conf.verb = 0

from scapy.all import wrpcap, Ether, IP, TCP, UDP, DNS, DNSQR, Raw

def eth():
    return Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")


class AttackTrafficGenerator:
    """
    Synthesizes labeled attack PCAPs matching the six NTRO threat categories.
    """

    def __init__(self, output_dir: str = "pcaps"):
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

    # -------------------------------------------------------------------------
    # (a) Volumetric / Protocol DDoS: SYN Flood + Spoofed Sources
    # -------------------------------------------------------------------------
    def generate_ddos_syn_flood(self, filename: str = "attack_ddos_syn.pcap", num_packets: int = 1000) -> str:
        """
        Synthesizes a distributed SYN flood with spoofed source IPs (high entropy)
        targeting a single protected gateway service.
        """
        packets = []
        base_time = time.time()
        victim_ip = "192.168.1.100"
        victim_port = 80

        # Simulate 100 spoofed source IPs across disparate subnets
        spoofed_ips = [f"{random.randint(11, 200)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}" for _ in range(100)]

        # Distribute SYN flood bursts across >=42 seconds to naturally span 3+ sliding windows
        duration_sec = 42.0
        for i in range(num_packets):
            src_ip = random.choice(spoofed_ips)
            sport = random.randint(1024, 65535)
            # High rate packets distributed over duration
            t = base_time + (i / float(num_packets)) * duration_sec
            pkt = eth() / IP(src=src_ip, dst=victim_ip) / TCP(sport=sport, dport=victim_port, flags="S", seq=random.randint(1000, 999999))
            pkt.time = t
            packets.append(pkt)

        pcap_path = os.path.join(self.output_dir, filename)
        wrpcap(pcap_path, packets)

        sidecar = {
            "pcap_file": filename,
            "threat_class": "a_volumetric_ddos",
            "attack_type": "SYN_flood_spoofed_source",
            "victim_ip": victim_ip,
            "victim_port": victim_port,
            "total_packets": len(packets),
            "expected_entropy": ">4.0",
            "expected_syn_ack_ratio": ">100.0",
        }
        with open(os.path.join(self.output_dir, filename.replace(".pcap", ".json")), "w") as f:
            json.dump(sidecar, f, indent=2)

        return pcap_path

    # -------------------------------------------------------------------------
    # (b) Botnet C2 Beaconing: Periodic Heartbeats with Jitter
    # -------------------------------------------------------------------------
    def generate_c2_beacon(self, filename: str = "attack_c2_beacon.pcap", num_beacons: int = 40, interval_sec: float = 3.0) -> str:
        """
        Synthesizes periodic C2 beaconing with low inter-arrival variance and subtle jitter
        over a persistent command-and-control connection.
        """
        packets = []
        base_time = time.time()
        bot_ip = "192.168.1.45"
        c2_ip = "45.33.32.156"
        c2_port = 8443
        sport = 51200
        curr_time = base_time

        # Initial handshake
        p1 = eth() / IP(src=bot_ip, dst=c2_ip) / TCP(sport=sport, dport=c2_port, flags="S", seq=100)
        p1.time = curr_time
        p2 = eth() / IP(src=c2_ip, dst=bot_ip) / TCP(sport=c2_port, dport=sport, flags="SA", seq=200, ack=101)
        p2.time = curr_time + 0.01
        p3 = eth() / IP(src=bot_ip, dst=c2_ip) / TCP(sport=sport, dport=c2_port, flags="A", seq=101, ack=201)
        p3.time = curr_time + 0.02
        packets.extend([p1, p2, p3])

        client_seq = 101
        for b in range(num_beacons):
            curr_time += interval_sec
            jitter = random.uniform(-interval_sec * 0.05, interval_sec * 0.05)
            t = curr_time + jitter

            p_ping = eth() / IP(src=bot_ip, dst=c2_ip) / TCP(sport=sport, dport=c2_port, flags="PA", seq=client_seq, ack=201) / Raw(load=b"BEACON_ID=9812_STATUS=IDLE\n")
            p_ping.time = t
            client_seq += 26
            packets.append(p_ping)

        pcap_path = os.path.join(self.output_dir, filename)
        wrpcap(pcap_path, packets)

        sidecar = {
            "pcap_file": filename,
            "threat_class": "b_c2_beaconing",
            "bot_ip": bot_ip,
            "c2_ip": c2_ip,
            "interval_sec": interval_sec,
            "beacons_count": num_beacons,
            "expected_iat_cv": "<0.15",
            "expected_periodicity_score": ">0.75"
        }
        with open(os.path.join(self.output_dir, filename.replace(".pcap", ".json")), "w") as f:
            json.dump(sidecar, f, indent=2)

        return pcap_path

    # -------------------------------------------------------------------------
    # (c) DGA Domains and DNS Tunnelling (dnscat2 / iodine simulation)
    # -------------------------------------------------------------------------
    def generate_dga_and_tunnel(self, filename: str = "attack_dga.pcap", num_queries: int = 50) -> str:
        """
        Synthesizes high-entropy DGA queries and long base64 TXT tunnel exfiltration packets.
        """
        packets = []
        base_time = time.time()
        client_ip = "192.168.1.66"
        dns_server = "8.8.8.8"
        t = base_time

        dga_names = []
        tunnel_names = []

        # 1. DGA generation (algorithmic high entropy)
        for i in range(num_queries // 2):
            # Random string with high consonant density
            random_str = "".join(random.choices(string.ascii_lowercase + "0123456789", k=18))
            dga_domain = f"{random_str}.biz"
            dga_names.append(dga_domain)

            pkt = eth() / IP(src=client_ip, dst=dns_server) / UDP(sport=random.randint(40000, 60000), dport=53) / DNS(id=i, qr=0, qd=DNSQR(qname=dga_domain, qtype="A"))
            pkt.time = t
            packets.append(pkt)
            t += random.uniform(0.1, 0.3)

        # 2. DNS Tunneling (dnscat2 / iodine emulation)
        for i in range(num_queries // 2):
            hex_data = "".join(random.choices("0123456789abcdef", k=48))
            tunnel_domain = f"dnscat.{hex_data}.exfil-c2.net"
            tunnel_names.append(tunnel_domain)

            # TXT record query carrying encoded data chunk
            pkt = eth() / IP(src=client_ip, dst=dns_server) / UDP(sport=random.randint(40000, 60000), dport=53) / DNS(id=1000 + i, qr=0, qd=DNSQR(qname=tunnel_domain, qtype="TXT"))
            pkt.time = t
            packets.append(pkt)
            t += random.uniform(0.05, 0.15)

        pcap_path = os.path.join(self.output_dir, filename)
        wrpcap(pcap_path, packets)

        sidecar = {
            "pcap_file": filename,
            "threat_class": "c_dga_dns_tunnel",
            "dga_samples": dga_names[:5],
            "tunnel_samples": tunnel_names[:5],
            "expected_entropy": ">3.8",
            "expected_tunnel_flag": True
        }
        with open(os.path.join(self.output_dir, filename.replace(".pcap", ".json")), "w") as f:
            json.dump(sidecar, f, indent=2)

        return pcap_path

    # -------------------------------------------------------------------------
    # (d) Malware inside Encrypted Sessions (Suspicious JA3 & Biometric PZX)
    # -------------------------------------------------------------------------
    def generate_encrypted_malware(self, filename: str = "attack_encrypted_malware.pcap", num_sessions: int = 10) -> str:
        """
        Synthesizes TLS sessions exhibiting known malicious ClientHello profiles
        (Cobalt Strike / Meterpreter cipher suites) and distinctive packet-size sequences.
        """
        packets = []
        base_time = time.time()
        client_ip = "192.168.1.80"
        c2_ip = "185.220.101.5"
        curr_time = base_time

        # Craft malicious TLS ClientHello with distinctive ciphers (e.g. Cobalt Strike default profile)
        for s in range(num_sessions):
            sport = 55000 + s
            t = curr_time

            # Handshake
            p_syn = eth() / IP(src=client_ip, dst=c2_ip) / TCP(sport=sport, dport=443, flags="S", seq=1000)
            p_syn.time = t
            p_synack = eth() / IP(src=c2_ip, dst=client_ip) / TCP(sport=443, dport=sport, flags="SA", seq=5000, ack=1001)
            p_synack.time = t + 0.01
            p_ack = eth() / IP(src=client_ip, dst=c2_ip) / TCP(sport=sport, dport=443, flags="A", seq=1001, ack=5001)
            p_ack.time = t + 0.02
            packets.extend([p_syn, p_synack, p_ack])

            # ClientHello with specific old/malicious cipher suites (RC4 / 3DES / static ECDH)
            rand_bytes = bytes([0xAA] * 32)
            ciphers = bytes([0x00, 0x06, 0x00, 0x05, 0x00, 0x0a, 0xc0, 0x11]) # RC4-SHA, 3DES, ECDHE-RSA-RC4
            comp = bytes([0x01, 0x00])
            exts = bytes([0x00, 0x00]) # No extensions
            handshake = bytes([0x01]) + (38 + len(ciphers) + len(comp) + len(exts)).to_bytes(3, "big") + bytes([0x03, 0x01]) + rand_bytes + bytes([0x00]) + ciphers + comp + exts
            rec = bytes([0x16, 0x03, 0x01]) + len(handshake).to_bytes(2, "big") + handshake

            p_ch = eth() / IP(src=client_ip, dst=c2_ip) / TCP(sport=sport, dport=443, flags="PA", seq=1001, ack=5001) / Raw(load=rec)
            p_ch.time = t + 0.03
            packets.append(p_ch)

            # Malware traffic biometric: distinctive packet size sequence (e.g. 512, 1024, 256)
            for p_size in [512, 1024, 256, 128]:
                t += 0.05
                p_data = eth() / IP(src=client_ip, dst=c2_ip) / TCP(sport=sport, dport=443, flags="PA", seq=2000, ack=5001) / Raw(load=b"X" * p_size)
                p_data.time = t
                packets.append(p_data)

            curr_time += 1.0

        pcap_path = os.path.join(self.output_dir, filename)
        wrpcap(pcap_path, packets)

        sidecar = {
            "pcap_file": filename,
            "threat_class": "d_encrypted_malware",
            "client_ip": client_ip,
            "c2_ip": c2_ip,
            "signature": "CobaltStrike_Legacy_RC4_JA3",
            "expected_pzx_sequence": [512, 1024, 256, 128]
        }
        with open(os.path.join(self.output_dir, filename.replace(".pcap", ".json")), "w") as f:
            json.dump(sidecar, f, indent=2)

        return pcap_path

    # -------------------------------------------------------------------------
    # (e) Reconnaissance and Port Scanning
    # -------------------------------------------------------------------------
    def generate_port_scan(self, filename: str = "attack_portscan.pcap", num_ports: int = 150) -> str:
        """
        Synthesizes both vertical port scan and horizontal subnet sweep (Nmap SYN stealth scan).
        """
        packets = []
        base_time = time.time()
        scanner_ip = "192.168.1.77"
        target_host = "192.168.1.5"
        t = base_time

        # Distribute port scan probes across >=42 seconds in repeated waves (multi-window persistence)
        wave_intervals = [0.0, 7.0, 14.0, 21.0, 28.0, 35.0, 42.0]
        ports_per_wave = max(10, num_ports // len(wave_intervals))
        
        for w_idx, wave_offset in enumerate(wave_intervals):
            wave_time = base_time + wave_offset
            # Vertical probes for this wave
            start_p = 20 + (w_idx * ports_per_wave) % num_ports
            for p_offset in range(ports_per_wave):
                p = start_p + p_offset
                pkt = eth() / IP(src=scanner_ip, dst=target_host) / TCP(sport=random.randint(40000, 60000), dport=p, flags="S")
                pkt.time = wave_time + (p_offset * 0.01)
                packets.append(pkt)
            
            # Horizontal sweep slice for this wave
            h_start = 1 + (w_idx * 7) % 50
            for h_offset in range(7):
                h = (h_start + h_offset) % 50 + 1
                dst_ip = f"192.168.1.{h}"
                pkt = eth() / IP(src=scanner_ip, dst=dst_ip) / TCP(sport=random.randint(40000, 60000), dport=445, flags="S")
                pkt.time = wave_time + 0.15 + (h_offset * 0.01)
                packets.append(pkt)

        pcap_path = os.path.join(self.output_dir, filename)
        wrpcap(pcap_path, packets)

        sidecar = {
            "pcap_file": filename,
            "threat_class": "e_recon_port_scan",
            "scanner_ip": scanner_ip,
            "vertical_target": target_host,
            "vertical_ports_probed": num_ports,
            "horizontal_targets_count": 50,
            "expected_scan_rate": ">50 pps",
            "expected_half_open_ratio": "1.0"
        }
        with open(os.path.join(self.output_dir, filename.replace(".pcap", ".json")), "w") as f:
            json.dump(sidecar, f, indent=2)

        return pcap_path

    # -------------------------------------------------------------------------
    # (f) Data Exfiltration: Extreme Outbound Asymmetry
    # -------------------------------------------------------------------------
    def generate_data_exfiltration(self, filename: str = "attack_exfil.pcap", num_chunks: int = 100) -> str:
        """
        Synthesizes a massive outbound data exfiltration upload with extreme
        outbound-to-inbound byte ratio (>25:1).
        """
        packets = []
        base_time = time.time()
        insider_ip = "192.168.1.99"
        drop_server = "198.51.100.88"
        drop_port = 443
        sport = 52345
        t = base_time

        # TCP Handshake
        p_syn = eth() / IP(src=insider_ip, dst=drop_server) / TCP(sport=sport, dport=drop_port, flags="S", seq=100)
        p_syn.time = t
        p_synack = eth() / IP(src=drop_server, dst=insider_ip) / TCP(sport=drop_port, dport=sport, flags="SA", seq=500, ack=101)
        p_synack.time = t + 0.01
        p_ack = eth() / IP(src=insider_ip, dst=drop_server) / TCP(sport=sport, dport=drop_port, flags="A", seq=101, ack=501)
        p_ack.time = t + 0.02
        packets.extend([p_syn, p_synack, p_ack])

        client_seq = 101
        server_ack = 501

        # Bulk upload sustained across >=42 seconds to naturally span 3+ sliding windows
        duration_sec = 42.0
        total_chunks = max(num_chunks, 200)
        for i in range(total_chunks):
            payload = b"A" * 1400
            t = base_time + (i / float(total_chunks)) * duration_sec
            p_data = eth() / IP(src=insider_ip, dst=drop_server) / TCP(sport=sport, dport=drop_port, flags="PA", seq=client_seq, ack=server_ack) / Raw(load=payload)
            p_data.time = t
            packets.append(p_data)
            client_seq += len(payload)

            # Inbound acknowledgment only every 10 packets (delayed ACK)
            if i % 10 == 0:
                p_ack_in = eth() / IP(src=drop_server, dst=insider_ip) / TCP(sport=drop_port, dport=sport, flags="A", seq=server_ack, ack=client_seq)
                p_ack_in.time = t + 0.001
                packets.append(p_ack_in)

        pcap_path = os.path.join(self.output_dir, filename)
        wrpcap(pcap_path, packets)

        sidecar = {
            "pcap_file": filename,
            "threat_class": "f_data_exfiltration",
            "insider_ip": insider_ip,
            "drop_server": drop_server,
            "total_outbound_bytes": num_chunks * 1400,
            "expected_byte_ratio": ">20.0",
            "expected_exfil_score": ">0.8"
        }
        with open(os.path.join(self.output_dir, filename.replace(".pcap", ".json")), "w") as f:
            json.dump(sidecar, f, indent=2)

        return pcap_path

    def generate_all_attacks(self) -> Dict[str, str]:
        """Generates the complete suite of 6 attack PCAPs."""
        return {
            "ddos_syn": self.generate_ddos_syn_flood(),
            "c2_beacon": self.generate_c2_beacon(),
            "dga_tunnel": self.generate_dga_and_tunnel(),
            "encrypted_malware": self.generate_encrypted_malware(),
            "port_scan": self.generate_port_scan(),
            "data_exfil": self.generate_data_exfiltration()
        }


if __name__ == "__main__":
    gen = AttackTrafficGenerator(output_dir="pcaps")
    paths = gen.generate_all_attacks()
    for threat, path in paths.items():
        print(f"Generated {threat}: {path}")
