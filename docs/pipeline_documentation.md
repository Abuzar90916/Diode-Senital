# Diode-Sentinel: Technical Pipeline Documentation
**System Architecture, Zero-Egress Diode Compliance, Feature Mathematics, and Data Synthesis**  
*National Technical Research Organisation (NTRO) — Problem Statement 26145*  
**Authors**: Person 1 (Infrastructure & Compliance) & Person 2 (Ingestion & Feature Engineering)  
**Contract Version**: `FlowFeatureRecord v1.0 (FROZEN)`  

---

## Executive Summary

Critical infrastructure operators isolate monitoring systems behind hardware data diodes or passive optical taps that mirror unidirectional IP traffic into an analytical enclave. While physical or protocol-level isolation eliminates the enclave as an attack vector into the production core, it imposes strict operational constraints: **the intelligence layer must derive high-fidelity threat detection purely from passive, unprobed network observations without ever transmitting a single packet or decrypting payload contents**.

**Diode-Sentinel** is a production-grade, memory-bounded, zero-egress threat detection and feature extraction engine built specifically for unidirectional enclave monitoring. This document details the engineering specifications, mathematical formulations, architectural safeguards, and synthetic traffic models governing the system.

```mermaid
flowchart LR
    subgraph Production Network
        CoreRouter["Core Gateway / Switch"]
        TAP["Passive Optical TAP / Span Port"]
        CoreRouter --> TAP
    end

    subgraph Hardware Boundary
        Diode["Hardware Data Diode (Tx Only -> Rx Only)"]
        TAP --> Diode
    end

    subgraph Monitored Enclave
        Diode --> Sniffer["Promiscuous Sniffer / PcapReader"]
        Watchdog["Dual-Check Compliance Watchdog"]
        Watchdog -.-> Sniffer
        
        Sniffer --> Aggregator["Sliding-Window Flow Engine"]
        Context["Windowed GlobalContext (TTL Purge)"] <--> Aggregator
        
        Aggregator --> F1["Volumetric Engine (DDoS)"]
        Aggregator --> F2["Timing Engine (C2)"]
        Aggregator --> F3["DNS Engine (DGA/Tunnels)"]
        Aggregator --> F4["Crypto Engine (JA3/PZX)"]
        Aggregator --> F5["Fanout Engine (Recon)"]
        Aggregator --> F6["Asymmetry Engine (Exfil)"]
        
        F1 & F2 & F3 & F4 & F5 & F6 --> Contract["FlowFeatureRecord JSONL (Frozen)"]
        Contract --> Person3["Person 3: ThreatCore AI/ML"]
        Contract --> Person4["Person 4: SecOps Dashboard"]
    end
```

---

## Section 1: System Architecture & Zero-Egress Diode Compliance

### 1.1 The Diode Constraint & Optical Mirroring Model
A common misconception in diode environments is that unidirectional capture means the monitored traffic itself is half-duplex. In reality:
- **Full-Duplex Source Traffic**: Gateway optical TAPs mirror *both* transmission legs (client $\leftrightarrow$ server) into the diode.
- **Unidirectional Enclave Input**: The physical diode carries both legs forward into the capture NIC of the monitoring enclave.
- **Zero Reverse Path**: The capture NIC inside the enclave has its physical TX pair disconnected, or its MAC driver configured with TX queues disabled.

The enclave can passively observe complete bidirectional TCP sessions and DNS request-response pairs, but **it cannot transmit an ARP request, TCP ACK, ICMP reply, or active probe**. If an analytical module attempts an outbound transmission, it violates the core physical security guarantee.

### 1.2 Dual-Check Diode Compliance Watchdog (`diode_compliance.py`)
To prevent accidental egress (e.g. library calls attempting DNS PTR lookups, GeoIP web queries, or raw socket writes), Diode-Sentinel implements a continuous **dual-check background watchdog**:

1. **Level 1 Check — Process Socket Table Audit**:
   - Inspects OS kernel connection tables via `psutil.Process().net_connections(kind="inet")`.
   - Asserts that zero non-loopback sockets are in `SYN_SENT`, `ESTABLISHED`, or active outbound states.
2. **Level 2 Check — Interface Kernel I/O Delta Monitoring**:
   - Polls interface-level kernel counters via `psutil.net_io_counters(pernic=True)`.
   - Computes $\Delta \text{bytes\_sent} = \text{bytes\_sent}(t) - \text{bytes\_sent}(t_0)$ on the capture NIC.
   - **Catches raw-socket writes** (e.g., `scapy.sendp()` or raw `AF_PACKET` writes) that bypass standard TCP/UDP socket tables.

```
+-------------------------------------------------------------------------+
|                  DIODE COMPLIANCE WATCHDOG DUAL CHECK                   |
+-------------------------------------------------------------------------+
| Level 1: Socket Table      | Proc net_connections() == 0 remote sockets |
| Level 2: Kernel NIC I/O    | Interface bytes_sent delta == 0 bytes      |
| Enforcement Mode           | Fail-Closed (DiodeComplianceViolationError)|
+-------------------------------------------------------------------------+
```

### 1.3 Offline In-Memory Metadata Enrichment (`features/offline_asn.py`)
Enrichment metadata (`src_asn`, `dst_asn`, `src_country`, `dst_country`) is critical for Person 3's destination-rarity scoring. To maintain strict zero-egress compliance:
- **Zero Live Lookups**: Web-service GeoIP calls and DNS PTR requests are physically prohibited.
- **In-Memory Prefix Radix Matching**: IP addresses are evaluated entirely in RAM against pre-loaded local prefix tables (`OfflineAsnResolver`). Private RFC 1918 subnets map to `ASN 0 ("PRIVATE")`, and public CIDRs resolve in $\mathcal{O}(1)$ prefix trie lookups.
- **Coverage Limits & Null Handling**: The lightweight in-memory trie indexes RFC 1918 subnets, primary cloud hyperscalers (AWS, Azure, Google), major CDNs (Cloudflare, Fastly), and known test/threat ranges. Public IP addresses outside these prefixes gracefully resolve to `(None, None)`. Downstream consumers (Person 3) treat `None` as "unclassified/rare public destination", which is itself a primary signal for C2 and exfiltration detection. In production, this can be seeded from offline MaxMind `GeoLite2-ASN.mmdb` without pipeline modifications.

### 1.4 Streaming Ingestion & Bounded Memory ($\mathcal{O}(1)$ RAM)
To sustain high packet volumes without memory exhaustion:
- **Streaming Ingestion** (`ingestion/pcap_reader.py`): Streams raw packets sequentially via an $\mathcal{O}(1)$ memory generator. PCAP files are never read entirely into heap RAM.
- **Sliding-Window Aggregator** (`features/flow_aggregator.py`): Organizes packets into 5-tuple flow states (`{src_ip}:{src_port}->{dst_ip}:{dst_port}/{proto}`). Flows inactive beyond `flow_idle_timeout_sec` ($60.0\text{s}$) are flushed and evicted.
- **Windowed Global Context TTL Eviction**: Cross-flow cardinality structures (e.g. host scan sets, source IP entropy frequency deques) maintain independent sliding-window time-to-live queues. Stale observations are purged automatically to prevent runaway accumulation during distributed scans.

---

## Section 2: Mathematical Models of the Six Feature Engines

Diode-Sentinel extracts features across **six pure mathematical feature domains**, strictly without application payload decryption.

```
=============================================================================
             DIODE-SENTINEL PURE FEATURE EXTRACTION SUITE
=============================================================================
  (a) Volumetric & Protocol DDoS     -> VolumetricFeatures
  (b) Botnet C2 Beaconing            -> TimingFeatures
  (c) DGA & DNS Tunnelling           -> DnsLexicalFeatures
  (d) Encrypted Traffic Metadata     -> CryptoMetadataFeatures
  (e) Reconnaissance & Port Scanning -> FanoutFeatures
  (f) Volume Asymmetry & Exfiltration-> VolumeAsymmetryFeatures
=============================================================================
```

### 2.1 Volumetric & Protocol DDoS Engine (`features/volumetric.py`)
*Maps to Threat Class (a): Volumetric / Protocol DDoS*

Measures arrival rates, protocol flag skews, and source dispersion:
1. **Packet Arrival Rate (PPS) & Byte Bandwidth (BPS)**:
   $$\text{PPS} = \frac{N_{\text{packets}}}{\Delta t}, \quad \text{BPS} = \frac{N_{\text{bytes}} \times 8}{\Delta t}$$
2. **SYN:ACK Imbalance Ratio**:
   $$\text{Ratio}_{\text{SYN:ACK}} = \frac{N_{\text{SYN}}}{\max(1, N_{\text{ACK}})}$$
   *Normal TCP traffic exhibits $\approx 1.0$. A high ratio ($> 3.0$) indicates half-open SYN floods.*
3. **Source IP Shannon Entropy ($H_{\text{src}}$)**:
   $$H_{\text{src}} = -\sum_{i=1}^{K} p_i \log_2(p_i), \quad p_i = \frac{c(\text{IP}_i)}{N}$$
   *Where $c(\text{IP}_i)$ is the frequency of IP $i$ within the window. Evaluated over 256-symbol space ($0.0 \le H \le 8.0$). High entropy ($H > 4.5$) indicates randomized/spoofed source storms.*

---

### 2.2 Timing & Autocorrelation Engine (`features/timing.py`)
*Maps to Threat Class (b): Botnet C2 Beaconing*

Quantifies heartbeat determinism and inter-packet arrival regularity:
1. **Inter-Arrival Time (IAT) Moments**:
   $$\mu_{\text{IAT}} = \frac{1}{N-1} \sum_{i=1}^{N-1} \Delta t_i, \quad \sigma_{\text{IAT}} = \sqrt{\frac{1}{N-1} \sum_{i=1}^{N-1} (\Delta t_i - \mu_{\text{IAT}})^2}$$
2. **Coefficient of Variation ($\text{CV}_{\text{IAT}}$)**:
   $$\text{CV}_{\text{IAT}} = \frac{\sigma_{\text{IAT}}}{\mu_{\text{IAT}}}$$
   *Human interactive browsing exhibits high variance ($\text{CV} \ge 1.0$). Automated botnet C2 heartbeats exhibit extreme regularity ($\text{CV} \le 0.20$).*
3. **Lag-1 Normalized Autocorrelation ($r_1$)**:
   $$r_1 = \frac{\sum_{i=1}^{N-2} (\Delta t_i - \mu)(\Delta t_{i+1} - \mu)}{\sum_{i=1}^{N-1} (\Delta t_i - \mu)^2}$$
   *Yields normalized periodicity score $\in [0.0, 1.0]$ detecting regular periodic signals despite subtle clock jitter.*

---

### 2.3 DNS Lexical Analysis Engine (`features/dns_lexical.py`)
*Maps to Threat Class (c): DGA Domains and DNS Tunnelling*

Passively analyzes DNS query names (QNAME) and resource record types:
1. **Alphabet-Specific QNAME Shannon Entropy**:
   $$H_{\text{QNAME}} = -\sum_{j=1}^{M} p(c_j) \log_2 p(c_j)$$
   *Computed over the 38-symbol hostname alphabet (`[a-z0-9.-]`). The theoretical maximum is strictly:*
   $$H_{\text{max}} = \log_2(38) \approx 5.248\text{ bits}$$
   *Normal English domains (e.g. `google.com`) yield $2.0 \le H \le 3.4$. Algorithmic DGA domains yield $H \ge 3.80$.*
2. **Consonant-to-Vowel Ratio ($R_{\text{CV}}$)**:
   $$R_{\text{CV}} = \frac{N_{\text{consonants}}}{\max(1, N_{\text{vowels}})}$$
   *Detects random character strings with abnormal consonant clustering ($R_{\text{CV}} \ge 2.5$) vs natural English text ($\approx 1.5$).*
3. **Covert Tunnel Signatures**:
   - Flags long QNAME lengths ($\ge 45$ characters).
   - Flags anomalous covert record types: `TXT` (Type 16) and `NULL` (Type 10) frequently leveraged by tools like `dnscat2` and `iodine`.

---

### 2.4 Encrypted Traffic Metadata Engine (`features/crypto_metadata.py`)
*Maps to Threat Class (d): Malware inside Encrypted Sessions*

STRICTLY PASSIVE: Inspects initial unencrypted TLS handshake headers without payload decryption. QUIC metadata parsing is not implemented in this prototype:
1. **JA3 Fingerprinting**:
   - Parses client handshake fields: `SSLVersion,CipherSuites,Extensions,EllipticCurves,PointFormats`.
   - Computes 32-character MD5 hash (e.g. `806dd281d6bc4f8f86d7e8d32132e141` matching Cobalt Strike default profiles).
2. **JA4 Representation**:
   - Compact fingerprint string: `t{ver}{sni}{ciph_cnt}{ext_cnt}_{hash}`.
3. **Packet Size Sequence Vector (PZX Biometric)**:
   - Records the ordered byte-length sequence of the initial $N$ data transfers (e.g., `[54, 54, 110, 566]`).
   - Identifies automated malware communication profiles (C2 beacons, shellcode stagers) based purely on traffic morphology.

---

### 2.5 Fanout & Reconnaissance Engine (`features/fanout.py`)
*Maps to Threat Class (e): Reconnaissance and Port Scanning*

Tracks entity endpoint cardinality across sliding windows in `GlobalContext`:
1. **Target Cardinality**:
   - $N_{\text{dst\_ports}}$: Distinct destination ports probed by source IP.
   - $N_{\text{dst\_ips}}$: Distinct destination hosts probed by source IP.
2. **Vertical & Horizontal Scan Scores**:
   $$\text{Score}_{\text{vert}} = \min\left(1.0, \frac{N_{\text{dst\_ports}}}{50}\right), \quad \text{Score}_{\text{horiz}} = \min\left(1.0, \frac{N_{\text{dst\_ips}}}{20}\right)$$
3. **Stealth Half-Open Ratio ($R_{\text{half\_open}}$)**:
   $$R_{\text{half\_open}} = \frac{N_{\text{SYN\_only}}}{\max(1, N_{\text{total\_probes}})}$$
   *Benign servers responding to ephemeral ports show $R_{\text{half\_open}} \approx 0.0$ (completed sessions). Nmap stealth SYN scanners show $R_{\text{half\_open}} \ge 0.80$.*

---

### 2.6 Volume Asymmetry & Exfiltration Engine (`features/volume_asymmetry.py`)
*Maps to Threat Class (f): Data Exfiltration*

Detects massive unauthorized outbound data transfers:
1. **Byte Direction Ratio**:
   $$\text{Ratio}_{\text{byte}} = \frac{\text{Bytes}_{\text{outbound}}}{\max(1, \text{Bytes}_{\text{inbound}})}$$
   *Normal web browsing has ratio $\ll 1.0$ (inbound downloads dominate). Data exfiltration displays ratio $\gg 10.0$.*
2. **Outbound Velocity**:
   $$V_{\text{out}} = \frac{\text{Bytes}_{\text{outbound}} \times 8}{\text{Duration}_{\text{sec}}}$$
3. **Unidirectional Leg Fallback Mode**:
   - If optical mirroring exposes only one directional link, sets `is_unidirectional_fallback = True` and computes exfiltration velocity against baseline historical percentiles.

---

## Section 3: Data Generation Suite & Threat PCAP Mapping

The NTRO Problem Statement requires validation against diverse threat scenarios generated using industry-standard tools. The `data_generation/` package synthesizes 8 labeled datasets accompanied by ground-truth sidecar JSONs.

| PCAP File | Ground Truth Label | Emulated Attack Pattern | Tool Emulated per PS | Key Ground-Truth Signatures |
| :--- | :--- | :--- | :--- | :--- |
| `benign_steady.pcap` | `none` | Continuous baseline office browsing | `iperf3` / `cURL` | Balanced SYN:ACK ($\approx 1.0$), low fanout, standard domains |
| `benign_bursty.pcap` | `benign` | Bursty multi-user daytime web browsing | `Ostinato` / `TRex` | Short HTTP/HTTPS bursts, variable IAT, valid handshakes |
| `attack_ddos_syn.pcap` | `a_volumetric_ddos` | Spoofed distributed SYN flood | `hping3` / `TRex` | $H_{\text{src}} \ge 6.5$, SYN:ACK $\gg 50.0$, 0 ACK packets |
| `attack_c2_beacon.pcap`| `b_c2_beaconing` | Periodic botnet C2 heartbeats | `Slowloris` / C2 simulator | IAT $\text{CV} \le 0.05$, periodicity autocorrelation $r_1 \ge 0.65$ |
| `attack_dga.pcap` | `c_dga_dns_tunnel` | Algorithmic domains + TXT exfil | `dnscat2` / `DGArchive` | QNAME $H \ge 3.85$, $R_{\text{CV}} \ge 2.5$, TXT tunnel chunks |
| `attack_encrypted_malware.pcap`| `d_encrypted_malware`| Cobalt Strike TLS handshake + PZX | Cobalt Strike / Metasploit | JA3: `806dd281...`, fixed PZX sequence `[54, 54, 110, 566]` |
| `attack_portscan.pcap` | `e_recon_port_scan` | Vertical port scan & horizontal sweep | `Nmap` (`-sS` SYN scan) | 150 ports probed, 50 hosts probed, half-open ratio $= 1.0$ |
| `attack_exfil.pcap` | `f_data_exfiltration` | Large bulk outbound data transfer | `iperf3` / SCP upload | Outbound:inbound byte ratio $> 100,000:1$, $> 140\text{ KB}$ |

---

## Section 4: Validation & Benchmark Results

### 4.1 Generalization on Real-World Captures (CTU-13 Scenario 9 Neris Botnet)
To demonstrate that feature extraction is not overfitted to synthetic laboratory traffic, the pipeline was evaluated against authentic binary packet captures from the **Stratosphere Laboratory CTU-13 research dataset (Scenario 9: `ctu13_neris_real_botnet_10k.pcap` & `ctu13_real_normal.pcap`)**:
- **Transparent Provenance**: Replayed directly from official captures at Czech Technical University in Prague ([https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-50/](https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-50/)), featuring genuine botnet host `147.32.84.165` performing C2 IRC, portscanning, and DDoS.
- **Zero Pipeline Crashes**: 100% crash-free streaming execution across 30,549 authentic network packets.
- **Zero NaN / Null Values**: Complete mathematical integrity across all 6 feature engines.
- **Alphabet-Specific Entropy Adherence**: All observed DNS QNAME entropies fall strictly within $[0.0, 5.25]$ bits ($H_{max} = \log_2(38)$), and byte/IP entropies within $[0.0, 8.0]$ bits.
- **Detailed Report**: See [`validation/GENERALIZATION_REPORT.md`](file:///c:/Users/suraj/Documents/MY_Projects/SIH2026/diode-sentinel/validation/GENERALIZATION_REPORT.md).

### 4.2 Dual-Profile Throughput & Tail Latency Benchmark

To maintain complete technical transparency, Diode-Sentinel documents performance across two distinct profiles with final post-optimization numbers:

1. **Profile A: Real-World PCAP Streaming (`ctu13_neris_real_botnet_10k.pcap`)**:
   - **Pure Engine Processing Rate**: **$3{,}105.0\text{ packets/sec}$** ($4.014\text{ Mbps}$)
   - **Wall-Clock Rate (inc. disk IO & Scapy parsing)**: **$1{,}197.8\text{ packets/sec}$**
   - **P50**: $0.132\text{ ms}$ | **P95**: $0.569\text{ ms}$ | **P99**: $1.389\text{ ms}$
   - **P99.9 Tail Latency**: $7.82\text{ ms}$ (at 5-second sliding window tick boundaries)

2. **Profile B: Sustained Multi-Flow Stress Test (2,000 Active Concurrent Flows)**:
   - **Pure Engine Rate**: **$819.0\text{ packets/sec}$** | **Wall-Clock Rate**: **$568.9\text{ packets/sec}$**
   - **P50**: $1.12\text{ ms}$ | **P95**: $1.87\text{ ms}$ | **P99**: $4.78\text{ ms}$
   - **P99.9 Tail Latency**: $7.82\text{ ms}$ | **Max**: $11.66\text{ ms}$

3. **Tail Latency Root Cause & Mitigations Applied**:
   - **GC Tuning**: `gc.set_threshold(10000, 100, 100)` raised Gen-0/1/2 sweep thresholds ~10–14× above CPython defaults, eliminating random mid-stream GC pauses. `gc.collect()` fires manually every 10 ticks (~100 s) at a controlled idle point between sliding windows.
   - **Remaining RECURRING_PERIODIC tail (P99 ≈ 4.78 ms)**: This is the tick-boundary batch itself — computing 6 feature families across all active flows synchronously on the one packet that crosses the slide boundary. This is **known, bounded, and SLA-compliant** (P99 ≪ 2000 ms SLA by 420×).
   - **ASN Resolver Acquitted**: In-memory ASN lookup costs $7.4\,\mu\text{s}$ per call ($< 0.01\%$ of latency).
   - **SLA Compliance**: Both profiles satisfy $P_{99} \ll 2.0\text{ seconds}$ SLA threshold.

4. **Horizontal Scaling Path (for high-throughput deployments)**:
   Individual flow 5-tuples are statistically independent — a flow's feature computation touches only its own state and the shared `WindowedGlobalContext`. At production-scale throughput (lakhs of pps), the natural scaling strategy is **horizontal sharding by 5-tuple hash**: partition incoming flows across N worker processes (or cores) using `hash(src_ip, src_port, dst_ip, dst_port, proto) % N`. Each worker runs its own `FlowAggregator` instance and writes to its own JSONL partition; Person 3's ingestion pipeline merges partitions. This achieves near-linear throughput scaling with no cross-process synchronisation required.

5. **Deferred Optimization — Zero-Copy Incremental Running Stats (documented, not a gap)**:
   The correct architectural fix for the P99 tick-boundary spike is to move partial feature accumulation into `Flow.update()` so `tick()` reads pre-computed values (O(1) per flow) rather than recomputing them. A per-packet amortised refresh approach was implemented, benchmarked, and reverted during this session: it degraded P50 from ~$0.5\text{ ms}$ to $9.76\text{ ms}$ and P99.9 from $13.87\text{ ms}$ to $68.95\text{ ms}$ because full 6-engine computation per packet is more expensive than the periodic batch it was trying to smooth. The correct refactor (incremental accumulation in `Flow.update()` with O(1) tick reads) requires modifying all 6 feature engines and is **explicitly deferred post-Person-3 handoff** to avoid introducing bugs at the schema contract boundary under time pressure. The 420× SLA margin makes this deferral a defensible engineering decision.

### 4.3 Adversarial Diode Watchdog Self-Test (`tests/test_diode_leak_injection.py`)
To prove that the watchdog actively catches violations rather than simply reporting zero:
- **Level 1 Socket Leak**: Deliberate injection of an outbound connection to `198.51.100.88:443` immediately triggered `dual_check_status.process_socket_table = "VIOLATION_DETECTED"`.
- **Level 2 NIC Byte Leak**: Deliberate injection of a $+4{,}096\text{ byte}$ interface delta immediately triggered `dual_check_status.nic_io_counter = "RAW_EGRESS_DETECTED"`.
- **Fail-Closed Mode**: Successfully raised `DiodeComplianceViolationError` when configured with `raise_on_violation=True`.

### 4.4 Test Suite History & Provenance ($37 \rightarrow 40 \rightarrow 44$ Progression)

To ensure full auditability for judges and team handoffs, the progression of the test suite count is documented:

1. **Initial Baseline ($37\text{ tests}$)**:
   - `tests/test_all.py` (8 tests): Core feature extraction, sliding window invariants, and mathematical boundaries.
   - `tests/test_detectors.py` (11 tests): 6 threat class detectors + 5 benign trap suppression tests.
   - `tests/test_diode_leak_injection.py` (4 tests): Watchdog socket and NIC leak injection verification.
   - `tests/test_e2e_pipeline.py` (1 test): Mock PCAP to detector end-to-end integration.
   - `tests/test_evaluation.py` (1 test): Benchmark evaluation harness test.
   - `tests/test_fp_reduction.py` (5 tests): Allowlist, baseline store, corroboration, and persistence filter unit tests.
   - `tests/test_schemas.py` (5 tests): Strict Pydantic v2 schema serialization and contract validation.
   - `tests/test_schema_jsonl_drift.py` (2 tests): JSONL field validation against canonical schemas.

2. **The $37 \rightarrow 40\text{ Jump}$ ($+3\text{ tests}$)**:
   - **Origin**: `tests/test_correlation.py` (3 tests: `test_recon_c2_exfil_chain`, `test_dga_to_c2_chain`, `test_ddos_smokescreen_chain`).
   - **Reason**: These multi-stage attack correlation tests were authored by Person 3 under `ML model SIH2026/`, but could not execute from the repository root because they attempted to import `correlation` and `schemas` which were not on `PYTHONPATH`. Once the repository was unified into root sibling packages (`correlation/`, `schemas/`, `threatcore/`), pytest discovered and cleanly executed all 3 tests.

3. **The $40 \rightarrow 44\text{ Jump}$ ($+4\text{ tests}$)**:
   - **Origin**: `tests/test_live_e2e_integration.py` (4 tests: `test_live_e2e_portscan_attack`, `test_live_e2e_c2_beacon_attack`, `test_live_e2e_dga_dns_attack`, `test_live_e2e_benign_traffic_suppression`).
   - **Reason**: Added during pre-demo integration hardening to prove that live binary PCAP captures (`data_generation/pcaps/*.pcap`) stream through `run_pipeline.py` into ThreatCore detectors in real time, validating detection of attacks and 100% false-alarm suppression on benign traffic.

---

## Section 5: Handoff & Integration Interfaces

### 5.1 Person 3 (ThreatCore AI/ML Detectors)
- **Contract**: [`schemas/CONTRACT.md`](file:///c:/Users/suraj/Documents/MY_Projects/SIH2026/diode-sentinel/schemas/CONTRACT.md) governs the frozen JSONL schema.
- **File Generation**: Run `run_pipeline.py --pcap <file> --output <features.jsonl> --alerts-output <alerts.jsonl>`.
- **Ingestion**: Person 3 loads records using:
  ```python
  from schemas.flow_feature_record import FlowFeatureRecord
  with open("output.jsonl") as f:
      records = [FlowFeatureRecord.model_validate_json(line) for line in f]
  ```

### 5.2 Person 4 (Live Operations Dashboard)
- **Compliance Status Polling**: Read [`diode_compliance_status.json`](file:///c:/Users/suraj/Documents/MY_Projects/SIH2026/diode_compliance_status.json) emitted by `DiodeComplianceWatchdog` for real-time zero-egress telemetry.
- **Flow Feature Stream**: Consume sliding-window records for radar charts, entropy graphs, and fanout visualizations.
