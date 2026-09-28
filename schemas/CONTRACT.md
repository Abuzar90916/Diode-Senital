# Data Contract & Schema Freeze: FlowFeatureRecord v1.0

**Status**: FROZEN  
**Effective Date**: September 4, 2026  
**Governing Component**: `diode-sentinel/schemas/flow_feature_record.py`  
**Consuming Roles**: Person 3 (ThreatCore AI/ML Detectors), Person 4 (Operations Dashboard)  
**Producing Role**: Person 2 (Ingestion & Flow Feature Aggregation)  

> [!IMPORTANT]
> **SCHEMA FREEZE POLICY**  
> This schema represents the authoritative, locked interface boundary for Diode-Sentinel.  
> No field names, types, or semantic definitions may be altered without formal written sign-off from Person 3.

---

## 1. Zero-Egress Architectural Mandate (NTRO PS 26145)

All features and metadata fields defined in this schema are computed **strictly from passively mirrored traffic inside the monitoring enclave**:
1. **No Outbound Network Queries**: Enrichment fields (`src_asn`, `dst_asn`, `src_country`, `dst_country`) are resolved **strictly via an offline, in-memory database** (local prefix table / offline MaxMind database loaded at startup). Any live DNS PTR, WHOIS, or HTTP GeoIP lookup is a compliance violation and strictly forbidden.
2. **No Payload Decryption**: Cryptographic features (`CryptoMetadataFeatures`) extract unencrypted TLS handshake metadata (JA3/JA4, biometric packet-length vectors) without decrypting application data. QUIC parsing is not currently implemented.
3. **Unidirectional Leg Fallback**: If full-duplex mirroring is not available on a link, `VolumeAsymmetryFeatures.is_unidirectional_fallback` is flagged `True`, and single-leg heuristics are engaged.

---

## 2. Master Record Specification (`FlowFeatureRecord`)

Every emitted sliding-window record conforms to the following JSON structure:

```json
{
  "flow_id": "192.168.1.45:51200->45.33.32.156:8443/TCP",
  "src_ip": "192.168.1.45",
  "src_port": 51200,
  "dst_ip": "45.33.32.156",
  "dst_port": 8443,
  "protocol": "TCP",
  "window_start": "2026-09-04T01:00:00.000000Z",
  "window_end": "2026-09-04T01:00:30.000000Z",
  "window_duration_sec": 30.0,
  "src_asn": 0,
  "dst_asn": 63949,
  "src_country": "PRIVATE",
  "dst_country": "US",
  "volumetric": { ... },
  "timing": { ... },
  "dns_lexical": { ... },
  "crypto_metadata": { ... },
  "fanout": { ... },
  "volume_asymmetry": { ... }
}
```

### Top-Level Metadata Fields
| Field Name | Type | Nullable | Description & Range |
| :--- | :--- | :---: | :--- |
| `flow_id` | `str` | No | Canonical 5-tuple string: `"{src_ip}:{src_port}->{dst_ip}:{dst_port}/{protocol}"` |
| `src_ip` | `str` | No | IPv4 or IPv6 source address |
| `src_port` | `int` | No | Source transport port $[0, 65535]$ |
| `dst_ip` | `str` | No | IPv4 or IPv6 destination address |
| `dst_port` | `int` | No | Destination transport port $[0, 65535]$ |
| `protocol` | `str` | No | Transport protocol: `"TCP"`, `"UDP"`, `"ICMP"`, `"OTHER"` |
| `window_start` | `datetime` | No | UTC timestamp marking start of observation window (ISO-8601) |
| `window_end` | `datetime` | No | UTC timestamp marking end of observation window (ISO-8601) |
| `window_duration_sec` | `float` | No | Duration of the sliding window in seconds (default: `30.0`) |
| `src_asn` | `int` | Yes | Source Autonomous System Number (resolved offline, $0$ for RFC1918) |
| `dst_asn` | `int` | Yes | Destination Autonomous System Number (resolved offline) |
| `src_country` | `str` | Yes | Source 2-letter ISO country code or `"PRIVATE"` |
| `dst_country` | `str` | Yes | Destination 2-letter ISO country code |

---

## 3. The Six Threat Feature Domains

### (a) Volumetric & Protocol DDoS (`VolumetricFeatures`)
Feeds Detector (a): Volumetric / Protocol DDoS (SYN floods, UDP reflection, spoofed storms).

| Field Name | Type | Default | Range / Formula | Purpose |
| :--- | :---: | :---: | :---: | :--- |
| `packet_count` | `int` | `0` | $[0, \infty)$ | Total packets observed in window |
| `byte_count` | `int` | `0` | $[0, \infty)$ | Total bytes observed in window |
| `packet_rate_pps` | `float` | `0.0` | $[0.0, \infty)$ | $\text{packets} / \text{duration}$ |
| `byte_rate_bps` | `float` | `0.0` | $[0.0, \infty)$ | $(\text{bytes} \times 8) / \text{duration}$ |
| `src_ip_entropy` | `float` | `0.0` | $[0.0, 8.0]$ | Shannon entropy $-\sum p_i \log_2(p_i)$ of source IPs |
| `syn_ack_ratio` | `float` | `0.0` | $[0.0, \infty)$ | $\text{SYN} / \max(1, \text{ACK})$ |
| `syn_count` | `int` | `0` | $[0, \infty)$ | Count of packets with TCP SYN flag set |
| `ack_count` | `int` | `0` | $[0, \infty)$ | Count of packets with TCP ACK flag set |
| `fin_count` | `int` | `0` | $[0, \infty)$ | Count of packets with TCP FIN flag set |
| `rst_count` | `int` | `0` | $[0, \infty)$ | Count of packets with TCP RST flag set |
| `udp_count` | `int` | `0` | $[0, \infty)$ | Count of UDP datagrams |
| `tcp_count` | `int` | `0` | $[0, \infty)$ | Count of TCP segments |
| `icmp_count` | `int` | `0` | $[0, \infty)$ | Count of ICMP messages |
| `zero_window_count`| `int` | `0` | $[0, \infty)$ | TCP zero-window advertisements (exhaustion) |
| `avg_packet_size` | `float` | `0.0` | $[0.0, 65535.0]$ | Mean packet size in bytes |

---

### (b) Timing & Autocorrelation (`TimingFeatures`)
Feeds Detector (b): Botnet C2 Beaconing (heartbeats, periodic beaconing, jitter).

| Field Name | Type | Default | Range / Formula | Purpose |
| :--- | :---: | :---: | :---: | :--- |
| `packet_count` | `int` | `0` | $[0, \infty)$ | Count of packets with valid timestamps |
| `iat_mean_ms` | `float` | `0.0` | $[0.0, \infty)$ | Arithmetic mean of Inter-Arrival Times (ms) |
| `iat_std_ms` | `float` | `0.0` | $[0.0, \infty)$ | Standard deviation $\sigma$ of IATs (ms) |
| `iat_cv` | `float` | `0.0` | $[0.0, \infty)$ | Coefficient of variation $\sigma / \mu$; low CV indicates beaconing |
| `iat_min_ms` | `float` | `0.0` | $[0.0, \infty)$ | Minimum IAT observed (ms) |
| `iat_max_ms` | `float` | `0.0` | $[0.0, \infty)$ | Maximum IAT observed (ms) |
| `periodicity_score`| `float` | `0.0` | $[0.0, 1.0]$ | Lag-1 normalized autocorrelation coefficient $r_1$ |
| `jitter_pct` | `float` | `0.0` | $[0.0, 100.0]$ | Estimated jitter percentage $\text{std} / \text{mean} \times 100$ |

---

### (c) DNS Lexical Analysis (`DnsLexicalFeatures`)
Feeds Detector (c): DGA Domains and DNS Tunnelling (iodine, dnscat2, exfiltration).

| Field Name | Type | Default | Range / Formula | Purpose |
| :--- | :---: | :---: | :---: | :--- |
| `has_dns` | `bool` | `False` | `{True, False}` | Flag indicating presence of DNS layer |
| `query_name` | `str` | `None` | Nullable string | Extracted DNS QNAME (e.g. `"exfil.domain.com"`) |
| `query_length` | `int` | `0` | $[0, 255]$ | Total character length of QNAME |
| `shannon_entropy` | `float` | `0.0` | $[0.0, 5.25]$ | Shannon entropy over 38-char alphabet (`a-z0-9.-`) |
| `consonant_vowel_ratio`|`float`| `0.0` | $[0.0, \infty)$ | Ratio of consonants to vowels in QNAME labels |
| `numeric_char_ratio` | `float` | `0.0` | $[0.0, 1.0]$ | Fraction of numeric characters in QNAME |
| `subdomain_count` | `int` | `0` | $[0, 127]$ | Number of dot-separated subdomain labels |
| `record_type` | `str` | `None` | Nullable string | Query type (`"A"`, `"AAAA"`, `"TXT"`, `"NULL"`) |
| `is_txt_or_null` | `bool` | `False` | `{True, False}` | Flag for TXT/NULL records commonly used by tunnels |
| `is_tunnel_candidate`| `bool`| `False` | `{True, False}` | Flag for long QNAME ($\ge 45$ chars) + high entropy |

---

### (d) Encrypted Traffic Metadata (`CryptoMetadataFeatures`)
Feeds Detector (d): Malware inside Encrypted Sessions (JA3/JA4, Cobalt Strike, Meterpreter).

| Field Name | Type | Default | Range / Formula | Purpose |
| :--- | :---: | :---: | :---: | :--- |
| `is_tls_quic` | `bool` | `False` | `{True, False}` | Flag indicating TLS or QUIC session observed |
| `ja3_str` | `str` | `None` | Raw string | Raw JA3 string: `Ver,Ciphers,Exts,Curves,Formats` |
| `ja3_digest` | `str` | `None` | 32-char hex | MD5 hash of `ja3_str` (e.g. `"806dd281..."`) |
| `ja4_str` | `str` | `None` | 36-char string | JA4 string format: `t13d1516_hash` |
| `tls_version` | `str` | `None` | String | e.g. `"TLSv1.2"`, `"TLSv1.3"` |
| `cipher_suites_count`|`int` | `0` | $[0, 255]$ | Number of cipher suites in ClientHello |
| `extensions_count` | `int` | `0` | $[0, 255]$ | Number of TLS extensions in ClientHello |
| `packet_size_sequence`|`List[int]`| `[]` | Length $\le 16$ | Initial $N$ packet payload byte lengths (PZX vector) |
| `inter_arrival_sequence_ms`|`List[float]`| `[]` | Length $\le 16$| Initial $N$ packet inter-arrival times (ms) |
| `sni` | `str` | `None` | Nullable string | Server Name Indication string from ClientHello |

---

### (e) Fanout & Reconnaissance (`FanoutFeatures`)
Feeds Detector (e): Reconnaissance and Port Scanning (vertical sweeps, horizontal subnets).

| Field Name | Type | Default | Range / Formula | Purpose |
| :--- | :---: | :---: | :---: | :--- |
| `dst_port_count` | `int` | `0` | $[0, \infty)$ | Distinct destination ports probed by source IP |
| `dst_ip_count` | `int` | `0` | $[0, \infty)$ | Distinct destination IPs probed by source IP |
| `scan_rate_pps` | `float` | `0.0` | $[0.0, \infty)$ | Unique $(IP, port)$ endpoints contacted per sec |
| `half_open_ratio`| `float` | `0.0` | $[0.0, 1.0]$ | SYN packets without payload / completion ratio |
| `port_entropy` | `float` | `0.0` | $[0.0, 16.0]$ | Shannon entropy of targeted destination ports |
| `horizontal_scan_score`|`float`| `0.0` | $[0.0, 1.0]$ | Multi-host sweep anomaly score |
| `vertical_scan_score` | `float`| `0.0` | $[0.0, 1.0]$ | Multi-port vertical scan anomaly score |

---

### (f) Volume Asymmetry & Exfiltration (`VolumeAsymmetryFeatures`)
Feeds Detector (f): Data Exfiltration (large uploads, tunnel transfers, covert channels).

| Field Name | Type | Default | Range / Formula | Purpose |
| :--- | :---: | :---: | :---: | :--- |
| `outbound_bytes` | `int` | `0` | $[0, \infty)$ | Forward bytes transferred (src $\to$ dst) |
| `inbound_bytes` | `int` | `0` | $[0, \infty)$ | Backward bytes transferred (dst $\to$ src) |
| `byte_ratio` | `float` | `0.0` | $[0.0, \infty)$ | $\text{outbound\_bytes} / \max(1, \text{inbound\_bytes})$ |
| `duration_sec` | `float` | `0.0` | $[0.0, \infty)$ | Active flow duration in seconds |
| `outbound_byte_rate_bps`|`float`| `0.0` | $[0.0, \infty)$ | Outbound transfer rate in bits per second |
| `byte_burstiness` | `float`| `0.0` | $[0.0, \infty)$ | Variance of bytes transferred per window slice |
| `is_unidirectional_fallback`|`bool`|`False`| `{True, False}`| Single-leg visibility fallback mode |
| `exfil_risk_score`| `float` | `0.0` | $[0.0, 1.0]$ | Composite heuristic score for abnormal exfiltration |

---

## 4. Handoff & Ingestion Rules for Person 3 & Person 4

1. **Serialization Format**: Standard JSON Lines (`.jsonl`), UTF-8 encoded, one `FlowFeatureRecord` per line.
2. **Timestamps**: All timestamps must be ISO-8601 with explicit UTC offset (`Z`).
3. **Missing / Null Values**: Categorical fields (`query_name`, `sni`, `ja3_digest`, `src_asn`, `dst_asn`) evaluate to `None` / `null` if the corresponding protocol layer was absent in the flow. Numerical feature values default to `0` or `0.0` (never `NaN` or `null`).
4. **Validation Test**: Any feature file exported by `run_pipeline.py --output` can be validated using:
   ```python
   from schemas.flow_feature_record import FlowFeatureRecord
   import json

   with open("features.jsonl") as f:
       for line in f:
           record = FlowFeatureRecord.model_validate_json(line)
   ```

**Contract Sign-off**:
- [x] Person 1 & 2 (Diode-Sentinel Core Lead): *Approved & Frozen*
- [ ] Person 3 (ThreatCore AI/ML Lead): *Pending Handoff Review*
