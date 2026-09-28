"""
Authoritative data contract for Diode-Sentinel.
Strict Pydantic v2 schemas defining the interface between:
- Ingestion & Feature Aggregation (Person 2)
- Threat Detectors & AI Models (Person 3)
- Live Visualization Dashboard (Person 4)
"""

from __future__ import annotations
from datetime import datetime, timezone
from typing import List, Optional
from pydantic import BaseModel, Field


class VolumetricFeatures(BaseModel):
    """
    Feeds Detector (a): Volumetric / Protocol DDoS
    Detects SYN floods, UDP reflection/amplification, and spoofed-source floods.
    """
    packet_count: int = Field(0, description="Total packets in sliding window")
    byte_count: int = Field(0, description="Total bytes in sliding window")
    packet_rate_pps: float = Field(0.0, description="Packets per second sustained")
    byte_rate_bps: float = Field(0.0, description="Bytes per second sustained")
    src_ip_entropy: float = Field(0.0, description="Shannon entropy of source IPs observed in window")
    syn_ack_ratio: float = Field(0.0, description="Ratio of SYN packets to ACK packets (high = SYN flood)")
    syn_count: int = Field(0, description="Raw count of SYN packets")
    ack_count: int = Field(0, description="Raw count of ACK packets")
    fin_count: int = Field(0, description="Raw count of FIN packets")
    rst_count: int = Field(0, description="Raw count of RST packets")
    udp_count: int = Field(0, description="Count of UDP packets")
    tcp_count: int = Field(0, description="Count of TCP packets")
    icmp_count: int = Field(0, description="Count of ICMP packets")
    zero_window_count: int = Field(0, description="Count of TCP zero-window packets")
    avg_packet_size: float = Field(0.0, description="Average packet size in bytes")


class TimingFeatures(BaseModel):
    """
    Feeds Detector (b): Botnet C2 Beaconing
    Detects periodicity and inter-arrival regularity toward command-and-control servers.
    """
    packet_count: int = Field(0, description="Packet count used for timing analysis")
    iat_mean_ms: float = Field(0.0, description="Mean Inter-Arrival Time in milliseconds")
    iat_std_ms: float = Field(0.0, description="Standard deviation of Inter-Arrival Time")
    iat_cv: float = Field(0.0, description="Coefficient of variation (std / mean); low CV indicates periodic beaconing")
    iat_min_ms: float = Field(0.0, description="Minimum Inter-Arrival Time in milliseconds")
    iat_max_ms: float = Field(0.0, description="Maximum Inter-Arrival Time in milliseconds")
    periodicity_score: float = Field(0.0, description="Autocorrelation peak-to-noise score (0.0=random, 1.0=exact periodic)")
    jitter_pct: float = Field(0.0, description="Estimated timing jitter percentage")


class DnsLexicalFeatures(BaseModel):
    """
    Feeds Detector (c): DGA Domains and DNS Tunnelling
    Detects algorithmic domain generation (DGA) and covert data exfiltration via DNS.
    """
    has_dns: bool = Field(False, description="Whether DNS traffic was observed in this flow")
    query_name: Optional[str] = Field(None, description="Extracted DNS query name (QNAME)")
    query_length: int = Field(0, description="Length of query string")
    shannon_entropy: float = Field(0.0, description="Shannon entropy of characters in query name")
    consonant_vowel_ratio: float = Field(0.0, description="Ratio of consonants to vowels (high/anomalous in DGAs)")
    numeric_char_ratio: float = Field(0.0, description="Fraction of numeric characters in query name")
    subdomain_count: int = Field(0, description="Number of subdomain labels")
    record_type: Optional[str] = Field(None, description="Observed query record type (A, AAAA, TXT, NULL, ANY)")
    is_txt_or_null: bool = Field(False, description="True if query is TXT or NULL record (classic tunnel fingerprint)")
    is_tunnel_candidate: bool = Field(False, description="Heuristic flag for high-entropy + long QNAME tunnel pattern")


# Backward compatibility alias
DnsFeatures = DnsLexicalFeatures


class CryptoMetadataFeatures(BaseModel):
    """
    Feeds Detector (d): Malware inside Encrypted Sessions
    STRICTLY PASSIVE: Inspects only TLS/QUIC handshake metadata without payload decryption.
    """
    is_tls_quic: bool = Field(False, description="Whether TLS or QUIC session was identified")
    ja3_str: Optional[str] = Field(None, description="Raw JA3 fingerprint string: SSLVersion,Ciphers,Extensions,EllipticCurves,PointFormats")
    ja3_digest: Optional[str] = Field(None, description="MD5 hash of the raw JA3 string")
    ja4_str: Optional[str] = Field(None, description="Standard JA4 fingerprint representation")
    tls_version: Optional[str] = Field(None, description="TLS protocol version (e.g. TLSv1.2, TLSv1.3)")
    cipher_suites_count: int = Field(0, description="Count of advertised cipher suites")
    extensions_count: int = Field(0, description="Count of advertised TLS extensions")
    packet_size_sequence: List[int] = Field(default_factory=list, description="Length vector of initial N data packets (traffic biometric)")
    inter_arrival_sequence_ms: List[float] = Field(default_factory=list, description="IAT sequence of initial N data packets")
    sni: Optional[str] = Field(None, description="Server Name Indication from ClientHello if present")


# Backward compatibility alias
CryptoFeatures = CryptoMetadataFeatures


class FanoutFeatures(BaseModel):
    """
    Feeds Detector (e): Reconnaissance and Port Scanning
    Identifies horizontal sweeps (same port, many hosts) and vertical scans (one host, many ports).
    Maintained inside windowed GlobalContext to guarantee bounded memory.
    """
    dst_port_count: int = Field(0, description="Distinct destination ports accessed by source IP in active window")
    dst_ip_count: int = Field(0, description="Distinct destination IPs accessed by source IP in active window")
    scan_rate_pps: float = Field(0.0, description="Rate of new unique (IP, port) endpoints contacted per second")
    half_open_ratio: float = Field(0.0, description="Ratio of SYN packets without subsequent payload or completion")
    port_entropy: float = Field(0.0, description="Shannon entropy of target destination port distribution")
    horizontal_scan_score: float = Field(0.0, description="Normalized score indicating multi-host scan behavior")
    vertical_scan_score: float = Field(0.0, description="Normalized score indicating multi-port scan behavior")


class VolumeAsymmetryFeatures(BaseModel):
    """
    Feeds Detector (f): Data Exfiltration
    Evaluates asymmetric data transfer and burst volume.
    NOTE: In full-duplex mirror taps feeding the hardware diode, both outbound and inbound
    legs are aggregated. If only one leg is present, fallback mode is engaged.
    """
    outbound_bytes: int = Field(0, description="Bytes transferred from source to destination")
    inbound_bytes: int = Field(0, description="Bytes received from destination to source")
    byte_ratio: float = Field(0.0, description="Ratio outbound / max(1, inbound). High ratio indicates exfil upload")
    duration_sec: float = Field(0.0, description="Active flow duration in seconds")
    outbound_byte_rate_bps: float = Field(0.0, description="Outbound byte transfer rate")
    byte_burstiness: float = Field(0.0, description="Variance of bytes transferred per window slice")
    is_unidirectional_fallback: bool = Field(False, description="True if only one direction of flow is physically visible")
    exfil_risk_score: float = Field(0.0, description="Composite score for abnormal upload volume/ratio")


class FlowFeatureRecord(BaseModel):
    """
    The master data contract emitted for every sliding-window tick per flow.
    Consolidated record consumed by Person 3 (Detector Models) and Person 4 (Dashboard).
    """
    flow_id: str = Field(..., description="Canonical 5-tuple: '{src_ip}:{src_port}->{dst_ip}:{dst_port}/{protocol}'")
    src_ip: str = Field(..., description="Source IPv4 / IPv6 address")
    src_port: int = Field(..., description="Source transport port")
    dst_ip: str = Field(..., description="Destination IPv4 / IPv6 address")
    dst_port: int = Field(..., description="Destination transport port")
    protocol: str = Field("TCP", description="Transport protocol (TCP, UDP, ICMP, etc.)")
    window_start: datetime = Field(..., description="UTC start of observation window")
    window_end: datetime = Field(..., description="UTC end of observation window")
    window_duration_sec: float = Field(30.0, description="Duration of the sliding window in seconds")
    # Optional offline-enriched metadata (strictly resolved via local offline database, zero egress)
    src_asn: Optional[int] = Field(None, description="Autonomous System Number of source IP (for destination-rarity scoring)")
    dst_asn: Optional[int] = Field(None, description="Autonomous System Number of destination IP (for exfil / C2 detection)")
    src_country: Optional[str] = Field(None, description="ISO-3166 2-letter country code for source")
    dst_country: Optional[str] = Field(None, description="ISO-3166 2-letter country code for destination")

    # The 6 threat feature families
    volumetric: VolumetricFeatures = Field(default_factory=VolumetricFeatures)
    timing: TimingFeatures = Field(default_factory=TimingFeatures)
    dns_lexical: DnsLexicalFeatures = Field(default_factory=DnsLexicalFeatures)
    crypto_metadata: CryptoMetadataFeatures = Field(default_factory=CryptoMetadataFeatures)
    fanout: FanoutFeatures = Field(default_factory=FanoutFeatures)
    volume_asymmetry: VolumeAsymmetryFeatures = Field(default_factory=VolumeAsymmetryFeatures)

    @classmethod
    def create_empty(cls, flow_id: str, src_ip: str, src_port: int, dst_ip: str, dst_port: int, protocol: str) -> "FlowFeatureRecord":
        now = datetime.now(timezone.utc)
        return cls(
            flow_id=flow_id,
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=dst_ip,
            dst_port=dst_port,
            protocol=protocol,
            window_start=now,
            window_end=now,
        )
