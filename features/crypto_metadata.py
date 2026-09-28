"""
Encrypted Traffic Metadata Feature Calculator for Diode-Sentinel.
Pure stateless function feeding Detector (d): Malware inside Encrypted Sessions.
STRICTLY ZERO DECRYPTION: Inspects only TLS/QUIC handshake metadata,
JA3 / JA4 fingerprints, cipher suite counts, and early packet-size sequences (PZX biometric).
"""

from typing import Dict, Any, List


def compute(flow) -> Dict[str, Any]:
    """
    Extracts passive cryptographic metadata without decrypting payloads.
    Uses TLS handshake characteristics and early packet size dynamics.
    """
    # Packet size sequence biometric (first 16 packets)
    pzx_sequence: List[int] = list(flow.fwd_packet_sizes) if flow.fwd_packet_sizes else []

    # Early inter-arrival sequence for first packets (in ms)
    iat_seq: List[float] = []
    ts_list = list(flow.timestamps)
    for i in range(1, min(len(ts_list), 10)):
        iat_seq.append(round((ts_list[i] - ts_list[i - 1]) * 1000.0, 2))

    return {
        "is_tls_quic": flow.is_tls,
        "ja3_str": flow.ja3_str,
        "ja3_digest": flow.ja3_digest,
        "ja4_str": flow.ja4_str,
        "tls_version": flow.tls_version,
        "cipher_suites_count": flow.tls_cipher_count,
        "extensions_count": flow.tls_extension_count,
        "packet_size_sequence": pzx_sequence,
        "inter_arrival_sequence_ms": iat_seq,
        "sni": flow.tls_sni,
    }
