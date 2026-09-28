"""
Volumetric and Protocol DDoS Feature Calculator for Diode-Sentinel.
Pure stateless function feeding Detector (a).
Identifies SYN floods, UDP reflection/amplification, and spoofed-source storms.
"""

from typing import Dict, Any


def compute(flow, global_context, current_time: float, window_sec: float) -> Dict[str, Any]:
    """
    Computes volumetric flow rate, protocol distributions, SYN:ACK asymmetry,
    and windowed source-IP Shannon entropy.
    """
    pkt_count = flow.packet_count
    byte_count = flow.byte_count

    duration = max(1.0, window_sec)
    pps = pkt_count / duration
    bps = byte_count / duration

    # SYN:ACK ratio: In normal TCP, ACK >= SYN. In SYN floods, SYN >> ACK.
    syn_ack_ratio = (flow.syn_count / max(1, flow.ack_count)) if flow.syn_count > 0 else 0.0

    # Protocol counts
    tcp_count = flow.packet_count if flow.protocol == "TCP" else 0
    udp_count = flow.packet_count if flow.protocol == "UDP" else 0
    icmp_count = flow.packet_count if flow.protocol.startswith("ICMP") else 0

    # Source IP entropy from windowed GlobalContext
    src_entropy = global_context.get_source_ip_entropy(current_time)

    avg_pkt_size = (byte_count / pkt_count) if pkt_count > 0 else 0.0

    return {
        "packet_count": pkt_count,
        "byte_count": byte_count,
        "packet_rate_pps": round(pps, 2),
        "byte_rate_bps": round(bps, 2),
        "src_ip_entropy": src_entropy,
        "syn_ack_ratio": round(syn_ack_ratio, 3),
        "syn_count": flow.syn_count,
        "ack_count": flow.ack_count,
        "fin_count": flow.fin_count,
        "rst_count": flow.rst_count,
        "udp_count": udp_count,
        "tcp_count": tcp_count,
        "icmp_count": icmp_count,
        "zero_window_count": flow.zero_window_count,
        "avg_packet_size": round(avg_pkt_size, 2)
    }
