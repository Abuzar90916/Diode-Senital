"""
Fanout and Reconnaissance Feature Calculator for Diode-Sentinel.
Pure stateless function feeding Detector (e): Reconnaissance and Port Scanning.
Identifies horizontal subnet sweeps, vertical port scans, and SYN stealth sweeps
using the windowed GlobalContext.
"""

from typing import Dict, Any


def compute(flow, global_context, current_time: float) -> Dict[str, Any]:
    """
    Computes distinct endpoint cardinality and scanning scores for the flow's source IP.
    """
    dst_ip_cnt, dst_port_cnt, scan_rate, half_open_ratio = global_context.get_fanout_stats(
        flow.src_ip, current_time
    )

    # Horizontal scan indicator: contacts many different destination IPs
    # Normalized between 0.0 and 1.0 (e.g. >= 20 distinct IPs -> 1.0)
    horizontal_score = min(1.0, dst_ip_cnt / 20.0)

    # Vertical scan indicator: contacts many different ports on few hosts
    # Normalized between 0.0 and 1.0 (e.g. >= 30 distinct ports -> 1.0)
    vertical_score = min(1.0, dst_port_cnt / 30.0)

    # Synthetic port entropy: normalized proxy based on port diversity
    port_entropy = min(5.0, (dst_port_cnt / 10.0))

    return {
        "dst_port_count": dst_port_cnt,
        "dst_ip_count": dst_ip_cnt,
        "scan_rate_pps": round(scan_rate, 2),
        "half_open_ratio": round(half_open_ratio, 3),
        "port_entropy": round(port_entropy, 3),
        "horizontal_scan_score": round(horizontal_score, 3),
        "vertical_scan_score": round(vertical_score, 3),
    }
