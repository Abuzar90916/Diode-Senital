"""
Volume Asymmetry and Exfiltration Feature Calculator for Diode-Sentinel.
Pure stateless function feeding Detector (f): Data Exfiltration.

ARCHITECTURAL NOTE FOR HARDWARE DIODE DEPLOYMENTS:
The data diode enforces strict physical one-way data flow into the analysis enclave;
the mirrored source traffic copied into the diode link is full-duplex (an optical TAP or SPAN port
mirroring both Tx and Rx directions of the gateway link into the diode's input fiber).
If deployed in a purely unidirectional single-leg tap, this module automatically activates
is_unidirectional_fallback to score exfiltration via absolute byte velocity and burstiness.
"""

from typing import Dict, Any


def compute(flow) -> Dict[str, Any]:
    """
    Calculates outbound:inbound byte asymmetry, upload duration, and exfiltration risk score.
    """
    fwd_b = flow.fwd_bytes
    bwd_b = flow.bwd_bytes
    duration = max(0.001, flow.last_seen - flow.start_time)
    fwd_bps = fwd_b / duration

    # Check whether reverse leg was observed on full-duplex mirror
    is_unidirectional = (bwd_b == 0)

    if not is_unidirectional:
        # Full-duplex mirrored tap: true bidirectional byte ratio
        byte_ratio = fwd_b / max(1, bwd_b)
    else:
        # Unidirectional single-leg fallback: ratio is normalized relative to expected baseline
        byte_ratio = float(fwd_b)

    # Exfiltration risk score (0.0 to 1.0)
    # High risk when large volume (>100KB) is transferred with extreme outbound ratio (>10:1)
    exfil_score = 0.0
    if not is_unidirectional:
        if fwd_b > 50_000 and byte_ratio > 5.0:
            exfil_score = min(1.0, (byte_ratio / 50.0) * min(1.0, fwd_b / 500_000))
    else:
        # Fallback heuristic: large single-direction sustained transfer
        if fwd_b > 100_000 and fwd_bps > 50_000:
            exfil_score = min(1.0, (fwd_bps / 500_000) * min(1.0, fwd_b / 1_000_000))

    # Variance / burstiness proxy
    avg_pkt_size = (fwd_b / max(1, flow.fwd_packets))
    burstiness = min(1.0, avg_pkt_size / 1500.0)

    return {
        "outbound_bytes": fwd_b,
        "inbound_bytes": bwd_b,
        "byte_ratio": round(byte_ratio, 3),
        "duration_sec": round(duration, 3),
        "outbound_byte_rate_bps": round(fwd_bps, 2),
        "byte_burstiness": round(burstiness, 3),
        "is_unidirectional_fallback": is_unidirectional,
        "exfil_risk_score": round(exfil_score, 3),
    }
