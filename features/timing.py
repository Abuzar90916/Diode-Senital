"""
Timing and Periodicity Feature Calculator for Diode-Sentinel.
Pure stateless function feeding Detector (b): Botnet C2 Beaconing.
Analyzes Inter-Arrival Time (IAT) distribution, coefficient of variation,
and periodicity signals to identify automated C2 callback heartbeats.
"""

import math
from typing import Dict, Any, List


def compute(flow, current_time: float, window_sec: float) -> Dict[str, Any]:
    """
    Calculates IAT statistics (mean, variance, CV) and periodicity score
    over the flow's packet timestamp sequence within the active window.
    """
    cutoff = current_time - window_sec
    # Extract timestamps within active window
    window_ts = [t for t in flow.timestamps if t >= cutoff]
    n_packets = len(window_ts)

    if n_packets < 2:
        return {
            "packet_count": n_packets,
            "iat_mean_ms": 0.0,
            "iat_std_ms": 0.0,
            "iat_cv": 0.0,
            "iat_min_ms": 0.0,
            "iat_max_ms": 0.0,
            "periodicity_score": 0.0,
            "jitter_pct": 0.0,
        }

    # Inter-arrival times in milliseconds
    iats: List[float] = [
        (window_ts[i] - window_ts[i - 1]) * 1000.0
        for i in range(1, n_packets)
    ]
    m = len(iats)

    mean_iat = sum(iats) / m
    variance = sum((x - mean_iat) ** 2 for x in iats) / m
    std_iat = math.sqrt(variance)

    # Coefficient of Variation: CV < 0.2 indicates tight deterministic periodicity (C2 beacon)
    # Poisson (benign human) traffic typically has CV >= 1.0
    cv = (std_iat / mean_iat) if mean_iat > 0 else 0.0

    min_iat = min(iats)
    max_iat = max(iats)

    # Periodicity score based on low CV and normalized lag-1 autocorrelation
    if variance < 1e-5:
        # Near-zero variance indicates perfect deterministic clockwork periodicity
        autocorr = 1.0
        regularity = 1.0
        periodicity_score = 1.0
    else:
        autocorr = 0.0
        if m >= 4:
            # Lag-1 autocorrelation
            num = sum((iats[i] - mean_iat) * (iats[i - 1] - mean_iat) for i in range(1, m))
            den = sum((x - mean_iat) ** 2 for x in iats)
            autocorr = max(0.0, min(1.0, num / den if den > 0 else 0.0))

        # Periodicity score: combines low variance / CV with autocorrelation strength
        # 1.0 = perfect regular clockwork heartbeat, 0.0 = completely irregular
        regularity = max(0.0, 1.0 - min(1.0, cv))
        periodicity_score = round(0.6 * regularity + 0.4 * autocorr, 3)

    # Jitter estimate: deviation spread relative to mean
    jitter_pct = min(100.0, round(((max_iat - min_iat) / max(1.0, mean_iat)) * 50.0, 2))

    return {
        "packet_count": n_packets,
        "iat_mean_ms": round(mean_iat, 2),
        "iat_std_ms": round(std_iat, 2),
        "iat_cv": round(cv, 4),
        "iat_min_ms": round(min_iat, 2),
        "iat_max_ms": round(max_iat, 2),
        "periodicity_score": periodicity_score,
        "jitter_pct": jitter_pct,
    }
