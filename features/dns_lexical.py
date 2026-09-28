"""
DNS Lexical and Structural Feature Calculator for Diode-Sentinel.
Pure stateless function feeding Detector (c): DGA Domains and DNS Tunnelling.
Extracts QNAME character Shannon entropy, consonant-vowel balance, query length,
and record-type anomalies (TXT, NULL, ANY) indicative of dnscat2 or iodine exfiltration.
"""

import math
from collections import Counter
from typing import Dict, Any


def compute(flow) -> Dict[str, Any]:
    """
    Computes lexical features of DNS query name and checks for tunnel indicators.
    """
    if not flow.has_dns or not flow.dns_query_name:
        return {
            "has_dns": False,
            "query_name": None,
            "query_length": 0,
            "shannon_entropy": 0.0,
            "consonant_vowel_ratio": 0.0,
            "numeric_char_ratio": 0.0,
            "subdomain_count": 0,
            "record_type": None,
            "is_txt_or_null": False,
            "is_tunnel_candidate": False,
        }

    qname = flow.dns_query_name.lower().strip(".")
    qlen = len(qname)
    rec_type = flow.dns_record_type or "A"

    if qlen == 0:
        return {
            "has_dns": True,
            "query_name": "",
            "query_length": 0,
            "shannon_entropy": 0.0,
            "consonant_vowel_ratio": 0.0,
            "numeric_char_ratio": 0.0,
            "subdomain_count": 0,
            "record_type": rec_type,
            "is_txt_or_null": False,
            "is_tunnel_candidate": False,
        }

    # Shannon entropy of characters: H = -sum(p * log2(p))
    # Benign domains: 2.0 - 3.2. DGAs / Base64 / Hex DNS tunnels: 3.8 - 4.8
    char_counts = Counter(qname)
    entropy = -sum((cnt / qlen) * math.log2(cnt / qlen) for cnt in char_counts.values())

    # Consonant to vowel ratio
    vowels = set("aeiou")
    letters = [c for c in qname if c.isalpha()]
    vowel_cnt = sum(1 for c in letters if c in vowels)
    consonant_cnt = len(letters) - vowel_cnt
    consonant_vowel_ratio = (consonant_cnt / max(1, vowel_cnt)) if vowel_cnt > 0 else float(consonant_cnt)

    # Numeric ratio
    digits_cnt = sum(1 for c in qname if c.isdigit())
    numeric_ratio = digits_cnt / qlen

    # Subdomain depth
    labels = qname.split(".")
    subdomain_count = len(labels)

    # Tunnel anomaly heuristics
    is_txt_or_null = rec_type.upper() in ("TXT", "NULL", "ANY")
    # Tunnels like dnscat2 / iodine typically produce long queries (>45 chars) with high entropy
    is_tunnel_candidate = (qlen >= 45 and entropy >= 3.5) or (is_txt_or_null and qlen >= 30)

    return {
        "has_dns": True,
        "query_name": flow.dns_query_name,
        "query_length": qlen,
        "shannon_entropy": round(entropy, 4),
        "consonant_vowel_ratio": round(consonant_vowel_ratio, 2),
        "numeric_char_ratio": round(numeric_ratio, 3),
        "subdomain_count": subdomain_count,
        "record_type": rec_type,
        "is_txt_or_null": is_txt_or_null,
        "is_tunnel_candidate": is_tunnel_candidate,
    }
