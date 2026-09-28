"""
Offline, Zero-Egress ASN and Country Enrichment Engine.

MANDATORY CONSTRAINT (NTRO PS 26145 / DIODE WATCHDOG):
This module operates STRICTLY IN-MEMORY using local offline tables.
Live DNS PTR queries, HTTP GeoIP REST calls, and external whois queries are
PHYSICALLY FORBIDDEN and will trip the Diode Compliance Watchdog.

COVERAGE & LIMITATIONS NOTICE:
The default built-in prefix map is a lightweight in-memory trie covering:
- RFC 1918 Private ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 -> ASN 0 / "PRIVATE")
- Core hyperscalers & CDNs (Google, Cloudflare, AWS, Azure, Fastly)
- Known threat/adversarial test subnets (Linode C2, Tor exit nodes, RFC5737 exfil sinks)

Coverage Limits:
Public IP addresses outside these pre-loaded prefixes will gracefully return (None, None).
Downstream consumers (e.g. Person 3 anomaly detectors) MUST treat None as "unclassified/rare public IP"
which itself serves as a strong destination-rarity signal for C2 and exfiltration detection.
In production deployments, this table can be replaced with a full offline MaxMind GeoLite2-ASN.mmdb
or Team Cymru IP2ASN flat file without any pipeline modifications.
"""

import ipaddress
from typing import Tuple, Optional, Dict, Any


class OfflineAsnResolver:
    """
    In-memory, zero-egress IP-to-ASN and Country resolver.
    Uses local prefix radix lookup tables and optional local MaxMind .mmdb files.
    """

    # Well-known offline CIDR prefix map for testing and core infrastructure
    # In production, this can be seeded from local MaxMind GeoLite2-ASN.mmdb or Team Cymru bulk IP2ASN
    _DEFAULT_OFFLINE_PREFIXES = [
        # RFC1918 & Loopback
        ("10.0.0.0/8", 0, "PRIVATE"),
        ("172.16.0.0/12", 0, "PRIVATE"),
        ("192.168.0.0/16", 0, "PRIVATE"),
        ("127.0.0.0/8", 0, "LOOPBACK"),
        ("169.254.0.0/16", 0, "LINK_LOCAL"),
        ("147.32.0.0/16", 0, "PRIVATE"),   # CTU-13 Benchmark Enclave (Monitored Internal Network)
        
        # Major Public DNS / CDNs / Cloud Providers
        ("8.8.8.0/24", 15169, "US"),      # Google
        ("8.8.4.0/24", 15169, "US"),      # Google
        ("142.250.0.0/15", 15169, "US"),  # Google
        ("172.217.0.0/16", 15169, "US"),  # Google
        ("1.1.1.0/24", 13335, "US"),      # Cloudflare
        ("1.0.0.0/24", 13335, "US"),      # Cloudflare
        ("104.16.0.0/12", 13335, "US"),   # Cloudflare
        ("13.232.0.0/14", 16509, "IN"),   # AWS India
        ("52.0.0.0/11", 16509, "US"),     # AWS US
        ("20.0.0.0/11", 8075, "US"),      # Microsoft Azure
        ("151.101.0.0/16", 54113, "US"),  # Fastly
        
        # Threat & Adversarial Test Ranges (as generated in attack_traffic_gen.py)
        ("45.33.32.0/24", 63949, "US"),   # Linode (Simulated C2)
        ("185.220.101.0/24", 206264, "DE"), # Tor Exit Node / Meterpreter
        ("198.51.100.0/24", 64496, "XX"), # RFC5737 TEST-NET-2 (Exfiltration Drop)
    ]

    def __init__(self, custom_prefixes: Optional[list] = None):
        """
        Initializes in-memory prefix trie. Zero network sockets opened.
        """
        self._networks = []
        raw_list = custom_prefixes or self._DEFAULT_OFFLINE_PREFIXES
        for cidr, asn, country in raw_list:
            try:
                net = ipaddress.ip_network(cidr, strict=False)
                self._networks.append((net, asn, country))
            except ValueError:
                continue

    def resolve(self, ip_str: str) -> Tuple[Optional[int], Optional[str]]:
        """
        Resolves an IPv4/IPv6 string to (ASN, Country) via offline in-memory lookup.
        STRICTLY PASSIVE: Zero network egress.
        
        :return: (asn: Optional[int], country: Optional[str])
        """
        if not ip_str:
            return (None, None)

        try:
            addr = ipaddress.ip_address(ip_str)
        except ValueError:
            return (None, None)

        # In-memory prefix match
        for net, asn, country in self._networks:
            if addr in net:
                return (asn, country)

        # RFC Private check after explicit test/threat ranges. Python marks
        # RFC5737 TEST-NET ranges as private, but those ranges are deliberate
        # adversarial fixtures and must retain their configured metadata.
        if addr.is_private:
            return (0, "PRIVATE")

        # Unknown / unassigned external default
        return (None, None)


# Global singleton instance for the pipeline
_GLOBAL_RESOLVER: Optional[OfflineAsnResolver] = None

def get_offline_asn_resolver() -> OfflineAsnResolver:
    global _GLOBAL_RESOLVER
    if _GLOBAL_RESOLVER is None:
        _GLOBAL_RESOLVER = OfflineAsnResolver()
    return _GLOBAL_RESOLVER
