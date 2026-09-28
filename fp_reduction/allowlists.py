import ipaddress
from typing import Set, Optional, List


class AllowlistManager:
    """
    Central, easy-to-audit store for known-good periodic destinations,
    benign client TLS fingerprints (browser, curl, python, IoT),
    internal scanner IPs, trusted cloud ASNs, and top domain lists.
    """

    def __init__(self, enterprise_subnets: Optional[List[str]] = None):
        # Configurable enterprise internal subnets (extends RFC1918 defaults)
        self.internal_networks = [
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
            ipaddress.ip_network("127.0.0.0/8"),
            ipaddress.ip_network("169.254.0.0/16"),
            ipaddress.ip_network("100.64.0.0/10"),  # CGNAT
        ]
        if enterprise_subnets:
            for cidr in enterprise_subnets:
                try:
                    self.internal_networks.append(ipaddress.ip_network(cidr, strict=False))
                except ValueError:
                    pass

        # Known periodic external infrastructure (NTP, cloud agents, OS update servers, telemetry)
        self.known_periodic_destinations: Set[str] = {
            "pool.ntp.org",
            "time.google.com",
            "time.windows.com",
            "time.apple.com",
            "169.254.169.254",          # Cloud IMDS
            "8.8.8.8",
            "1.1.1.1",
            "metrics.internal.local",
            "agent-heartbeat.local",
            "update.microsoft.com",
            "windowsupdate.microsoft.com",
            "time.nist.gov",
            "45.33.22.11",              # Mock clean telemetry/NTP server
        }

        # Known common, benign JA4 hashes (Web browsers, CLI tools, IoT agents, standard OS services)
        self.known_ja4_hashes: Set[str] = {
            "t13d151600_8daaf6152771_014541793740",  # Chrome Desktop
            "t13d151600_8daaf6152771_000000000000",  # Firefox Desktop
            "t13d311200_a371f4152771_112233445566",  # Edge Desktop
            "t13i151600_8daaf6152771_014541793740",  # Standard Windows Update SSL
            "ja4_benign_browser_1",                  # Test stub hash
            "ja4_browser_profile",                   # Client profile: browser
            "ja4_curl_cli_profile",                  # Client profile: curl_cli
            "ja4_python_requests_profile",           # Client profile: python_requests
            "ja4_iot_agent_profile",                 # Client profile: iot_agent
            "t13d1516h2_8daaf6152771_curl",
            "t13d151600_python_requests",
            "t13d080400_iot_agent",
        }

        # Internal vulnerability scanner IPs (Nessus, Qualys, Rapid7, internal security audit hosts)
        self.internal_scanner_ips: Set[str] = {
            "192.168.10.250",           # Standard benign vulnerability scanner appliance
            "192.168.1.100",
            "192.168.1.101",
            "10.0.0.250",
            "172.16.0.99",
        }

        # Trusted Cloud ASNs (AWS, Google, Cloudflare, Azure)
        self.trusted_cloud_asns: Set[int] = {
            16509,  # Amazon AWS
            15169,  # Google Cloud
            13335,  # Cloudflare
            8075,   # Microsoft Azure
            2852,   # CESNET / Czech Technical University (CTU-13 Enclave)
        }

        # Tranco / Alexa top legitimate domains
        self.top_domains: Set[str] = {
            "google.com",
            "microsoft.com",
            "amazonaws.com",
            "cloudflare.com",
            "apple.com",
            "github.com",
            "wikipedia.org",
            "youtube.com",
            "amazon.com",
            "stackoverflow.com",
            "ntro.gov.in",
            "sih.gov.in",
            "example.com",
        }

    def is_known_periodic_dest(self, dest: Optional[str], port: Optional[int] = None) -> bool:
        """Returns True if destination is a known benign periodic service or port."""
        if port == 123:  # NTP port
            return True
        if not dest:
            return False
        dest_lower = dest.lower()
        return any(known in dest_lower for known in self.known_periodic_destinations)

    def is_known_ja4(self, ja4: Optional[str]) -> bool:
        """Returns True if JA4 fingerprint belongs to known benign software."""
        if not ja4:
            return False
        return ja4 in self.known_ja4_hashes

    def is_internal_scanner(self, ip: Optional[str]) -> bool:
        """Returns True if IP address belongs to known internal vulnerability scanner."""
        if not ip:
            return False
        return ip in self.internal_scanner_ips

    def is_trusted_cloud_asn(self, asn: Optional[int]) -> bool:
        """Returns True if ASN belongs to trusted major cloud provider."""
        if asn is None:
            return False
        return asn in self.trusted_cloud_asns

    def is_top_domain(self, domain: Optional[str]) -> bool:
        """Returns True if domain is present in known top domain list."""
        if not domain:
            return False
        domain_lower = domain.lower().strip(".")
        return any(domain_lower == top or domain_lower.endswith("." + top) for top in self.top_domains)

    def is_local_or_private(self, ip_str: Optional[str]) -> bool:
        """
        Network-agnostic check: Returns True if IP address is an RFC1918 private,
        loopback, link-local, multicast, or enterprise internal subnet.
        """
        if not ip_str:
            return False
        try:
            addr = ipaddress.ip_address(ip_str)
            if addr.is_loopback or addr.is_link_local or addr.is_multicast:
                return True
            for net in self.internal_networks:
                if addr in net:
                    return True
        except ValueError:
            pass
        return False
