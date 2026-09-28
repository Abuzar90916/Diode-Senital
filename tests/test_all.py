"""
Comprehensive Test Suite for Diode-Sentinel.
Validates:
1. Schemas & serialization contracts (Pydantic v2)
2. Dual-check diode compliance watchdog
3. Sliding window flow aggregator and windowed GlobalContext TTL eviction
4. The six feature calculators against known mathematical ground truth
5. Synthetic PCAP generation and streaming replay
"""

import os
import sys
import math
import time
import unittest

# Ensure diode-sentinel is in sys.path
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, BASE_DIR)

from scapy.config import conf
conf.verb = 0

from scapy.all import IP, TCP, UDP, DNS, DNSQR, Ether, wrpcap
from schemas.flow_feature_record import FlowFeatureRecord
from ingestion.pcap_reader import PcapStreamingReader
from ingestion.diode_compliance import DiodeComplianceWatchdog
from features.flow_aggregator import Flow, FlowAggregator, WindowedGlobalContext
from features import (
    volumetric,
    timing,
    dns_lexical,
    crypto_metadata,
    fanout,
    volume_asymmetry,
)


class TestDiodeSentinel(unittest.TestCase):

    def setUp(self):
        self.temp_dir = os.path.join(BASE_DIR, "tests", "scratch")
        os.makedirs(self.temp_dir, exist_ok=True)

    # -------------------------------------------------------------------------
    # 1. Schemas Contract Verification
    # -------------------------------------------------------------------------
    def test_schema_contract_serialization(self):
        record = FlowFeatureRecord.create_empty(
            flow_id="192.168.1.5:1234->8.8.8.8:53/UDP",
            src_ip="192.168.1.5",
            src_port=1234,
            dst_ip="8.8.8.8",
            dst_port=53,
            protocol="UDP"
        )
        # Verify sub-models are initialized
        self.assertIsNotNone(record.volumetric)
        self.assertIsNotNone(record.timing)
        self.assertIsNotNone(record.dns_lexical)
        self.assertIsNotNone(record.crypto_metadata)
        self.assertIsNotNone(record.fanout)
        self.assertIsNotNone(record.volume_asymmetry)

        # Verify JSON serialization works without error
        self.assertEqual(record.window_duration_sec, 30.0)
        json_str = record.model_dump_json()
        self.assertIn("192.168.1.5", json_str)
        self.assertIn("volumetric", json_str)
        self.assertIn("window_duration_sec", json_str)

    # -------------------------------------------------------------------------
    # 2. Dual-Check Diode Compliance Watchdog
    # -------------------------------------------------------------------------
    def test_diode_compliance_watchdog(self):
        status_file = os.path.join(self.temp_dir, "test_compliance.json")
        watchdog = DiodeComplianceWatchdog(
            check_interval_sec=0.2,
            status_file_path=status_file
        )
        # Verify initial check passes
        status = watchdog.verify_now()
        self.assertTrue(status["compliant"])
        self.assertEqual(status["egress_bytes"], 0)
        self.assertEqual(status["dual_check_status"]["process_socket_table"], "CLEAN")
        self.assertEqual(status["dual_check_status"]["nic_io_counter"], "CLEAN")
        self.assertTrue(os.path.exists(status_file))

    # -------------------------------------------------------------------------
    # 3. GlobalContext Windowed TTL Eviction (Risk 3 Verification)
    # -------------------------------------------------------------------------
    def test_global_context_ttl_eviction(self):
        ctx = WindowedGlobalContext(window_ttl_sec=5.0)
        t0 = 1000.0

        # Record activity at t0
        ctx.record_activity(timestamp=t0, src_ip="10.0.0.1", dst_ip="1.1.1.1", dst_port=80)
        ctx.record_activity(timestamp=t0, src_ip="10.0.0.1", dst_ip="2.2.2.2", dst_port=443)
        ctx.record_activity(timestamp=t0, src_ip="10.0.0.2", dst_ip="3.3.3.3", dst_port=80)

        # Before eviction (at t0 + 2s): source 10.0.0.1 has touched 2 IPs, 2 ports
        dst_ips, dst_ports, scan_rate, half_open = ctx.get_fanout_stats("10.0.0.1", current_time=t0 + 2.0)
        self.assertEqual(dst_ips, 2)
        self.assertEqual(dst_ports, 2)

        # Advance time to t0 + 6.0s (past 5.0s window TTL)
        ctx.evict_expired(current_time=t0 + 6.0)

        # Assert memory is cleanly evicted and keys purged (O(1) memory bound)
        self.assertNotIn("10.0.0.1", ctx.src_activity)
        self.assertNotIn("10.0.0.2", ctx.src_activity)
        self.assertEqual(len(ctx.recent_sources), 0)

    # -------------------------------------------------------------------------
    # 4. Feature Calculators Unit Testing
    # -------------------------------------------------------------------------
    def test_volumetric_calculator(self):
        flow = Flow("192.168.1.10", 45000, "10.0.0.1", 80, "TCP", 100.0)
        flow.packet_count = 100
        flow.byte_count = 15000
        flow.syn_count = 95
        flow.ack_count = 5

        ctx = WindowedGlobalContext(window_ttl_sec=30.0)
        result = volumetric.compute(flow, ctx, current_time=130.0, window_sec=30.0)

        # SYN:ACK ratio = 95 / 5 = 19.0
        self.assertEqual(result["syn_ack_ratio"], 19.0)
        self.assertAlmostEqual(result["packet_rate_pps"], 100 / 30.0, places=1)
        self.assertEqual(result["tcp_count"], 100)

    def test_timing_periodicity_calculator(self):
        flow = Flow("192.168.1.10", 45000, "10.0.0.1", 80, "TCP", 100.0)
        # Synthetic strict periodic timestamps (every 2.0 seconds) -> C2 beacon profile
        for i in range(10):
            flow.timestamps.append(100.0 + (i * 2.0))

        result = timing.compute(flow, current_time=125.0, window_sec=30.0)
        # Strict periodicity should have near 0 CV and high periodicity score
        self.assertAlmostEqual(result["iat_mean_ms"], 2000.0, delta=10.0)
        self.assertLess(result["iat_cv"], 0.05)
        self.assertGreater(result["periodicity_score"], 0.70)

    def test_dns_lexical_calculator(self):
        # Benign domain
        benign_flow = Flow("10.0.0.2", 53000, "8.8.8.8", 53, "UDP", 100.0)
        benign_flow.has_dns = True
        benign_flow.dns_query_name = "google.com"
        benign_flow.dns_record_type = "A"

        res_benign = dns_lexical.compute(benign_flow)
        self.assertLess(res_benign["shannon_entropy"], 3.2)
        self.assertFalse(res_benign["is_tunnel_candidate"])

        # Malicious DGA / Tunnel domain (dnscat2 long hex string)
        mal_flow = Flow("10.0.0.3", 53000, "8.8.8.8", 53, "UDP", 100.0)
        mal_flow.has_dns = True
        mal_flow.dns_query_name = "dnscat.a8f9c1b2d3e4f5a6b7c8d9e012345678.tunnel.attacker-c2.net"
        mal_flow.dns_record_type = "TXT"

        res_mal = dns_lexical.compute(mal_flow)
        self.assertGreater(res_mal["shannon_entropy"], 3.5)
        self.assertTrue(res_mal["is_txt_or_null"])
        self.assertTrue(res_mal["is_tunnel_candidate"])

    def test_volume_asymmetry_calculator(self):
        # Full-duplex mirror test: heavy upload exfil
        flow = Flow("192.168.1.99", 54321, "198.51.100.1", 443, "TCP", 100.0)
        flow.last_seen = 110.0
        flow.fwd_bytes = 500_000
        flow.bwd_bytes = 5_000  # 100:1 ratio

        result = volume_asymmetry.compute(flow)
        self.assertFalse(result["is_unidirectional_fallback"])
        self.assertEqual(result["byte_ratio"], 100.0)
        self.assertGreater(result["exfil_risk_score"], 0.7)

    # -------------------------------------------------------------------------
    # 5. Streaming PCAP Ingest & Replay Test
    # -------------------------------------------------------------------------
    def test_streaming_pcap_reader(self):
        test_pcap = os.path.join(self.temp_dir, "test_stream.pcap")
        pkts = [
            Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=1000 + i, dport=80)
            for i in range(20)
        ]
        wrpcap(test_pcap, pkts)

        reader = PcapStreamingReader(test_pcap)
        count = 0
        for pkt in reader.stream():
            count += 1
            self.assertEqual(pkt[IP].src, "192.168.1.1")

        self.assertEqual(count, 20)
        stats = reader.get_stats()
        self.assertEqual(stats["packets_read"], 20)


if __name__ == "__main__":
    unittest.main(verbosity=2)
