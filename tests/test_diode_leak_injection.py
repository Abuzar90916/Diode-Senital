"""
Adversarial Leak Injection Tests for Diode Compliance Watchdog.
Proves that the watchdog ACTUALLY DETECTS violations rather than passively reporting zero.

Strict Testing Philosophy:
All adversarial leak states are injected via in-memory mocking of the OS kernel
inspection points (psutil.Process.net_connections and psutil.net_io_counters).
Zero real network sockets are opened, ensuring 100% deterministic, firewall-safe CI.
"""

import os
import sys
import unittest
import json
from unittest.mock import patch, MagicMock
from collections import namedtuple

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, BASE_DIR)

from ingestion.diode_compliance import (
    DiodeComplianceWatchdog,
    DiodeComplianceViolationError,
)

# Mock types for psutil connection and NIC stats
MockAddr = namedtuple("MockAddr", ["ip", "port"])
MockConn = namedtuple("MockConn", ["fd", "family", "type", "laddr", "raddr", "status", "pid"])
MockNicStats = namedtuple("MockNicStats", ["bytes_sent", "bytes_recv", "packets_sent", "packets_recv", "errin", "errout", "dropin", "dropout"])


class TestDiodeWatchdogLeakInjection(unittest.TestCase):
    """
    Adversarial self-test suite injecting artificial leaks at Level 1 and Level 2.
    """

    def setUp(self):
        self.status_file = os.path.join(BASE_DIR, "tests", "scratch", "test_watchdog_status.json")
        os.makedirs(os.path.dirname(self.status_file), exist_ok=True)

    def tearDown(self):
        if os.path.exists(self.status_file):
            try:
                os.remove(self.status_file)
            except OSError:
                pass
        root_status = os.path.join(BASE_DIR, "diode_compliance_status.json")
        default_status = {
            "compliant": True,
            "egress_bytes": 0,
            "violations_count": 0,
            "recent_violations": [],
            "monitored_interface": "loopback",
            "dual_check_status": {
                "process_socket_table": "CLEAN",
                "nic_io_counter": "CLEAN"
            }
        }
        try:
            with open(root_status, "w", encoding="utf-8") as f:
                json.dump(default_status, f, indent=2)
        except OSError:
            pass

    # -------------------------------------------------------------------------
    # Baseline: Clean state passes compliance
    # -------------------------------------------------------------------------
    @patch("psutil.Process")
    @patch("psutil.net_io_counters")
    def test_clean_baseline_passes(self, mock_io, mock_proc):
        # Clean NIC counters: 1000 bytes baseline, stays at 1000
        mock_io.return_value = {"eth0": MockNicStats(1000, 5000, 10, 50, 0, 0, 0, 0)}
        # Clean loopback only socket
        mock_instance = MagicMock()
        mock_instance.net_connections.return_value = [
            MockConn(1, 2, 1, MockAddr("127.0.0.1", 8080), MockAddr("127.0.0.1", 54321), "ESTABLISHED", 100)
        ]
        mock_proc.return_value = mock_instance

        watchdog = DiodeComplianceWatchdog(monitored_interface="eth0", status_file_path=self.status_file)
        status = watchdog.verify_now()

        self.assertTrue(status["compliant"])
        self.assertEqual(status["egress_bytes"], 0)
        self.assertEqual(status["dual_check_status"]["process_socket_table"], "CLEAN")
        self.assertEqual(status["dual_check_status"]["nic_io_counter"], "CLEAN")
        self.assertEqual(status["violations_count"], 0)

    # -------------------------------------------------------------------------
    # Level 1 Adversarial Test: Socket table leak (unauthorized outbound connection)
    # -------------------------------------------------------------------------
    @patch("psutil.Process")
    @patch("psutil.net_io_counters")
    def test_adversarial_level1_socket_leak(self, mock_io, mock_proc):
        """
        Adversarial Test: Deliberately injects an active outbound TCP connection
        to external IP 198.51.100.88 (exfil server) inside process connection table.
        Asserts the watchdog catches it and flags compliant: false.
        """
        mock_io.return_value = {"eth0": MockNicStats(1000, 5000, 10, 50, 0, 0, 0, 0)}
        mock_instance = MagicMock()
        
        # Inject illegal remote connection (non-loopback destination)
        illegal_socket = MockConn(
            fd=5, family=2, type=1,
            laddr=MockAddr("192.168.1.100", 49152),
            raddr=MockAddr("198.51.100.88", 443),
            status="ESTABLISHED", pid=100
        )
        mock_instance.net_connections.return_value = [illegal_socket]
        mock_proc.return_value = mock_instance

        watchdog = DiodeComplianceWatchdog(monitored_interface="eth0", status_file_path=self.status_file)
        with self.assertRaises(DiodeComplianceViolationError):
            watchdog.verify_now()

        # Assertions proving the watchdog actively caught the violation
        with open(self.status_file, "r", encoding="utf-8") as handle:
            status = json.load(handle)
        self.assertFalse(status["compliant"], "Watchdog failed to flag illegal outbound socket!")
        self.assertEqual(status["dual_check_status"]["process_socket_table"], "VIOLATION_DETECTED")
        self.assertGreaterEqual(status["violations_count"], 1)
        self.assertTrue(any("198.51.100.88:443" in v["reason"] for v in watchdog.violations))

    # -------------------------------------------------------------------------
    # Level 2 Adversarial Test: NIC raw-socket byte egress
    # -------------------------------------------------------------------------
    @patch("psutil.Process")
    @patch("psutil.net_io_counters")
    def test_adversarial_level2_raw_packet_leak(self, mock_io, mock_proc):
        """
        Adversarial Test: Injects an artificial positive delta on the capture interface's
        bytes_sent counter (simulating an unauthorized scapy.sendp() or raw socket write).
        Asserts the watchdog catches the delta and records egress bytes.
        """
        # Clean sockets
        mock_instance = MagicMock()
        mock_instance.net_connections.return_value = []
        mock_proc.return_value = mock_instance

        # Initial baseline: 10,000 bytes sent
        mock_io.return_value = {"eth0": MockNicStats(10000, 50000, 100, 500, 0, 0, 0, 0)}
        watchdog = DiodeComplianceWatchdog(monitored_interface="eth0", status_file_path=self.status_file)
        
        # Verify initial clean check
        initial_status = watchdog.verify_now()
        self.assertTrue(initial_status["compliant"])

        # INJECT LEAK: Interface bytes_sent jumps by 4,096 bytes (e.g. 4 raw packets sent)
        mock_io.return_value = {"eth0": MockNicStats(14096, 50000, 104, 500, 0, 0, 0, 0)}
        
        with self.assertRaises(DiodeComplianceViolationError):
            watchdog.verify_now()

        # Assertions proving Level 2 raw-egress detection
        with open(self.status_file, "r", encoding="utf-8") as handle:
            leaked_status = json.load(handle)
        self.assertFalse(leaked_status["compliant"], "Watchdog failed to detect raw byte egress delta!")
        self.assertEqual(leaked_status["dual_check_status"]["nic_io_counter"], "RAW_EGRESS_DETECTED")
        self.assertEqual(leaked_status["egress_bytes"], 4096)
        self.assertTrue(any("4096 bytes" in v["reason"] for v in watchdog.violations))

    # -------------------------------------------------------------------------
    # Fail-Closed Enforcement: Exception raised on leak
    # -------------------------------------------------------------------------
    @patch("psutil.Process")
    @patch("psutil.net_io_counters")
    def test_adversarial_fail_closed_exception(self, mock_io, mock_proc):
        """
        Asserts that when raise_on_violation=True, any leak immediately halts execution
        by raising DiodeComplianceViolationError.
        """
        mock_instance = MagicMock()
        mock_instance.net_connections.return_value = [
            MockConn(5, 2, 1, MockAddr("192.168.1.100", 50000), MockAddr("8.8.8.8", 53), "SYN_SENT", 100)
        ]
        mock_proc.return_value = mock_instance
        mock_io.return_value = {"eth0": MockNicStats(1000, 1000, 10, 10, 0, 0, 0, 0)}

        watchdog = DiodeComplianceWatchdog(
            monitored_interface="eth0",
            status_file_path=self.status_file,
            raise_on_violation=True
        )

        with self.assertRaises(DiodeComplianceViolationError) as ctx:
            watchdog.verify_now()

        self.assertIn("Diode compliance violation detected", str(ctx.exception))

    # -------------------------------------------------------------------------
    # Default CLI & run_pipeline Fail-Closed Enforcement
    # -------------------------------------------------------------------------
    @patch("psutil.Process")
    @patch("psutil.net_io_counters")
    def test_adversarial_run_pipeline_default_cli_fail_closed(self, mock_io, mock_proc):
        """
        Proves that run_pipeline() with default settings (fail_closed=True)
        halts execution and re-raises DiodeComplianceViolationError upon detecting an illegal socket.
        """
        from run_pipeline import run_pipeline
        mock_instance = MagicMock()
        mock_instance.net_connections.return_value = [
            MockConn(5, 2, 1, MockAddr("192.168.1.100", 50000), MockAddr("198.51.100.88", 443), "ESTABLISHED", 100)
        ]
        mock_proc.return_value = mock_instance
        mock_io.return_value = {"loopback": MockNicStats(1000, 1000, 10, 10, 0, 0, 0, 0)}

        test_pcap = os.path.join(BASE_DIR, "data_generation", "pcaps", "attack_portscan.pcap")

        with self.assertRaises(DiodeComplianceViolationError) as ctx:
            run_pipeline(
                pcap_path=test_pcap,
                output_records_file=None,
                output_alerts_file=None,
                run_watchdog=True,
                fail_closed=True,
            )

        self.assertIn("Diode compliance violation detected", str(ctx.exception))

    # -------------------------------------------------------------------------
    # Dashboard Server RuntimeController Fail-Closed Enforcement
    # -------------------------------------------------------------------------
    @patch("psutil.Process")
    @patch("psutil.net_io_counters")
    def test_adversarial_dashboard_server_runtime_fail_closed(self, mock_io, mock_proc):
        """
        Proves that dashboard/server.py's RuntimeController fails closed when a leak occurs,
        capturing DiodeComplianceViolationError in last_error, publishing an ERROR event,
        and setting running=False.
        """
        from dashboard.server import RuntimeController
        mock_instance = MagicMock()
        mock_instance.net_connections.return_value = [
            MockConn(5, 2, 1, MockAddr("192.168.1.100", 50000), MockAddr("203.0.113.99", 80), "SYN_SENT", 100)
        ]
        mock_proc.return_value = mock_instance
        mock_io.return_value = {"loopback": MockNicStats(1000, 1000, 10, 10, 0, 0, 0, 0)}

        test_pcap = os.path.join(BASE_DIR, "data_generation", "pcaps", "attack_portscan.pcap")
        rc = RuntimeController()
        rc.start(pcap=test_pcap)

        # Wait for worker thread to terminate
        if rc.thread and rc.thread.is_alive():
            rc.thread.join(timeout=5.0)

        status = rc.status()
        self.assertFalse(status["running"], "RuntimeController failed to stop running on diode leak!")
        self.assertIsNotNone(status["last_error"], "RuntimeController failed to capture diode error!")
        self.assertIn("Diode compliance violation detected", status["last_error"])

        # Check published error event
        error_events = rc.snapshot("ERROR")
        self.assertGreaterEqual(len(error_events), 1)
        self.assertIn("Diode compliance violation detected", error_events[0]["data"]["message"])


if __name__ == "__main__":
    unittest.main(verbosity=2)

