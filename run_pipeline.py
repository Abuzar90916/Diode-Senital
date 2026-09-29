"""
Master Pipeline Runner for Diode-Sentinel.
Integrates:
- Streaming Ingestion (PcapStreamingReader / LiveStreamingCapture)
- Diode Compliance Watchdog (dual-check zero-egress monitor)
- Sliding-Window Flow Aggregator
- 6 Feature Calculators
- Pydantic FlowFeatureRecord serialization
- 6 ThreatCore detectors, corroboration, persistence, and correlation
- Structured Alert and Incident JSONL output
"""

import os
import sys
import time
import argparse
import json
from typing import Any, Callable, Dict, List, Optional

# Ensure current directory is in path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from ingestion.pcap_reader import PcapStreamingReader
from ingestion.live_capture import LiveStreamingCapture
from ingestion.diode_compliance import DiodeComplianceWatchdog
from ingestion.diode_compliance import DiodeComplianceViolationError
from features.flow_aggregator import FlowAggregator
from schemas.alert_record import Alert, AlertCandidate
from schemas.incident_record import IncidentRecord
from fp_reduction.allowlists import AllowlistManager
from fp_reduction.baseline_store import BaselineStore
from fp_reduction.corroboration import CorroborationEngine
from fp_reduction.persistence_filter import PersistenceFilter
from correlation.chain_matcher import ChainMatcher
from threatcore import (
    DDoSDetector,
    C2BeaconDetector,
    DGADNSDetector,
    EncryptedMalwareDetector,
    PortScanDetector,
    ExfiltrationDetector,
)
from data_generation.benign_traffic_gen import BenignTrafficGenerator
from data_generation.attack_traffic_gen import AttackTrafficGenerator
from benchmark.throughput_bench import ThroughputBenchmark


class RuntimeDetectionEngine:
    """Owns state for the live FlowFeatureRecord-to-Alert path."""

    def __init__(self, required_windows: int = 3):
        self.allowlists = AllowlistManager()
        self.baseline = BaselineStore()
        self.corroborator = CorroborationEngine(default_min_signals=2)
        self.persistence = PersistenceFilter(
            required_windows=required_windows,
            window_ttl_seconds=300,
            min_window_interval_sec=2.0,
        )
        self.chain_matcher = ChainMatcher()
        self.detectors = [
            DDoSDetector(allowlist_manager=self.allowlists),
            C2BeaconDetector(allowlist_manager=self.allowlists),
            DGADNSDetector(allowlist_manager=self.allowlists),
            EncryptedMalwareDetector(allowlist_manager=self.allowlists),
            PortScanDetector(allowlist_manager=self.allowlists),
            ExfiltrationDetector(allowlist_manager=self.allowlists),
        ]

    def process_record(self, record) -> List[Dict[str, Any]]:
        """Evaluate one emitted feature record and return alert/incident events."""
        events: List[Dict[str, Any]] = []
        promoted_alerts: List[Alert] = []

        for detector in self.detectors:
            candidate = detector.detect(record, self.baseline)
            if candidate is None:
                continue
            passed, signal_count, _ = self.corroborator.evaluate_candidate(candidate)
            if not passed:
                continue
            promoted, _, alert = self.persistence.process_candidate(candidate, signal_count)
            if promoted and alert is not None:
                promoted_alerts.append(alert)
                events.append({"type": "ALERT", "data": json.loads(alert.model_dump_json())})

        # Baselines are updated only after detection, preventing the current
        # observation from explaining away its own anomaly.
        self.baseline.update(record.src_ip, "volumetric_rate", record.volumetric.packet_rate_pps, record.window_end)
        self.baseline.update(record.src_ip, "byte_ratio", record.volume_asymmetry.byte_ratio, record.window_end)
        self.baseline.update(record.src_ip, "outbound_byte_rate_bps", record.volume_asymmetry.outbound_byte_rate_bps, record.window_end)

        for incident in self.chain_matcher.process_new_alerts(promoted_alerts):
            events.append({"type": "INCIDENT", "data": json.loads(incident.model_dump_json())})
        return events


def run_pipeline(
    pcap_path: Optional[str] = None,
    interface: Optional[str] = None,
    replay_speed: Optional[float] = None,
    output_records_file: Optional[str] = None,
    output_alerts_file: Optional[str] = None,
    event_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    run_watchdog: bool = True,
    required_windows: int = 3,
    fail_closed: bool = True,
    stop_event: Optional[Any] = None,
):
    print("=================================================================")
    print("  DIODE-SENTINEL: Unidirectional Cyber Threat Feature Engine     ")
    print("  National Technical Research Organisation (NTRO) - SIH 26145   ")
    print("=================================================================")

    watchdog = None
    if run_watchdog:
        print("[+] Starting Dual-Check Diode Compliance Watchdog...")
        # Bind monitored_interface to the specific ingress interface (or loopback in PCAP replay demo mode)
        # to ensure strict zero-egress tracking on the mirror link without false trips from host laptop background adapters.
        target_interface = interface if interface is not None else ("loopback" if pcap_path else None)
        watchdog = DiodeComplianceWatchdog(
            monitored_interface=target_interface,
            check_interval_sec=1.0,
            raise_on_violation=fail_closed,
        )
        watchdog.start()
        status = watchdog.get_status()
        print(f"    Watchdog Status: Egress Bytes: {status['egress_bytes']} | Compliant: {status['compliant']}")

    aggregator = FlowAggregator(
        window_size_sec=15.0,
        slide_interval_sec=5.0,
        flow_idle_timeout_sec=30.0
    )
    detection_engine = RuntimeDetectionEngine(required_windows=required_windows)

    # Ingestion Source
    if pcap_path:
        print(f"[+] Ingesting from PCAP file: {pcap_path}")
        reader = PcapStreamingReader(pcap_path, replay_speed=replay_speed)
        packet_stream = reader.stream()
    elif interface:
        print(f"[+] Ingesting from Live Mirror Interface: {interface} (Read-Only Sniff)")
        live_cap = LiveStreamingCapture(interface=interface)
        packet_stream = live_cap.stream()
    else:
        print("[-] Error: Specify either --pcap <path> or --interface <name>.")
        if watchdog:
            watchdog.stop()
        return

    records_out_handle = None
    alerts_out_handle = None
    if output_records_file:
        records_out_handle = open(output_records_file, "w", encoding="utf-8")
        print(f"[+] Streaming FlowFeatureRecords to: {output_records_file}")
    if output_alerts_file:
        alerts_out_handle = open(output_alerts_file, "w", encoding="utf-8")
        print(f"[+] Streaming Alerts and Incidents to: {output_alerts_file}")

    total_packets = 0
    total_records = 0
    total_alerts = 0
    diode_failure: Optional[str] = None

    def handle_record(record):
        nonlocal total_alerts
        rec_json = record.model_dump_json()
        if records_out_handle:
            records_out_handle.write(rec_json + "\n")
            records_out_handle.flush()
        for event in detection_engine.process_record(record):
            total_alerts += 1 if event["type"] == "ALERT" else 0
            event_json = json.dumps(event, separators=(",", ":"))
            if alerts_out_handle:
                alerts_out_handle.write(event_json + "\n")
                alerts_out_handle.flush()
            if event_callback:
                event_callback(event)
    start_time = time.time()

    try:
        for pkt in packet_stream:
            if stop_event and stop_event.is_set():
                print("[*] Pipeline stop signal received. Halting packet loop.")
                break
            # Immediate fail-closed check if background watchdog detected egress
            if watchdog and not watchdog.compliant:
                reasons = "; ".join(v["reason"] for v in watchdog.violations[-3:])
                diode_failure = f"Diode compliance violation detected mid-stream: {reasons}"
                break
            total_packets += 1
            emitted_records = aggregator.process_packet(pkt)
            if emitted_records:
                total_records += len(emitted_records)
                for rec in emitted_records:
                    handle_record(rec)
                    # Periodic console summary
                    if total_records % 5 == 0:
                        print(f"  [EMIT] Flow: {rec.flow_id[:40]}... | Packets: {rec.volumetric.packet_count} | SynAckRatio: {rec.volumetric.syn_ack_ratio} | IAT CV: {rec.timing.iat_cv} | DNS: {rec.dns_lexical.has_dns} | ExfilScore: {rec.volume_asymmetry.exfil_risk_score}")

        # Final flush if no diode violation
        if not diode_failure:
            final_records = aggregator.flush()
            total_records += len(final_records)
            for rec in final_records:
                handle_record(rec)

    except KeyboardInterrupt:
        print("\n[!] Pipeline interrupted by user.")
    finally:
        if records_out_handle:
            records_out_handle.close()
        if alerts_out_handle:
            alerts_out_handle.close()
        if watchdog:
            try:
                final_status = watchdog.verify_now()
            except DiodeComplianceViolationError as exc:
                if not diode_failure:
                    diode_failure = str(exc)
                watchdog.raise_on_violation = False
                final_status = watchdog.get_status()
            watchdog.stop()
            dual_check = final_status.get("dual_check_status") or {}
            sock_table_status = dual_check.get("process_socket_table", "UNKNOWN")
            nic_counter_status = dual_check.get("nic_io_counter", "UNKNOWN")
            print("\n---------------- DIODE COMPLIANCE REPORT ----------------")
            print(f"  Compliant:            {final_status.get('compliant')}")
            print(f"  Egress Bytes Sent:    {final_status.get('egress_bytes', 0)}")
            print(f"  Socket Table Status:  {sock_table_status}")
            print(f"  NIC Counter Status:   {nic_counter_status}")
            print("---------------------------------------------------------\n")

    if diode_failure:
        print(f"[FATAL] Pipeline halted by diode compliance watchdog: {diode_failure}")
        if event_callback:
            event_callback({"type": "ERROR", "data": {"message": diode_failure}})
        if fail_closed:
            raise DiodeComplianceViolationError(diode_failure)

    elapsed = time.time() - start_time
    pps = total_packets / max(0.001, elapsed)
    print(f"[+] Pipeline complete: {total_packets:,} packets -> {total_records:,} FlowFeatureRecords -> {total_alerts:,} Alerts in {elapsed:.2f}s ({pps:,.1f} pps)")
    return {
        "packets": total_packets,
        "records": total_records,
        "alerts": total_alerts,
        "elapsed_sec": elapsed,
        "packets_per_sec": pps,
        "error": diode_failure,
    }


def main():
    parser = argparse.ArgumentParser(description="Diode-Sentinel Pipeline Runner")
    parser.add_argument("--pcap", type=str, help="Path to PCAP file to replay")
    parser.add_argument("--interface", type=str, help="Network interface for live read-only capture")
    parser.add_argument("--replay-speed", type=float, default=None, help="Playback speed multiplier (e.g. 1.0 = real-time, None = max speed)")
    parser.add_argument("--output", type=str, default="flow_features.jsonl", help="Output file for FlowFeatureRecords (JSON Lines)")
    parser.add_argument("--alerts-output", type=str, default="alerts.jsonl", help="Output file for Alert and Incident JSONL events")
    parser.add_argument("--persistence-windows", type=int, default=3, help="Consecutive windows required for alert promotion (production default: 3; finite PCAP demos may use 1)")
    parser.add_argument("--generate-data", action="store_true", help="Generate all benign and attack PCAPs")
    parser.add_argument("--bench", action="store_true", help="Run the throughput benchmark against SLA targets")
    parser.add_argument("--no-watchdog", action="store_true", help="Disable diode compliance watchdog")
    parser.add_argument("--no-fail-closed", action="store_true", help="Do not halt process with exception on diode leak (default: fail-closed)")

    args = parser.parse_args()

    if args.generate_data:
        print("[+] Generating Benign & Attack PCAPs with ground truth...")
        b_gen = BenignTrafficGenerator(output_dir="data_generation/pcaps")
        b_gen.generate_steady_benign()
        b_gen.generate_bursty_benign()
        a_gen = AttackTrafficGenerator(output_dir="data_generation/pcaps")
        a_gen.generate_all_attacks()
        print("[+] All PCAPs generated successfully in 'data_generation/pcaps/'")
        return

    if args.bench:
        bench = ThroughputBenchmark()
        bench.run_benchmark(pcap_path=args.pcap, test_packet_count=20000)
        return

    if not args.pcap and not args.interface:
        # Default run: generate sample pcap and run through it
        print("[!] No source specified. Generating sample benign PCAP to demonstrate pipeline...")
        b_gen = BenignTrafficGenerator(output_dir="data_generation/pcaps")
        sample_pcap = b_gen.generate_steady_benign(filename="demo_sample.pcap", num_sessions=20)
        run_pipeline(
            pcap_path=sample_pcap,
            output_records_file=args.output,
            output_alerts_file=args.alerts_output,
            run_watchdog=not args.no_watchdog,
            required_windows=args.persistence_windows,
            fail_closed=not args.no_fail_closed,
        )
    else:
        run_pipeline(
            pcap_path=args.pcap,
            interface=args.interface,
            replay_speed=args.replay_speed,
            output_records_file=args.output,
            output_alerts_file=args.alerts_output,
            run_watchdog=not args.no_watchdog,
            required_windows=args.persistence_windows,
            fail_closed=not args.no_fail_closed,
        )


if __name__ == "__main__":
    main()
