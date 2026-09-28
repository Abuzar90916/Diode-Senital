"""
Streaming PCAP Reader for Diode-Sentinel.
Strictly Read-Only, One-Way Ingestion using Scapy PcapReader.
Guarantees O(1) memory by streaming packet-by-packet (no rdpcap batch loading).
"""

import os
import time
from typing import Generator, Optional, Tuple, Dict, Any
from scapy.utils import PcapReader
from scapy.packet import Packet


class PcapStreamingReader:
    """
    High-performance streaming reader for PCAP/PCAPNG files.
    Enforces strict read-only access and bounded memory.
    """

    def __init__(self, pcap_path: str, replay_speed: Optional[float] = None):
        """
        :param pcap_path: Path to the .pcap or .pcapng file.
        :param replay_speed: Multiplier for pacing packet delivery based on original capture timestamps.
                             None or <= 0 means maximum throughput (no sleep).
                             1.0 = real-time playback, 2.0 = 2x speed, etc.
        """
        if not os.path.isfile(pcap_path):
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

        self.pcap_path = pcap_path
        self.replay_speed = replay_speed
        self.packets_read = 0
        self.bytes_read = 0
        self.start_wall_time: Optional[float] = None
        self.last_wall_time: Optional[float] = None
        self.first_pkt_time: Optional[float] = None
        self.last_pkt_time: Optional[float] = None

    def stream(self) -> Generator[Packet, None, None]:
        """
        Yields packets one-by-one from the PCAP file.
        Guarantees streaming iterator behavior without loading file into RAM.
        """
        self.packets_read = 0
        self.bytes_read = 0
        self.start_wall_time = time.time()

        with PcapReader(self.pcap_path) as reader:
            for packet in reader:
                pkt_time = float(packet.time)
                pkt_len = len(packet)

                if self.first_pkt_time is None:
                    self.first_pkt_time = pkt_time
                    self.last_pkt_time = pkt_time
                    last_pkt_wall_time = time.time()
                else:
                    # Optional pacing for realistic simulation
                    if self.replay_speed and self.replay_speed > 0:
                        pkt_delta = pkt_time - (self.last_pkt_time or pkt_time)
                        if pkt_delta > 0:
                            sleep_duration = pkt_delta / self.replay_speed
                            # Cap max single packet sleep to 1.0s to avoid hanging on long gaps
                            time.sleep(min(sleep_duration, 1.0))
                    self.last_pkt_time = pkt_time

                self.packets_read += 1
                self.bytes_read += pkt_len
                self.last_wall_time = time.time()

                yield packet

    def get_stats(self) -> Dict[str, Any]:
        """
        Returns runtime statistics for ingestion monitoring.
        """
        elapsed = (self.last_wall_time - self.start_wall_time) if (self.last_wall_time and self.start_wall_time) else 0.0
        pps = (self.packets_read / elapsed) if elapsed > 0 else 0.0
        mbps = (self.bytes_read * 8 / (elapsed * 1_000_000)) if elapsed > 0 else 0.0

        return {
            "pcap_path": self.pcap_path,
            "packets_read": self.packets_read,
            "bytes_read": self.bytes_read,
            "elapsed_wall_sec": round(elapsed, 4),
            "packets_per_sec": round(pps, 2),
            "mbps_sustained": round(mbps, 4),
            "capture_duration_sec": round((self.last_pkt_time - self.first_pkt_time), 4) if (self.last_pkt_time and self.first_pkt_time) else 0.0
        }
