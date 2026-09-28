"""
Live Interface Capture for Diode-Sentinel.
Strictly Read-Only, Promiscuous Sniffing on a Mirrored Data Diode Port.
Never binds an outbound or send-capable socket.
Yields packets via the exact same generator interface as PcapStreamingReader.
"""

import time
import queue
import threading
from typing import Generator, Optional, Dict, Any
from scapy.all import sniff
from scapy.packet import Packet


class LiveStreamingCapture:
    """
    Reads packets continuously from a mirrored network tap / data diode interface.
    Uses an internal bounded FIFO queue to decouple Scapy packet capture from
    downstream flow aggregation processing without memory spikes.
    """

    def __init__(self, interface: Optional[str] = None, bpf_filter: str = "ip or ip6", max_queue_size: int = 10000):
        """
        :param interface: Name of network interface (e.g., 'eth1', 'Ethernet 2'). If None, uses default.
        :param bpf_filter: BPF filter string to isolate IP traffic at kernel level.
        :param max_queue_size: Maximum packets buffered in memory queue (bounded memory protection).
        """
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.max_queue_size = max_queue_size
        self.packet_queue: queue.Queue = queue.Queue(maxsize=max_queue_size)
        self.running = False
        self.sniffer_thread: Optional[threading.Thread] = None

        self.packets_captured = 0
        self.packets_dropped = 0
        self.bytes_captured = 0
        self.start_wall_time: Optional[float] = None
        self.last_wall_time: Optional[float] = None

    def _packet_handler(self, packet: Packet):
        """Callback invoked by Scapy sniff on each incoming packet (RX only)."""
        self.packets_captured += 1
        self.bytes_captured += len(packet)
        self.last_wall_time = time.time()
        try:
            self.packet_queue.put_nowait(packet)
        except queue.Full:
            self.packets_dropped += 1

    def _sniffer_worker(self):
        """Worker thread running Scapy sniff in read-only promiscuous mode."""
        try:
            # strictly store=False to avoid in-memory accumulation
            sniff(
                iface=self.interface,
                filter=self.bpf_filter,
                prn=self._packet_handler,
                store=False,
                stop_filter=lambda _: not self.running
            )
        except Exception as e:
            # In case of interface access failure, signal end of queue with None
            self.packet_queue.put(None)

    def start(self):
        """Starts live sniffing thread."""
        self.running = True
        self.start_wall_time = time.time()
        self.sniffer_thread = threading.Thread(target=self._sniffer_worker, daemon=True)
        self.sniffer_thread.start()

    def stop(self):
        """Stops live sniffing."""
        self.running = False
        if self.sniffer_thread and self.sniffer_thread.is_alive():
            self.sniffer_thread.join(timeout=1.0)

    def stream(self) -> Generator[Packet, None, None]:
        """
        Yields packets continuously from the live interface queue.
        Matches the generator contract of PcapStreamingReader.
        """
        if not self.running:
            self.start()

        while self.running or not self.packet_queue.empty():
            try:
                pkt = self.packet_queue.get(timeout=0.5)
                if pkt is None:
                    break
                yield pkt
            except queue.Empty:
                continue

    def get_stats(self) -> Dict[str, Any]:
        """Returns live capture statistics."""
        elapsed = (self.last_wall_time - self.start_wall_time) if (self.last_wall_time and self.start_wall_time) else 0.0
        pps = (self.packets_captured / elapsed) if elapsed > 0 else 0.0
        mbps = (self.bytes_captured * 8 / (elapsed * 1_000_000)) if elapsed > 0 else 0.0

        return {
            "interface": self.interface or "default",
            "packets_captured": self.packets_captured,
            "packets_dropped": self.packets_dropped,
            "bytes_captured": self.bytes_captured,
            "queue_depth": self.packet_queue.qsize(),
            "elapsed_wall_sec": round(elapsed, 4),
            "packets_per_sec": round(pps, 2),
            "mbps_sustained": round(mbps, 4)
        }
