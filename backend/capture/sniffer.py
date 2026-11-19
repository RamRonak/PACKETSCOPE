import threading
import time
import queue
from typing import Optional, Dict, Any, List
from config import Config
from backend.analysis.packet_parser import PacketParser
from database.models import DatabaseManager

class SnifferEngine:
    """
    Thread-safe packet sniffer engine for live network capture.
    Handles Scapy live sniffing, filter application, buffer management,
    and fallback for environments without raw capture drivers (e.g. Windows without Npcap).
    """

    def __init__(self):
        self.is_running = False
        self.is_paused = False
        self.current_session_id: Optional[int] = None
        self.interface: str = "all"
        self.filter_str: str = ""
        self.captured_packets: List[Dict[str, Any]] = []
        self.scapy_packets: list = []  # For pcap export
        self.packet_queue = queue.Queue(maxsize=Config.MAX_CAPTURE_PACKETS)
        self.lock = threading.Lock()
        self.thread: Optional[threading.Thread] = None
        self.start_time: float = 0.0
        self.stop_event = threading.Event()
        self.mode: str = "idle"  # 'idle', 'live', 'simulation'
        self.status_message: str = "Ready"

    def get_status(self) -> Dict[str, Any]:
        """Return current sniffer state and packet counts."""
        with self.lock:
            elapsed = time.time() - self.start_time if self.is_running else 0.0
            return {
                "is_running": self.is_running,
                "is_paused": self.is_paused,
                "session_id": self.current_session_id,
                "interface": self.interface,
                "filter": self.filter_str,
                "packet_count": len(self.captured_packets),
                "elapsed_seconds": round(elapsed, 1),
                "mode": self.mode,
                "status_message": self.status_message
            }

    def start_capture(self, interface: str = "all", filter_type: str = "ALL", session_name: str = None) -> Dict[str, Any]:
        """Start a new packet capture session in a background worker thread."""
        with self.lock:
            if self.is_running:
                return {"success": False, "message": "Capture is already active"}

            self.interface = interface
            self.filter_str = filter_type.upper() if filter_type else "ALL"
            self.captured_packets.clear()
            self.scapy_packets.clear()
            while not self.packet_queue.empty():
                try:
                    self.packet_queue.get_nowait()
                except queue.Empty:
                    break

            name = session_name or f"Live Capture {time.strftime('%Y-%m-%d %H:%M:%S')}"
            self.current_session_id = DatabaseManager.create_session(
                name=name,
                interface=self.interface,
                filter_applied=self.filter_str,
                notes="Authorized network monitoring session"
            )

            self.is_running = True
            self.is_paused = False
            self.stop_event.clear()
            self.start_time = time.time()

            # Check if Scapy native pcap is supported
            from scapy.all import conf
            pcap_available = getattr(conf, 'use_pcap', False) and (
                hasattr(conf, 'L2listen') and 'NotAvailableSocket' not in str(conf.L2listen)
            )

            if pcap_available:
                self.mode = "live"
                self.status_message = "Capturing live packets via Npcap/Scapy"
                self.thread = threading.Thread(target=self._scapy_capture_loop, daemon=True)
            else:
                # Driver missing on Windows or elevated socket required
                self.mode = "simulated_live"
                self.status_message = "Live generator mode active (Npcap driver missing on Windows host)"
                self.thread = threading.Thread(target=self._educational_traffic_loop, daemon=True)

            self.thread.start()
            return {
                "success": True,
                "session_id": self.current_session_id,
                "mode": self.mode,
                "message": self.status_message
            }

    def stop_capture(self) -> Dict[str, Any]:
        """Stop the ongoing capture session and persist to database."""
        with self.lock:
            if not self.is_running:
                return {"success": False, "message": "No capture session is running"}

            self.is_running = False
            self.is_paused = False
            self.stop_event.set()

        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=2.0)

        with self.lock:
            session_id = self.current_session_id
            total_count = len(self.captured_packets)
            self.mode = "idle"
            self.status_message = f"Capture stopped. Total packets: {total_count}"

            # Save batch to SQLite
            if session_id and self.captured_packets:
                DatabaseManager.save_packets_batch(session_id, self.captured_packets)
                DatabaseManager.finish_session(session_id, total_packets=total_count, status="completed")

        return {
            "success": True,
            "session_id": session_id,
            "packet_count": total_count,
            "message": "Capture stopped successfully"
        }

    def _process_scapy_packet(self, scapy_pkt):
        """Process an individual Scapy packet and append to buffer."""
        if not self.is_running or self.is_paused:
            return

        with self.lock:
            if len(self.captured_packets) >= Config.MAX_CAPTURE_PACKETS:
                self.is_running = False
                self.stop_event.set()
                return

            pkt_num = len(self.captured_packets) + 1
            parsed = PacketParser.parse_packet(scapy_pkt, packet_number=pkt_num)

            # Apply protocol filter
            if self.filter_str and self.filter_str != "ALL":
                proto = parsed["protocol"].upper()
                if self.filter_str not in proto:
                    return

            self.captured_packets.append(parsed)
            self.scapy_packets.append(scapy_pkt)

    def _scapy_capture_loop(self):
        """Standard live Scapy capture loop."""
        from scapy.all import sniff
        
        bpf = ""
        if self.filter_str == "TCP": bpf = "tcp"
        elif self.filter_str == "UDP": bpf = "udp"
        elif self.filter_str == "ICMP": bpf = "icmp"
        elif self.filter_str == "DNS": bpf = "port 53"

        iface = None if self.interface in ["all", "default", ""] else self.interface

        try:
            sniff(
                iface=iface,
                filter=bpf if bpf else None,
                prn=self._process_scapy_packet,
                stop_filter=lambda x: self.stop_event.is_set(),
                store=False
            )
        except Exception as e:
            with self.lock:
                self.status_message = f"Capture error: {str(e)}"
                self.is_running = False

    def _educational_traffic_loop(self):
        """
        Generates realistic, educational live network traffic in real-time when
        Windows host lacks Npcap driver or elevated raw sockets.
        Ensures students and evaluators can experience live packet sniffing,
        filters, Chart.js updates, and packet inspection!
        """
        import os
        from scapy.all import rdpcap
        
        # Load sample packets to stream in real-time
        sample_path = os.path.join(Config.SAMPLE_PCAPS_FOLDER, "sample_mixed_network.pcap")
        if not os.path.exists(sample_path):
            from sample_pcaps.generate_samples import generate_sample_pcaps
            generate_sample_pcaps()

        sample_pkts = rdpcap(sample_path)
        idx = 0
        num_pkts = len(sample_pkts)

        while not self.stop_event.is_set() and self.is_running:
            if not self.is_paused:
                pkt = sample_pkts[idx % num_pkts].copy()
                pkt.time = time.time()
                self._process_scapy_packet(pkt)
                idx += 1

            # Sleep between packets to simulate realistic arrival intervals (300ms - 800ms)
            time.sleep(0.5)

            if len(self.captured_packets) >= Config.MAX_CAPTURE_PACKETS:
                break

        with self.lock:
            self.is_running = False

    def get_latest_packets(self, since_index: int = 0) -> List[Dict[str, Any]]:
        """Retrieve newly captured packets since given index for live polling."""
        with self.lock:
            return self.captured_packets[since_index:]

# Global Singleton Sniffer Instance
global_sniffer = SnifferEngine()
