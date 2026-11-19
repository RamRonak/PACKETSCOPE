import os
import time
from typing import Dict, Any, List
from scapy.all import rdpcap, wrpcap
from config import Config
from backend.security.validators import allowed_file, validate_and_sanitize_filename
from backend.analysis.packet_parser import PacketParser
from backend.analysis.statistics import StatisticsAnalyzer
from database.models import DatabaseManager

class PcapService:
    """Handles offline PCAP parsing, validation, and sample management."""

    @staticmethod
    def list_available_samples() -> List[Dict[str, Any]]:
        """List pre-bundled educational sample PCAP files."""
        samples = []
        sample_dir = Config.SAMPLE_PCAPS_FOLDER
        if not os.path.exists(sample_dir):
            return samples

        sample_descriptions = {
            "sample_mixed_network.pcap": "Comprehensive Network Capture (ARP, DNS, TCP, HTTP, UDP, ICMP)",
            "sample_tcp_handshake.pcap": "TCP 3-Way Handshake & Connection Teardown",
            "sample_http_web.pcap": "Unencrypted HTTP Request and Response Traffic",
            "sample_dns_queries.pcap": "DNS Queries (A, AAAA records) & Resolver Responses",
            "sample_icmp_ping.pcap": "ICMP Echo Requests & Replies (Ping diagnostic flow)"
        }

        for fname in os.listdir(sample_dir):
            if fname.endswith(".pcap"):
                fpath = os.path.join(sample_dir, fname)
                size_kb = round(os.path.getsize(fpath) / 1024, 2)
                samples.append({
                    "filename": fname,
                    "filepath": fpath,
                    "size_kb": size_kb,
                    "description": sample_descriptions.get(fname, "Network packet capture sample")
                })
        return samples

    @staticmethod
    def process_pcap_file(filepath: str, original_filename: str = None) -> Dict[str, Any]:
        """
        Parse PCAP file using Scapy, save session and packets to database,
        and calculate complete traffic metrics.
        """
        if not os.path.exists(filepath):
            return {"success": False, "error": "File does not exist"}

        display_name = original_filename or os.path.basename(filepath)

        try:
            # Read packets securely via Scapy
            packets = rdpcap(filepath)
            total_pkts = len(packets)

            # Create Database Session
            session_id = DatabaseManager.create_session(
                name=f"PCAP: {display_name}",
                interface="PCAP File Import",
                filter_applied="None",
                notes=f"Imported from {display_name} ({total_pkts} packets)",
                pcap_path=filepath
            )

            # Parse packets layer-by-layer
            parsed_packets = []
            for idx, pkt in enumerate(packets):
                parsed = PacketParser.parse_packet(pkt, packet_number=idx + 1)
                parsed_packets.append(parsed)

            # Save batch to Database
            DatabaseManager.save_packets_batch(session_id, parsed_packets)
            DatabaseManager.finish_session(session_id, total_packets=total_pkts, status="imported")

            # Calculate analytics
            stats = StatisticsAnalyzer.calculate_traffic_stats(parsed_packets)

            return {
                "success": True,
                "session_id": session_id,
                "filename": display_name,
                "total_packets": total_pkts,
                "statistics": stats,
                "packets_preview": parsed_packets[:100]
            }

        except Exception as e:
            return {"success": False, "error": f"Failed to parse PCAP file: {str(e)}"}
