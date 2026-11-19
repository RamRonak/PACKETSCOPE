from typing import Dict, Any, List, Optional
from backend.capture.sniffer import global_sniffer
from backend.analysis.statistics import StatisticsAnalyzer
from database.models import DatabaseManager

class CaptureService:
    """Orchestrates capture sessions, real-time data streaming, and database lookups."""

    @staticmethod
    def start_live_capture(interface: str, filter_type: str, session_name: str = None) -> Dict[str, Any]:
        return global_sniffer.start_capture(interface, filter_type, session_name)

    @staticmethod
    def stop_live_capture() -> Dict[str, Any]:
        return global_sniffer.stop_capture()

    @staticmethod
    def get_live_status() -> Dict[str, Any]:
        return global_sniffer.get_status()

    @staticmethod
    def get_live_data(since_index: int = 0) -> Dict[str, Any]:
        """Fetch newly captured packets and updated statistics for live dashboard polling."""
        status = global_sniffer.get_status()
        new_packets = global_sniffer.get_latest_packets(since_index=since_index)
        all_current_packets = global_sniffer.captured_packets

        # Calculate live stats
        stats = StatisticsAnalyzer.calculate_traffic_stats(all_current_packets)

        return {
            "status": status,
            "packets": new_packets,
            "total_captured": len(all_current_packets),
            "next_index": len(all_current_packets),
            "statistics": stats
        }

    @staticmethod
    def get_session_dashboard_data(session_id: int) -> Optional[Dict[str, Any]]:
        """Retrieve full session metadata, statistics, and packets for visualization."""
        session = DatabaseManager.get_session(session_id)
        if not session:
            return None

        packets, total_count = DatabaseManager.get_packets(session_id, limit=5000)
        stats = StatisticsAnalyzer.calculate_traffic_stats(packets)

        return {
            "session": session,
            "statistics": stats,
            "packets": packets[:250],  # initial slice for table
            "total_packets": total_count
        }
