from collections import Counter, defaultdict
from typing import List, Dict, Any

class StatisticsAnalyzer:
    """Calculates comprehensive network traffic metrics and chart data."""

    @staticmethod
    def calculate_traffic_stats(packets: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Compute all dashboard stats and Chart.js datasets from a list of packet dicts."""
        total_packets = len(packets)
        if total_packets == 0:
            return {
                "total_packets": 0,
                "total_bytes": 0,
                "duration_seconds": 0.0,
                "avg_packet_size": 0,
                "packet_rate": 0.0,
                "protocol_counts": {},
                "protocol_chart": {"labels": [], "data": []},
                "timeline_chart": {"labels": [], "data": []},
                "top_sources": [],
                "top_destinations": [],
                "size_distribution": {"labels": ["<64B", "64-128B", "129-512B", "513-1024B", "1025-1518B", ">1518B"], "data": [0, 0, 0, 0, 0, 0]}
            }

        total_bytes = 0
        protocol_counts = Counter()
        src_ip_counts = Counter()
        dst_ip_counts = Counter()
        
        # Packet size buckets
        size_buckets = {
            "<64B": 0,
            "64-128B": 0,
            "129-512B": 0,
            "513-1024B": 0,
            "1025-1518B": 0,
            ">1518B": 0
        }

        timestamps = []

        for p in packets:
            p_len = p.get("packet_len", 0)
            total_bytes += p_len

            # Categorize protocol
            proto = p.get("protocol", "OTHER").upper()
            if "TCP" in proto:
                if "HTTP" in proto:
                    protocol_counts["HTTP"] += 1
                elif "TLS" in proto or "HTTPS" in proto:
                    protocol_counts["HTTPS"] += 1
                else:
                    protocol_counts["TCP"] += 1
            elif "UDP" in proto:
                if "DNS" in proto:
                    protocol_counts["DNS"] += 1
                else:
                    protocol_counts["UDP"] += 1
            elif "ICMP" in proto:
                protocol_counts["ICMP"] += 1
            elif "DNS" in proto:
                protocol_counts["DNS"] += 1
            elif "ARP" in proto:
                protocol_counts["ARP"] += 1
            else:
                protocol_counts[proto] += 1

            # Top IPs
            src_ip = p.get("ip_src")
            if src_ip and src_ip != "N/A":
                src_ip_counts[src_ip] += 1

            dst_ip = p.get("ip_dst")
            if dst_ip and dst_ip != "N/A":
                dst_ip_counts[dst_ip] += 1

            # Size histogram
            if p_len < 64:
                size_buckets["<64B"] += 1
            elif p_len <= 128:
                size_buckets["64-128B"] += 1
            elif p_len <= 512:
                size_buckets["129-512B"] += 1
            elif p_len <= 1024:
                size_buckets["513-1024B"] += 1
            elif p_len <= 1518:
                size_buckets["1025-1518B"] += 1
            else:
                size_buckets[">1518B"] += 1

            t = p.get("timestamp")
            if t:
                timestamps.append(float(t))

        # Time range & Rate
        if timestamps:
            timestamps.sort()
            duration = max(0.1, timestamps[-1] - timestamps[0])
            packet_rate = round(total_packets / duration, 2)
        else:
            duration = 1.0
            packet_rate = 0.0

        avg_packet_size = int(total_bytes / total_packets) if total_packets > 0 else 0

        # Timeline generation (up to 15-20 time slices)
        timeline_bins = defaultdict(int)
        if timestamps:
            t0 = timestamps[0]
            bin_size = max(1.0, duration / 15.0)
            for t in timestamps:
                bin_idx = int((t - t0) / bin_size)
                sec_offset = int(bin_idx * bin_size)
                timeline_bins[f"+{sec_offset}s"] += 1

        timeline_labels = list(timeline_bins.keys())
        timeline_data = list(timeline_bins.values())

        # Protocol Chart format
        sorted_protos = protocol_counts.most_common(7)
        proto_labels = [p[0] for p in sorted_protos]
        proto_data = [p[1] for p in sorted_protos]

        # Top 5 Sources and Destinations
        top_src = [{"ip": ip, "count": cnt} for ip, cnt in src_ip_counts.most_common(5)]
        top_dst = [{"ip": ip, "count": cnt} for ip, cnt in dst_ip_counts.most_common(5)]

        return {
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "duration_seconds": round(duration, 2),
            "avg_packet_size": avg_packet_size,
            "packet_rate": packet_rate,
            "protocol_counts": dict(protocol_counts),
            "protocol_chart": {
                "labels": proto_labels,
                "data": proto_data
            },
            "timeline_chart": {
                "labels": timeline_labels if timeline_labels else ["0s"],
                "data": timeline_data if timeline_data else [total_packets]
            },
            "top_sources": top_src,
            "top_destinations": top_dst,
            "size_distribution": {
                "labels": list(size_buckets.keys()),
                "data": list(size_buckets.values())
            }
        }
