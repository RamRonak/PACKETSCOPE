import time
from datetime import datetime
from scapy.all import (
    Ether, IP, IPv6, TCP, UDP, ICMP, DNS, DNSQR, DNSRR, ARP, Raw
)
from backend.analysis.protocol_detector import (
    ProtocolDetector, ETHERTYPE_MAP, IP_PROTO_MAP
)
from backend.security.validators import sanitize_payload, format_hex_dump
from config import Config

ICMP_TYPES = {
    0: "Echo Reply",
    3: "Destination Unreachable",
    4: "Source Quench",
    5: "Redirect",
    8: "Echo Request",
    11: "Time Exceeded",
    12: "Parameter Problem",
    13: "Timestamp Request",
    14: "Timestamp Reply"
}

DNS_QTYPES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    255: "ANY"
}

class PacketParser:
    """Extracts structured layer-by-layer metadata from Scapy packet objects."""

    @staticmethod
    def parse_packet(packet, packet_number: int = 1) -> dict:
        """Parse a Scapy packet into a structured dictionary suitable for UI and DB."""
        # Timestamp
        pkt_time = float(getattr(packet, 'time', time.time()))
        formatted_time = datetime.fromtimestamp(pkt_time).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        packet_len = len(packet)

        # Layers detected
        layers = []
        layer_details = {}

        # 1. Ethernet Layer
        eth_src = "N/A"
        eth_dst = "N/A"
        eth_type = "N/A"
        if packet.haslayer(Ether):
            eth = packet[Ether]
            layers.append("Ethernet")
            eth_src = eth.src
            eth_dst = eth.dst
            type_num = eth.type
            eth_type = ETHERTYPE_MAP.get(type_num, f"0x{type_num:04x}")
            layer_details["Ethernet"] = {
                "Source MAC": eth_src,
                "Destination MAC": eth_dst,
                "EtherType": eth_type,
                "Type Code": f"0x{type_num:04x}"
            }

        # 2. Network Layer (IPv4 / IPv6 / ARP)
        ip_src = "N/A"
        ip_dst = "N/A"
        ip_version = None
        ip_ttl = None
        protocol = "OTHER"
        info = ""

        if packet.haslayer(IP):
            ip = packet[IP]
            layers.append("IPv4")
            ip_src = getattr(ip, 'src', 'N/A')
            ip_dst = getattr(ip, 'dst', 'N/A')
            ip_version = 4
            ip_ttl = getattr(ip, 'ttl', 64)
            proto_num = getattr(ip, 'proto', 6)
            protocol = IP_PROTO_MAP.get(proto_num, f"IP-{proto_num}")
            
            flags_str = []
            if hasattr(ip, 'flags'):
                if getattr(ip.flags, 'DF', False): flags_str.append("Don't Fragment (DF)")
                if getattr(ip.flags, 'MF', False): flags_str.append("More Fragments (MF)")
            
            ihl = getattr(ip, 'ihl', None)
            ihl_str = f"{ihl * 4} bytes" if ihl is not None else "20 bytes"
            pkt_total_len = getattr(ip, 'len', None)
            total_len_str = f"{pkt_total_len} bytes" if pkt_total_len is not None else f"{packet_len} bytes"
            ip_id = getattr(ip, 'id', None)
            id_str = f"0x{ip_id:04x} ({ip_id})" if ip_id is not None else "0x0000"
            chksum = getattr(ip, 'chksum', None)
            chksum_str = f"0x{chksum:04x}" if chksum is not None else "N/A"

            layer_details["IPv4"] = {
                "Source IP": ip_src,
                "Destination IP": ip_dst,
                "Version": 4,
                "Header Length (IHL)": ihl_str,
                "Total Length": total_len_str,
                "Identification": id_str,
                "Flags": ", ".join(flags_str) if flags_str else "None",
                "TTL (Time to Live)": ip_ttl,
                "Protocol": f"{protocol} ({proto_num})",
                "Header Checksum": chksum_str
            }

        elif packet.haslayer(IPv6):
            ip6 = packet[IPv6]
            layers.append("IPv6")
            ip_src = ip6.src
            ip_dst = ip6.dst
            ip_version = 6
            ip_ttl = ip6.hlim
            protocol = f"IPv6-{ip6.nh}"
            layer_details["IPv6"] = {
                "Source IPv6": ip_src,
                "Destination IPv6": ip_dst,
                "Version": 6,
                "Traffic Class": ip6.tc,
                "Flow Label": ip6.fl,
                "Payload Length": f"{ip6.plen} bytes",
                "Next Header": ip6.nh,
                "Hop Limit": ip6.hlim
            }

        elif packet.haslayer(ARP):
            arp = packet[ARP]
            layers.append("ARP")
            protocol = "ARP"
            ip_src = arp.psrc
            ip_dst = arp.pdst
            op_name = "Request (who-has)" if arp.op == 1 else ("Reply (is-at)" if arp.op == 2 else f"Op-{arp.op}")
            info = f"ARP {op_name} {arp.psrc} -> {arp.pdst}"
            layer_details["ARP"] = {
                "Hardware Type": arp.hwtype,
                "Protocol Type": f"0x{arp.ptype:04x}",
                "Hardware Size": arp.hwlen,
                "Protocol Size": arp.plen,
                "Opcode": f"{arp.op} ({op_name})",
                "Sender MAC": arp.hwsrc,
                "Sender IP": arp.psrc,
                "Target MAC": arp.hwdst,
                "Target IP": arp.pdst
            }

        # 3. Transport Layer (TCP / UDP / ICMP)
        src_port = None
        dst_port = None
        tcp_flags = ""

        if packet.haslayer(TCP):
            tcp = packet[TCP]
            layers.append("TCP")
            protocol = "TCP"
            src_port = getattr(tcp, 'sport', None)
            dst_port = getattr(tcp, 'dport', None)
            
            flags_list = []
            if hasattr(tcp, 'flags'):
                if getattr(tcp.flags, 'F', False): flags_list.append("FIN")
                if getattr(tcp.flags, 'S', False): flags_list.append("SYN")
                if getattr(tcp.flags, 'R', False): flags_list.append("RST")
                if getattr(tcp.flags, 'P', False): flags_list.append("PSH")
                if getattr(tcp.flags, 'A', False): flags_list.append("ACK")
                if getattr(tcp.flags, 'U', False): flags_list.append("URG")
                if getattr(tcp.flags, 'E', False): flags_list.append("ECE")
                if getattr(tcp.flags, 'C', False): flags_list.append("CWR")
            tcp_flags = "[" + ", ".join(flags_list) + "]" if flags_list else "[None]"
            
            seq_val = getattr(tcp, 'seq', 0)
            ack_val = getattr(tcp, 'ack', 0)
            win_val = getattr(tcp, 'window', 0)
            dataofs = getattr(tcp, 'dataofs', None)
            dataofs_str = f"{dataofs * 4} bytes" if dataofs is not None else "20 bytes"
            chksum_tcp = getattr(tcp, 'chksum', None)
            chksum_tcp_str = f"0x{chksum_tcp:04x}" if chksum_tcp is not None else "N/A"
            flags_int = int(tcp.flags) if hasattr(tcp, 'flags') and tcp.flags is not None else 0
            
            info = f"{src_port} -> {dst_port} {tcp_flags} Seq={seq_val} Ack={ack_val} Win={win_val}"
            
            layer_details["TCP"] = {
                "Source Port": src_port,
                "Destination Port": dst_port,
                "Sequence Number": seq_val,
                "Acknowledgment Number": ack_val,
                "Data Offset": dataofs_str,
                "Flags": f"{tcp_flags} (0x{flags_int:02x})",
                "Window Size": win_val,
                "Checksum": chksum_tcp_str,
                "Urgent Pointer": getattr(tcp, 'urgptr', 0)
            }

        elif packet.haslayer(UDP):
            udp = packet[UDP]
            layers.append("UDP")
            protocol = "UDP"
            src_port = getattr(udp, 'sport', None)
            dst_port = getattr(udp, 'dport', None)
            udp_len = getattr(udp, 'len', None)
            udp_len_str = f"{udp_len} bytes" if udp_len is not None else f"{packet_len} bytes"
            chksum_udp = getattr(udp, 'chksum', None)
            chksum_udp_str = f"0x{chksum_udp:04x}" if chksum_udp is not None else "N/A"
            info = f"{src_port} -> {dst_port} Len={udp_len_str}"
            layer_details["UDP"] = {
                "Source Port": src_port,
                "Destination Port": dst_port,
                "Length": udp_len_str,
                "Checksum": chksum_udp_str
            }

        elif packet.haslayer(ICMP):
            icmp = packet[ICMP]
            layers.append("ICMP")
            protocol = "ICMP"
            type_num = getattr(icmp, 'type', 0)
            code_num = getattr(icmp, 'code', 0)
            type_desc = ICMP_TYPES.get(type_num, f"Type-{type_num}")
            info = f"ICMP {type_desc} (type={type_num}, code={code_num})"
            chksum_icmp = getattr(icmp, 'chksum', None)
            chksum_icmp_str = f"0x{chksum_icmp:04x}" if chksum_icmp is not None else "N/A"
            layer_details["ICMP"] = {
                "Type": f"{type_num} ({type_desc})",
                "Code": code_num,
                "Checksum": chksum_icmp_str,
                "Identifier": getattr(icmp, 'id', 'N/A'),
                "Sequence Number": getattr(icmp, 'seq', 'N/A')
            }

        # 4. Application Layer (DNS / HTTP / TLS)
        raw_payload = b""
        if packet.haslayer(Raw):
            raw_payload = bytes(packet[Raw].load)

        if packet.haslayer(DNS):
            dns = packet[DNS]
            layers.append("DNS")
            protocol = "DNS"
            qr_val = getattr(dns, 'qr', 0)
            qr_type = "Response" if qr_val == 1 else "Standard Query"
            queries_list = []
            answers_list = []

            qd_count = getattr(dns, 'qdcount', None)
            if qd_count is None:
                qd_count = 1 if hasattr(dns, 'qd') and dns.qd is not None else 0

            an_count = getattr(dns, 'ancount', None)
            if an_count is None:
                an_count = 1 if hasattr(dns, 'an') and dns.an is not None else 0

            if qd_count > 0 and packet.haslayer(DNSQR):
                q = packet[DNSQR]
                qname = q.qname.decode('utf-8', errors='ignore').rstrip('.') if isinstance(q.qname, bytes) else str(q.qname)
                qtype_name = DNS_QTYPES.get(q.qtype, f"Type-{q.qtype}")
                queries_list.append(f"{qtype_name} {qname}")

            if an_count > 0 and packet.haslayer(DNSRR):
                rr = packet[DNSRR]
                rdata = str(getattr(rr, 'rdata', ''))
                answers_list.append(rdata)

            if queries_list and answers_list:
                info = f"DNS {qr_type} {queries_list[0]} -> {answers_list[0]}"
            elif answers_list:
                info = f"DNS {qr_type} answer: {', '.join(answers_list)}"
            elif queries_list:
                info = f"DNS {qr_type} {queries_list[0]}"

            dns_id = getattr(dns, 'id', 0)
            layer_details["DNS"] = {
                "Transaction ID": f"0x{dns_id:04x}",
                "QR Flag": f"{qr_val} ({qr_type})",
                "Opcode": getattr(dns, 'opcode', 0),
                "Questions Count": qd_count,
                "Answer RRs": an_count,
                "Authority RRs": getattr(dns, 'nscount', 0) or 0,
                "Additional RRs": getattr(dns, 'arcount', 0) or 0,
                "Queries": ", ".join(queries_list) if queries_list else "None",
                "Answers": ", ".join(answers_list) if answers_list else "None"
            }

        else:
            # Check for HTTP or HTTPS signatures
            if src_port or dst_port:
                app_name, app_desc = ProtocolDetector.identify_application_protocol(
                    src_port or 0, dst_port or 0, raw_payload
                )
                if app_name:
                    protocol = app_name
                    layers.append(app_name)
                    if app_name == "HTTP" and raw_payload:
                        try:
                            http_lines = raw_payload.decode('utf-8', errors='ignore').split('\r\n')
                            first_line = http_lines[0] if http_lines else ""
                            info = f"HTTP {first_line}"
                            headers = {}
                            for h in http_lines[1:]:
                                if ":" in h:
                                    k, v = h.split(":", 1)
                                    headers[k.strip()] = v.strip()
                            layer_details["HTTP"] = {
                                "First Line": first_line,
                                "Host": headers.get("Host", "N/A"),
                                "User-Agent": headers.get("User-Agent", "N/A"),
                                "Content-Type": headers.get("Content-Type", "N/A"),
                                "Content-Length": headers.get("Content-Length", "N/A")
                            }
                        except Exception:
                            pass

        if not info:
            info = f"{protocol} packet ({packet_len} bytes)"

        # Safe Payload Preview
        safe_preview = sanitize_payload(raw_payload, max_bytes=Config.SAFE_PAYLOAD_PREVIEW_BYTES)
        hex_dump = format_hex_dump(raw_payload, max_bytes=Config.SAFE_PAYLOAD_PREVIEW_BYTES)

        return {
            "packet_number": packet_number,
            "timestamp": pkt_time,
            "formatted_time": formatted_time,
            "eth_src": eth_src,
            "eth_dst": eth_dst,
            "eth_type": eth_type,
            "ip_src": ip_src,
            "ip_dst": ip_dst,
            "ip_version": ip_version,
            "ip_ttl": ip_ttl,
            "protocol": protocol,
            "src_port": src_port,
            "dst_port": dst_port,
            "packet_len": packet_len,
            "tcp_flags": tcp_flags,
            "info": info,
            "payload_preview": safe_preview,
            "hex_dump": hex_dump,
            "layers": layers,
            "layer_details": layer_details
        }
