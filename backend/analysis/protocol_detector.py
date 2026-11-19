"""Protocol Detector and Classifier for PacketScope."""

# Common Port to Protocol Mapping
PORT_MAP = {
    20: ("FTP-DATA", "Application", "File Transfer Protocol (Data)"),
    21: ("FTP", "Application", "File Transfer Protocol (Control)"),
    22: ("SSH", "Application", "Secure Shell Remote Login"),
    23: ("TELNET", "Application", "Unencrypted Remote Terminal"),
    25: ("SMTP", "Application", "Simple Mail Transfer Protocol"),
    53: ("DNS", "Application", "Domain Name System"),
    67: ("DHCP", "Application", "DHCP Server"),
    68: ("DHCP", "Application", "DHCP Client"),
    69: ("TFTP", "Application", "Trivial File Transfer Protocol"),
    80: ("HTTP", "Application", "Hypertext Transfer Protocol"),
    110: ("POP3", "Application", "Post Office Protocol v3"),
    123: ("NTP", "Application", "Network Time Protocol"),
    137: ("NETBIOS-NS", "Application", "NetBIOS Name Service"),
    138: ("NETBIOS-DGM", "Application", "NetBIOS Datagram Service"),
    139: ("NETBIOS-SSN", "Application", "NetBIOS Session Service"),
    143: ("IMAP", "Application", "Internet Message Access Protocol"),
    161: ("SNMP", "Application", "Simple Network Management Protocol"),
    162: ("SNMP-TRAP", "Application", "SNMP Trap"),
    443: ("HTTPS", "Application", "HTTP over TLS/SSL"),
    445: ("SMB", "Application", "Server Message Block"),
    465: ("SMTPS", "Application", "Secure SMTP"),
    514: ("SYSLOG", "Application", "System Logging Protocol"),
    587: ("SUBMISSION", "Application", "SMTP Mail Submission"),
    993: ("IMAPS", "Application", "Secure IMAP"),
    995: ("POP3S", "Application", "Secure POP3"),
    1883: ("MQTT", "Application", "Message Queuing Telemetry Transport"),
    1900: ("SSDP", "Application", "Simple Service Discovery Protocol"),
    3000: ("HTTP-DEV", "Application", "Development Web Server"),
    3306: ("MYSQL", "Application", "MySQL Database"),
    3389: ("RDP", "Application", "Remote Desktop Protocol"),
    5000: ("HTTP-FLASK", "Application", "Flask Web Server"),
    5353: ("mDNS", "Application", "Multicast DNS"),
    5432: ("POSTGRES", "Application", "PostgreSQL Database"),
    8000: ("HTTP-ALT", "Application", "Alternative HTTP"),
    8080: ("HTTP-PROXY", "Application", "HTTP Proxy / Web"),
    8443: ("HTTPS-ALT", "Application", "Alternative HTTPS"),
    8883: ("MQTT-TLS", "Application", "Secure MQTT")
}

# EtherType Mapping
ETHERTYPE_MAP = {
    0x0800: "IPv4",
    0x0806: "ARP",
    0x86DD: "IPv6",
    0x8100: "802.1Q (VLAN)",
    0x88CC: "LLDP",
    0x88E5: "MACsec"
}

# IP Protocol Number Mapping
IP_PROTO_MAP = {
    1: "ICMP",
    2: "IGMP",
    6: "TCP",
    17: "UDP",
    41: "IPv6-Route",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
    89: "OSPF"
}

# TCP Flags breakdown
TCP_FLAGS_MAP = {
    0x01: "FIN",
    0x02: "SYN",
    0x04: "RST",
    0x08: "PSH",
    0x10: "ACK",
    0x20: "URG",
    0x40: "ECE",
    0x80: "CWR"
}

class ProtocolDetector:
    """Helper for identifying protocols, layers, and descriptions."""

    @staticmethod
    def identify_application_protocol(src_port: int, dst_port: int, raw_payload: bytes = b"") -> tuple[str, str]:
        """
        Identify application protocol from source/destination ports and signature sniffing.
        Returns (Protocol Name, Description)
        """
        # First check payload signatures for HTTP
        if raw_payload:
            first_line = raw_payload[:20]
            if any(first_line.startswith(verb) for verb in [b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ", b"HTTP/1."]):
                return "HTTP", "Hypertext Transfer Protocol"
            if first_line.startswith(b"\x16\x03"):
                return "TLS/HTTPS", "Transport Layer Security Handshake"

        # Check destination port, then source port
        if dst_port in PORT_MAP:
            name, _, desc = PORT_MAP[dst_port]
            return name, desc
        if src_port in PORT_MAP:
            name, _, desc = PORT_MAP[src_port]
            return name, desc

        return "", ""

    @staticmethod
    def parse_tcp_flags(flags_int: int) -> list[str]:
        """Convert TCP flags integer to human readable list of flag names."""
        flags = []
        for bit, name in TCP_FLAGS_MAP.items():
            if flags_int & bit:
                flags.append(name)
        return flags

    @staticmethod
    def get_ethertype_name(ethertype: int) -> str:
        """Resolve numeric EtherType to friendly name."""
        return ETHERTYPE_MAP.get(ethertype, f"0x{ethertype:04x}")

    @staticmethod
    def get_ip_proto_name(proto_num: int) -> str:
        """Resolve numeric IP protocol to friendly name."""
        return IP_PROTO_MAP.get(proto_num, f"Proto-{proto_num}")

    @staticmethod
    def get_badge_class(protocol: str) -> str:
        """Return CSS badge style class for the given protocol."""
        proto = protocol.upper()
        if "TCP" in proto:
            return "badge-tcp"
        elif "UDP" in proto:
            return "badge-udp"
        elif "ICMP" in proto:
            return "badge-icmp"
        elif "DNS" in proto:
            return "badge-dns"
        elif "HTTP" in proto:
            return "badge-http"
        elif "ARP" in proto:
            return "badge-arp"
        elif "TLS" in proto or "HTTPS" in proto:
            return "badge-https"
        return "badge-other"
