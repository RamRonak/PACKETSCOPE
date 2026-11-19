"""Functional and Accuracy Testing for PacketParser and ProtocolDetector."""
import unittest
import time
from scapy.all import Ether, IP, TCP, UDP, ICMP, DNS, DNSQR, DNSRR, ARP, Raw

from backend.analysis.packet_parser import PacketParser
from backend.analysis.protocol_detector import ProtocolDetector

class TestPacketParser(unittest.TestCase):

    def test_ethernet_ip_tcp_parsing(self):
        """Verify accurate dissection of Ethernet, IPv4, and TCP headers."""
        pkt = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / \
              IP(src="192.168.1.50", dst="10.0.0.1", ttl=64, id=12345) / \
              TCP(sport=54321, dport=80, seq=1000, ack=5000, flags="SA", window=65535)

        parsed = PacketParser.parse_packet(pkt, packet_number=1)

        self.assertEqual(parsed['packet_number'], 1)
        self.assertEqual(parsed['eth_src'], "00:11:22:33:44:55")
        self.assertEqual(parsed['eth_dst'], "66:77:88:99:aa:bb")
        self.assertEqual(parsed['ip_src'], "192.168.1.50")
        self.assertEqual(parsed['ip_dst'], "10.0.0.1")
        self.assertEqual(parsed['ip_ttl'], 64)
        self.assertEqual(parsed['protocol'], "HTTP")  # Port 80 identified as HTTP
        self.assertEqual(parsed['src_port'], 54321)
        self.assertEqual(parsed['dst_port'], 80)
        self.assertIn("SYN", parsed['tcp_flags'])
        self.assertIn("ACK", parsed['tcp_flags'])
        self.assertIn("Ethernet", parsed['layers'])
        self.assertIn("IPv4", parsed['layers'])
        self.assertIn("TCP", parsed['layers'])

    def test_udp_dns_parsing(self):
        """Verify accurate dissection of UDP and DNS query/answer layers."""
        pkt = Ether() / \
              IP(src="192.168.1.100", dst="8.8.8.8", ttl=128) / \
              UDP(sport=49152, dport=53) / \
              DNS(id=0xbeef, qr=1, qd=DNSQR(qname="packetscope.org", qtype="A"),
                  an=DNSRR(rrname="packetscope.org.", type="A", rdata="93.184.216.34", ttl=3600))

        parsed = PacketParser.parse_packet(pkt, packet_number=2)

        self.assertEqual(parsed['protocol'], "DNS")
        self.assertEqual(parsed['src_port'], 49152)
        self.assertEqual(parsed['dst_port'], 53)
        self.assertEqual(parsed['ip_src'], "192.168.1.100")
        self.assertEqual(parsed['ip_dst'], "8.8.8.8")
        self.assertIn("DNS", parsed['layers'])
        self.assertIn("UDP", parsed['layers'])
        self.assertIn("packetscope.org", parsed['info'])

    def test_icmp_ping_parsing(self):
        """Verify accurate dissection of ICMP Echo Request and Reply."""
        pkt = Ether() / \
              IP(src="192.168.1.10", dst="8.8.4.4", ttl=55) / \
              ICMP(type=8, code=0, id=0x1234, seq=42)

        parsed = PacketParser.parse_packet(pkt, packet_number=3)

        self.assertEqual(parsed['protocol'], "ICMP")
        self.assertEqual(parsed['ip_src'], "192.168.1.10")
        self.assertEqual(parsed['ip_dst'], "8.8.4.4")
        self.assertIn("Echo Request", parsed['info'])
        self.assertEqual(parsed['layer_details']['ICMP']['Code'], 0)

    def test_arp_parsing(self):
        """Verify accurate dissection of ARP Who-Has request."""
        pkt = Ether(src="aa:bb:cc:dd:ee:ff", dst="ff:ff:ff:ff:ff:ff") / \
              ARP(op=1, hwsrc="aa:bb:cc:dd:ee:ff", psrc="192.168.1.100",
                  hwdst="00:00:00:00:00:00", pdst="192.168.1.1")

        parsed = PacketParser.parse_packet(pkt, packet_number=4)

        self.assertEqual(parsed['protocol'], "ARP")
        self.assertEqual(parsed['ip_src'], "192.168.1.100")
        self.assertEqual(parsed['ip_dst'], "192.168.1.1")
        self.assertIn("who-has", parsed['info'])
        self.assertIn("ARP", parsed['layers'])

    def test_sensitive_payload_sanitization(self):
        """Verify that authentication tokens and passwords are redacted from payload."""
        sensitive_payload = b"POST /login HTTP/1.1\r\nHost: test.com\r\nCookie: session_id=SECRET_COOKIE_XYZ\r\npassword=SuperSecretPassword123\r\n\r\n"
        pkt = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=50000, dport=80) / Raw(load=sensitive_payload)

        parsed = PacketParser.parse_packet(pkt, packet_number=5)

        self.assertNotIn("SuperSecretPassword123", parsed['payload_preview'])
        self.assertNotIn("SECRET_COOKIE_XYZ", parsed['payload_preview'])
        self.assertIn("[REDACTED_FOR_SECURITY]", parsed['payload_preview'])

if __name__ == '__main__':
    unittest.main()
