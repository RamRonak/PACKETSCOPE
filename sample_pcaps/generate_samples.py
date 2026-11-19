"""Generate realistic, educational sample PCAP files for PacketScope."""
import os
import time
from scapy.all import (
    Ether, IP, TCP, UDP, ICMP, DNS, DNSQR, DNSRR, ARP, Raw, wrpcap
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def generate_sample_pcaps():
    print("[*] Generating sample PCAP files for PacketScope...")
    now = time.time()

    # 1. TCP 3-Way Handshake & Data PCAP
    # Client: 192.168.1.100:54321 -> Server: 192.168.1.1:80
    handshake_pkts = []
    # SYN
    p1 = Ether(src="00:11:22:33:44:55", dst="aa:bb:cc:dd:ee:ff") / \
         IP(src="192.168.1.100", dst="192.168.1.1", ttl=64) / \
         TCP(sport=54321, dport=80, flags="S", seq=1000, window=65535)
    p1.time = now
    handshake_pkts.append(p1)

    # SYN-ACK
    p2 = Ether(src="aa:bb:cc:dd:ee:ff", dst="00:11:22:33:44:55") / \
         IP(src="192.168.1.1", dst="192.168.1.100", ttl=64) / \
         TCP(sport=80, dport=54321, flags="SA", seq=5000, ack=1001, window=65535)
    p2.time = now + 0.015
    handshake_pkts.append(p2)

    # ACK
    p3 = Ether(src="00:11:22:33:44:55", dst="aa:bb:cc:dd:ee:ff") / \
         IP(src="192.168.1.100", dst="192.168.1.1", ttl=64) / \
         TCP(sport=54321, dport=80, flags="A", seq=1001, ack=5001, window=65535)
    p3.time = now + 0.020
    handshake_pkts.append(p3)

    # PSH-ACK Data
    p4 = Ether(src="00:11:22:33:44:55", dst="aa:bb:cc:dd:ee:ff") / \
         IP(src="192.168.1.100", dst="192.168.1.1", ttl=64) / \
         TCP(sport=54321, dport=80, flags="PA", seq=1001, ack=5001, window=65535) / \
         Raw(load=b"GET /api/status HTTP/1.1\r\nHost: packetscope.local\r\nUser-Agent: PacketScope-Client/1.0\r\n\r\n")
    p4.time = now + 0.035
    handshake_pkts.append(p4)

    # FIN-ACK
    p5 = Ether(src="00:11:22:33:44:55", dst="aa:bb:cc:dd:ee:ff") / \
         IP(src="192.168.1.100", dst="192.168.1.1", ttl=64) / \
         TCP(sport=54321, dport=80, flags="FA", seq=1075, ack=5001, window=65535)
    p5.time = now + 0.080
    handshake_pkts.append(p5)

    wrpcap(os.path.join(BASE_DIR, "sample_tcp_handshake.pcap"), handshake_pkts)
    print("  [+] sample_tcp_handshake.pcap created.")

    # 2. HTTP Web Traffic PCAP
    http_pkts = []
    # Request
    http_req = Ether(src="00:50:56:c0:00:08", dst="00:0c:29:1b:2c:3d") / \
               IP(src="10.0.0.15", dst="172.217.16.206", ttl=128) / \
               TCP(sport=49152, dport=80, flags="PA", seq=2000, ack=7000) / \
               Raw(load=b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\nAccept: text/html\r\n\r\n")
    http_req.time = now + 1.0
    http_pkts.append(http_req)

    # Response
    http_res = Ether(src="00:0c:29:1b:2c:3d", dst="00:50:56:c0:00:08") / \
               IP(src="172.217.16.206", dst="10.0.0.15", ttl=56) / \
               TCP(sport=80, dport=49152, flags="PA", seq=7000, ack=2145) / \
               Raw(load=b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Length: 48\r\n\r\n<html><body><h1>PacketScope Analyzer</h1></body></html>")
    http_res.time = now + 1.045
    http_pkts.append(http_res)

    wrpcap(os.path.join(BASE_DIR, "sample_http_web.pcap"), http_pkts)
    print("  [+] sample_http_web.pcap created.")

    # 3. DNS Queries & Answers PCAP
    dns_pkts = []
    # Query 1: A record for google.com
    q1 = Ether(src="00:11:22:33:44:55", dst="00:22:33:44:55:66") / \
         IP(src="192.168.1.50", dst="8.8.8.8", ttl=64) / \
         UDP(sport=51234, dport=53) / \
         DNS(id=0x1a2b, qr=0, qd=DNSQR(qname="google.com", qtype="A"))
    q1.time = now + 2.0
    dns_pkts.append(q1)

    # Response 1
    r1 = Ether(src="00:22:33:44:55:66", dst="00:11:22:33:44:55") / \
         IP(src="8.8.8.8", dst="192.168.1.50", ttl=58) / \
         UDP(sport=53, dport=51234) / \
         DNS(id=0x1a2b, qr=1, aa=0, qd=DNSQR(qname="google.com", qtype="A"),
             an=DNSRR(rrname="google.com.", type="A", rdata="142.250.190.46", ttl=300))
    r1.time = now + 2.025
    dns_pkts.append(r1)

    # Query 2: AAAA record for packetscope.net
    q2 = Ether(src="00:11:22:33:44:55", dst="1.1.1.1") / \
         IP(src="192.168.1.50", dst="1.1.1.1", ttl=64) / \
         UDP(sport=51235, dport=53) / \
         DNS(id=0x3c4d, qr=0, qd=DNSQR(qname="packetscope.net", qtype="AAAA"))
    q2.time = now + 2.1
    dns_pkts.append(q2)

    # Response 2
    r2 = Ether(src="1.1.1.1", dst="00:11:22:33:44:55") / \
         IP(src="1.1.1.1", dst="192.168.1.50", ttl=56) / \
         UDP(sport=53, dport=51235) / \
         DNS(id=0x3c4d, qr=1, aa=1, qd=DNSQR(qname="packetscope.net", qtype="AAAA"),
             an=DNSRR(rrname="packetscope.net.", type="AAAA", rdata="2606:4700:4700::1111", ttl=120))
    r2.time = now + 2.118
    dns_pkts.append(r2)

    wrpcap(os.path.join(BASE_DIR, "sample_dns_queries.pcap"), dns_pkts)
    print("  [+] sample_dns_queries.pcap created.")

    # 4. ICMP Ping PCAP
    icmp_pkts = []
    for seq in range(1, 5):
        # Echo Request
        req = Ether(src="00:11:22:33:44:55", dst="00:aa:bb:cc:dd:ee") / \
              IP(src="192.168.1.100", dst="8.8.4.4", ttl=64) / \
              ICMP(type=8, code=0, id=0x1234, seq=seq) / \
              Raw(load=b"PacketScope Ping Diagnostic Payload 12345678")
        req.time = now + 3.0 + (seq * 0.2)
        icmp_pkts.append(req)

        # Echo Reply
        rep = Ether(src="00:aa:bb:cc:dd:ee", dst="00:11:22:33:44:55") / \
              IP(src="8.8.4.4", dst="192.168.1.100", ttl=57) / \
              ICMP(type=0, code=0, id=0x1234, seq=seq) / \
              Raw(load=b"PacketScope Ping Diagnostic Payload 12345678")
        rep.time = now + 3.0 + (seq * 0.2) + 0.022
        icmp_pkts.append(rep)

    wrpcap(os.path.join(BASE_DIR, "sample_icmp_ping.pcap"), icmp_pkts)
    print("  [+] sample_icmp_ping.pcap created.")

    # 5. Rich Mixed Network Capture (ARP + DNS + TCP + HTTP + UDP + ICMP)
    mixed_pkts = []
    # Add ARP Request & Reply
    arp_req = Ether(src="00:11:22:33:44:55", dst="ff:ff:ff:ff:ff:ff") / \
              ARP(op=1, hwsrc="00:11:22:33:44:55", psrc="192.168.1.100",
                  hwdst="00:00:00:00:00:00", pdst="192.168.1.1")
    arp_req.time = now + 0.05
    mixed_pkts.append(arp_req)

    arp_rep = Ether(src="aa:bb:cc:dd:ee:ff", dst="00:11:22:33:44:55") / \
              ARP(op=2, hwsrc="aa:bb:cc:dd:ee:ff", psrc="192.168.1.1",
                  hwdst="00:11:22:33:44:55", pdst="192.168.1.100")
    arp_rep.time = now + 0.06
    mixed_pkts.append(arp_rep)

    # Combine all previous packets into mixed
    mixed_pkts.extend(dns_pkts)
    mixed_pkts.extend(handshake_pkts)
    mixed_pkts.extend(http_pkts)
    mixed_pkts.extend(icmp_pkts)

    # Add a generic UDP datagram (NTP)
    ntp_pkt = Ether(src="00:11:22:33:44:55", dst="aa:bb:cc:dd:ee:ff") / \
              IP(src="192.168.1.100", dst="129.6.15.28", ttl=64) / \
              UDP(sport=48231, dport=123) / \
              Raw(load=b"\x1b" + b"\x00" * 47)
    ntp_pkt.time = now + 4.5
    mixed_pkts.append(ntp_pkt)

    # Sort by time
    mixed_pkts.sort(key=lambda p: float(getattr(p, 'time', 0.0)))
    wrpcap(os.path.join(BASE_DIR, "sample_mixed_network.pcap"), mixed_pkts)
    print(f"  [+] sample_mixed_network.pcap created with {len(mixed_pkts)} packets.")
    print("[+] All sample PCAP files generated successfully.")

if __name__ == "__main__":
    generate_sample_pcaps()
