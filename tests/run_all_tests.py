"""Comprehensive Test Runner & Performance Benchmark for PacketScope."""
import sys
import os
import time
import unittest

# Ensure root in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from scapy.all import Ether, IP, TCP, UDP, ICMP
from backend.analysis.packet_parser import PacketParser
from app import create_app

def run_performance_benchmarks():
    print("\n" + "=" * 65)
    print(" [BENCHMARK] PACKETSCOPE PERFORMANCE BENCHMARKS")
    print("=" * 65)

    # 1. Packet Parsing Throughput Benchmark
    print("[*] Generating 1,000 synthetic multi-layer packets for throughput benchmark...")
    test_packets = []
    for i in range(1000):
        if i % 3 == 0:
            pkt = Ether() / IP(src=f"192.168.1.{i%254 + 1}", dst="10.0.0.1") / TCP(sport=50000 + (i%10000), dport=80, flags="PA")
        elif i % 3 == 1:
            pkt = Ether() / IP(src="10.0.0.15", dst="8.8.8.8") / UDP(sport=40000 + (i%10000), dport=53)
        else:
            pkt = Ether() / IP(src="192.168.1.1", dst="192.168.1.2") / ICMP(type=8, code=0, seq=i)
        test_packets.append(pkt)

    start_t = time.perf_counter()
    parsed_count = 0
    for idx, p in enumerate(test_packets):
        _ = PacketParser.parse_packet(p, packet_number=idx + 1)
        parsed_count += 1
    duration = time.perf_counter() - start_t

    throughput = round(parsed_count / duration, 2)
    print(f" [+] Processed {parsed_count} packets in {duration:.4f} seconds.")
    print(f" [+] Parsing Throughput: {throughput:,.2f} packets/second")

    # 2. Flask API Response Time Benchmark
    print("\n[*] Benchmarking Flask API endpoint latency...")
    app = create_app()
    client = app.test_client()

    endpoints = [
        ('/', 'Home Page'),
        ('/dashboard', 'Main Dashboard'),
        ('/inspector', 'Packet Inspector'),
        ('/protocols', 'Protocol Analysis'),
        ('/education', 'Networking Education'),
        ('/api/interfaces', 'Interfaces API'),
        ('/api/sessions', 'Sessions History API')
    ]

    for ep, label in endpoints:
        t0 = time.perf_counter()
        resp = client.get(ep)
        lat_ms = round((time.perf_counter() - t0) * 1000, 2)
        print(f" [+] {label:<22} ({ep:<18}) Status: {resp.status_code} | Latency: {lat_ms:6.2f} ms")

def main():
    print("=" * 65)
    print(" [TEST SUITE] RUNNING PACKETSCOPE COMPREHENSIVE TEST SUITE")
    print("=" * 65)

    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Discover and add tests
    tests_dir = os.path.dirname(os.path.abspath(__file__))
    discovered = loader.discover(start_dir=tests_dir, pattern='test_*.py')
    suite.addTests(discovered)

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    # Run performance benchmarks
    run_performance_benchmarks()

    print("\n" + "=" * 65)
    if result.wasSuccessful():
        print(f" [RESULT] ALL {result.testsRun} TESTS PASSED SUCCESSFULLY.")
    else:
        print(f" [RESULT] TESTS FAILED. Failures: {len(result.failures)}, Errors: {len(result.errors)}")
    print("=" * 65 + "\n")

    return 0 if result.wasSuccessful() else 1

if __name__ == '__main__':
    sys.exit(main())
