"""Functional Testing for SnifferEngine and Interface Detection."""
import unittest
import time
from backend.capture.interfaces import get_network_interfaces, get_system_capture_capabilities
from backend.capture.sniffer import SnifferEngine

class TestSniffer(unittest.TestCase):

    def test_network_interface_detection(self):
        """Verify that host interfaces are properly detected and categorized."""
        interfaces = get_network_interfaces()
        self.assertIsInstance(interfaces, list)
        self.assertGreater(len(interfaces), 0)

        first = interfaces[0]
        self.assertIn('name', first)
        self.assertIn('ip_address', first)
        self.assertIn('is_up', first)
        self.assertIn('is_loopback', first)

    def test_system_capabilities(self):
        """Verify system capabilities inspection."""
        caps = get_system_capture_capabilities()
        self.assertIn('os', caps)
        self.assertIn('pcap_driver_installed', caps)
        self.assertIn('offline_pcap_supported', caps)
        self.assertTrue(caps['offline_pcap_supported'])

    def test_sniffer_start_and_stop_lifecycle(self):
        """Verify thread-safe start, capture, packet collection, and stop sequence."""
        sniffer = SnifferEngine()
        status_initial = sniffer.get_status()
        self.assertFalse(status_initial['is_running'])

        # Start Capture
        start_res = sniffer.start_capture(interface="all", filter_type="ALL", session_name="Test Lifecycle Session")
        self.assertTrue(start_res['success'])
        self.assertIsNotNone(start_res['session_id'])

        # Allow worker thread to process at least a couple of educational packets
        time.sleep(1.2)

        status_running = sniffer.get_status()
        self.assertTrue(status_running['is_running'])
        self.assertGreater(status_running['packet_count'], 0)

        # Stop Capture
        stop_res = sniffer.stop_capture()
        self.assertTrue(stop_res['success'])
        self.assertGreaterEqual(stop_res['packet_count'], 1)

        status_stopped = sniffer.get_status()
        self.assertFalse(status_stopped['is_running'])

if __name__ == '__main__':
    unittest.main()
