"""Functional and Export Testing for PCAP Parsing, CSV, and PDF Generation."""
import unittest
import os
from config import Config
from backend.services.pcap_service import PcapService
from backend.services.export_service import ExportService
from database.models import DatabaseManager

class TestPcapAndExport(unittest.TestCase):

    def setUp(self):
        self.sample_pcap = os.path.join(Config.SAMPLE_PCAPS_FOLDER, "sample_mixed_network.pcap")
        self.assertTrue(os.path.exists(self.sample_pcap), "Sample PCAP must exist")

    def test_pcap_parsing_and_database_storage(self):
        """Verify PCAP file parsing, layer extraction, and SQLite storage."""
        result = PcapService.process_pcap_file(self.sample_pcap, original_filename="test_mixed.pcap")
        self.assertTrue(result['success'])
        self.assertGreater(result['total_packets'], 0)

        session_id = result['session_id']
        session = DatabaseManager.get_session(session_id)
        self.assertIsNotNone(session)
        self.assertEqual(session['total_packets'], result['total_packets'])

        packets, total_count = DatabaseManager.get_packets(session_id)
        self.assertEqual(total_count, result['total_packets'])
        self.assertGreater(len(packets), 0)

    def test_csv_export(self):
        """Verify CSV export formatting and header presence."""
        result = PcapService.process_pcap_file(self.sample_pcap, original_filename="csv_test.pcap")
        session_id = result['session_id']

        csv_content, filename = ExportService.export_csv(session_id)
        self.assertIn("No.,Timestamp,Formatted Time", csv_content)
        self.assertIn("Source IP,Destination IP", csv_content)
        self.assertTrue(filename.endswith(".csv"))
        self.assertGreater(len(csv_content), 100)

    def test_pdf_report_generation(self):
        """Verify ReportLab PDF cybersecurity report generation."""
        result = PcapService.process_pcap_file(self.sample_pcap, original_filename="pdf_test.pcap")
        session_id = result['session_id']

        pdf_path = ExportService.generate_pdf_report(session_id)
        self.assertTrue(os.path.exists(pdf_path))
        self.assertTrue(pdf_path.endswith(".pdf"))
        self.assertGreater(os.path.getsize(pdf_path), 1000)  # Valid PDF size

if __name__ == '__main__':
    unittest.main()
