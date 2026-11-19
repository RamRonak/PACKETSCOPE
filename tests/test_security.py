"""Security Testing for Input Validation, Uploads, and Payload Sanitization."""
import unittest
from backend.security.validators import (
    allowed_file, validate_and_sanitize_filename, sanitize_payload,
    validate_filter_input, format_hex_dump
)

class TestSecurity(unittest.TestCase):

    def test_allowed_extensions(self):
        """Verify strict extension whitelisting (.pcap, .pcapng, .cap)."""
        self.assertTrue(allowed_file("traffic.pcap"))
        self.assertTrue(allowed_file("capture.pcapng"))
        self.assertTrue(allowed_file("dump.cap"))
        
        # Block dangerous or unsupported extensions
        self.assertFalse(allowed_file("malicious.exe"))
        self.assertFalse(allowed_file("exploit.py"))
        self.assertFalse(allowed_file("payload.sh"))
        self.assertFalse(allowed_file("script.php"))
        self.assertFalse(allowed_file("config.ini"))
        self.assertFalse(allowed_file("no_extension"))

    def test_path_traversal_prevention(self):
        """Verify secure filename sanitization against path traversal attacks."""
        dangerous_names = [
            "../../etc/passwd.pcap",
            "..\\..\\windows\\system32\\cmd.pcap",
            "/root/secret.pcap",
            "../../../evil.pcapng"
        ]
        for name in dangerous_names:
            safe = validate_and_sanitize_filename(name)
            self.assertNotIn("..", safe)
            self.assertNotIn("/", safe)
            self.assertNotIn("\\", safe)

    def test_filter_input_validation(self):
        """Verify protection against injection attacks in filter parameters."""
        valid, _ = validate_filter_input(protocol="TCP", ip="192.168.1.1", port="80")
        self.assertTrue(valid)

        # Invalid protocol
        valid_bad_proto, _ = validate_filter_input(protocol="INVALID_PROTO")
        self.assertFalse(valid_bad_proto)

        # SQL / Script injection in IP field
        valid_bad_ip, _ = validate_filter_input(ip="127.0.0.1; DROP TABLE users;--")
        self.assertFalse(valid_bad_ip)

        # Out-of-range port
        valid_bad_port, _ = validate_filter_input(port="999999")
        self.assertFalse(valid_bad_port)

        # Non-numeric port
        valid_nan_port, _ = validate_filter_input(port="eighty")
        self.assertFalse(valid_nan_port)

    def test_payload_credential_masking(self):
        """Verify that password strings, bearer tokens, and cookies are masked."""
        raw = b"Authorization: Basic dXNlcjpwYXNz\r\nBearer 123456abcdef\r\npassword=SuperSecret!"
        sanitized = sanitize_payload(raw)
        self.assertNotIn("SuperSecret!", sanitized)
        self.assertNotIn("123456abcdef", sanitized)
        self.assertIn("[REDACTED_FOR_SECURITY]", sanitized)

if __name__ == '__main__':
    unittest.main()
