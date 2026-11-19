import os
import re
from werkzeug.utils import secure_filename
from config import Config

# Sensitive patterns to scrub from educational previews (tokens, passwords, cookies, basic/bearer auth)
SENSITIVE_PATTERNS = [
    re.compile(r'(?i)(password|passwd|pwd|pass)\s*[:=]\s*([^&\s\r\n]+)'),
    re.compile(r'(?i)(bearer\s+|token\s*[:=]\s*|auth_token\s*[:=]\s*|access_token\s*[:=]\s*|secret\s*[:=]\s*)([^&\s\r\n]+)'),
    re.compile(r'(?i)(cookie|set-cookie)\s*:\s*([^;\r\n]+)'),
    re.compile(r'(?i)(authorization\s*:\s*(?:basic|bearer)\s*)([^&\s\r\n]+)'),
    re.compile(r'(?i)(api[_-]?key)\s*[:=]\s*([^&\s\r\n]+)')
]

def allowed_file(filename: str) -> bool:
    """Validate file extension against approved packet capture formats."""
    if not filename or '.' not in filename:
        return False
    ext = filename.rsplit('.', 1)[1].lower()
    return ext in Config.ALLOWED_EXTENSIONS

def validate_and_sanitize_filename(filename: str) -> str:
    """Sanitize and secure upload filenames to avoid directory traversal."""
    safe_name = secure_filename(filename)
    if not safe_name:
        safe_name = "upload.pcap"
    return safe_name

def sanitize_payload(payload_bytes: bytes, max_bytes: int = 128) -> str:
    """
    Safely decode and sanitize application payload.
    Ensures passwords, session cookies, and authentication tokens are masked.
    """
    if not payload_bytes:
        return ""
    
    # Slice to safe length
    preview_bytes = payload_bytes[:max_bytes]
    try:
        text = preview_bytes.decode('utf-8', errors='replace')
    except Exception:
        text = preview_bytes.decode('latin-1', errors='replace')

    # Strip / mask sensitive credential patterns
    if Config.MASK_SENSITIVE_DATA:
        for pattern in SENSITIVE_PATTERNS:
            text = pattern.sub(r'\1: [REDACTED_FOR_SECURITY]', text)

    # Filter non-printable ASCII for clean display
    sanitized = ''.join(c if (32 <= ord(c) < 127 or c in '\r\n\t') else '.' for c in text)
    return sanitized.strip()

def format_hex_dump(raw_bytes: bytes, max_bytes: int = 128) -> str:
    """Format raw packet bytes into a standard Wireshark/tcpdump hex + ASCII dump."""
    if not raw_bytes:
        return ""
    
    data = raw_bytes[:max_bytes]
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        # Pad hex part to 48 characters for 16 bytes
        hex_part = hex_part.ljust(48)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        lines.append(f'{i:04x}   {hex_part}   {ascii_part}')
    return '\n'.join(lines)

def validate_filter_input(protocol: str = None, ip: str = None, port: str = None) -> tuple[bool, str]:
    """Validate query parameters for filtering."""
    if protocol and protocol.upper() not in ['ALL', 'TCP', 'UDP', 'ICMP', 'DNS', 'HTTP', 'ARP', 'OTHER']:
        return False, "Invalid protocol filter"
    
    if ip:
        # Check basic IPv4 pattern or partial string
        if not re.match(r'^[0-9a-zA-Z\.\:\*_-]{1,45}$', ip):
            return False, "Invalid IP address query"

    if port:
        try:
            p_val = int(port)
            if p_val < 0 or p_val > 65535:
                return False, "Port must be between 0 and 65535"
        except ValueError:
            return False, "Port must be an integer"

    return True, "Valid"
