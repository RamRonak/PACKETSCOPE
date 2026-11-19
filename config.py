import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Config:
    """Application configuration for PacketScope."""
    APP_NAME = "PacketScope"
    APP_TAGLINE = "Capture. Analyze. Understand Your Network."
    APP_VERSION = "1.0.0"

    # Security
    SECRET_KEY = os.environ.get("PACKETSCOPE_SECRET_KEY", "packetscope-educational-secret-key-2026")
    DEBUG = os.environ.get("PACKETSCOPE_DEBUG", "True").lower() == "true"
    HOST = os.environ.get("PACKETSCOPE_HOST", "127.0.0.1")
    PORT = int(os.environ.get("PACKETSCOPE_PORT", 5000))

    # Directories
    DATABASE_PATH = os.path.join(BASE_DIR, "database", "packetscope.db")
    UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
    SAMPLE_PCAPS_FOLDER = os.path.join(BASE_DIR, "sample_pcaps")
    REPORTS_FOLDER = os.path.join(BASE_DIR, "reports")

    # File Upload Limits
    MAX_CONTENT_LENGTH = 50 * 1024 * 1024  # 50 MB max upload
    ALLOWED_EXTENSIONS = {"pcap", "pcapng", "cap"}

    # Packet Capture Constraints
    MAX_CAPTURE_PACKETS = 5000  # Safe in-memory limit to prevent resource exhaustion
    DEFAULT_PACKET_COUNT = 100
    CAPTURE_TIMEOUT_SECONDS = 300  # Auto-stop after 5 minutes if left unattended

    # Privacy and Security Safeguards
    CAPTURE_SAFE_MODE = True
    SAFE_PAYLOAD_PREVIEW_BYTES = 128
    MASK_SENSITIVE_DATA = True
    ALLOW_PACKET_INJECTION = False
    ALLOW_PROMISCUOUS_PROBE = False

    # Template and Static Folders
    TEMPLATE_FOLDER = os.path.join(BASE_DIR, "frontend", "templates")
    STATIC_FOLDER = os.path.join(BASE_DIR, "frontend", "static")
