from flask import Blueprint, render_template, request, redirect, url_for
from config import Config
from backend.capture.interfaces import get_network_interfaces, get_system_capture_capabilities
from backend.services.pcap_service import PcapService
from database.models import DatabaseManager

views_bp = Blueprint('views', __name__)

@views_bp.route('/')
def home():
    """Home landing page with hero, features, and protocol overview."""
    interfaces = get_network_interfaces()
    caps = get_system_capture_capabilities()
    samples = PcapService.list_available_samples()
    return render_template(
        'index.html',
        app_name=Config.APP_NAME,
        tagline=Config.APP_TAGLINE,
        interfaces=interfaces,
        capabilities=caps,
        samples=samples
    )

@views_bp.route('/dashboard')
def dashboard():
    """Main network monitoring dashboard."""
    interfaces = get_network_interfaces()
    caps = get_system_capture_capabilities()
    sessions = DatabaseManager.get_sessions(limit=20)
    current_session_id = request.args.get('session_id', type=int)
    
    return render_template(
        'dashboard.html',
        app_name=Config.APP_NAME,
        interfaces=interfaces,
        capabilities=caps,
        sessions=sessions,
        selected_session_id=current_session_id
    )

@views_bp.route('/inspector')
def inspector():
    """Dedicated deep packet inspection page."""
    sessions = DatabaseManager.get_sessions(limit=30)
    selected_session_id = request.args.get('session_id', type=int)
    if not selected_session_id and sessions:
        selected_session_id = sessions[0]['id']

    return render_template(
        'inspector.html',
        app_name=Config.APP_NAME,
        sessions=sessions,
        selected_session_id=selected_session_id
    )

@views_bp.route('/protocols')
def protocols():
    """Protocol analysis reference and header dissection guide."""
    return render_template(
        'protocols.html',
        app_name=Config.APP_NAME
    )

@views_bp.route('/pcap')
def pcap_analysis():
    """Offline PCAP file upload and metadata inspection."""
    samples = PcapService.list_available_samples()
    sessions = DatabaseManager.get_sessions(limit=15)
    return render_template(
        'pcap_analysis.html',
        app_name=Config.APP_NAME,
        samples=samples,
        sessions=sessions
    )

@views_bp.route('/history')
def history():
    """Capture history and PDF/CSV report generation center."""
    sessions = DatabaseManager.get_sessions(limit=100)
    return render_template(
        'history.html',
        app_name=Config.APP_NAME,
        sessions=sessions
    )

@views_bp.route('/education')
def education():
    """Interactive networking fundamentals and quiz module."""
    return render_template(
        'education.html',
        app_name=Config.APP_NAME
    )
