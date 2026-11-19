import os
import json
from flask import Blueprint, request, jsonify, send_file, Response, current_app
from werkzeug.utils import secure_filename

from config import Config
from backend.capture.interfaces import get_network_interfaces, get_system_capture_capabilities
from backend.services.capture_service import CaptureService
from backend.services.pcap_service import PcapService
from backend.services.export_service import ExportService
from backend.security.validators import allowed_file, validate_and_sanitize_filename, validate_filter_input
from database.models import DatabaseManager

api_bp = Blueprint('api', __name__, url_prefix='/api')

@api_bp.route('/interfaces', methods=['GET'])
def list_interfaces():
    """List network interfaces and OS packet capture capabilities."""
    ifaces = get_network_interfaces()
    caps = get_system_capture_capabilities()
    return jsonify({
        "success": True,
        "interfaces": ifaces,
        "capabilities": caps
    })

@api_bp.route('/capture/start', methods=['POST'])
def start_capture():
    """Start live packet capture."""
    data = request.get_json(silent=True) or {}
    interface = data.get('interface', 'all')
    filter_type = data.get('filter', 'ALL')
    session_name = data.get('session_name')

    valid, err_msg = validate_filter_input(protocol=filter_type)
    if not valid:
        return jsonify({"success": False, "error": err_msg}), 400

    result = CaptureService.start_live_capture(interface, filter_type, session_name)
    return jsonify(result)

@api_bp.route('/capture/stop', methods=['POST'])
def stop_capture():
    """Stop active packet capture."""
    result = CaptureService.stop_live_capture()
    return jsonify(result)

@api_bp.route('/capture/status', methods=['GET'])
def capture_status():
    """Get status of active capture session."""
    status = CaptureService.get_live_status()
    return jsonify(status)

@api_bp.route('/capture/live', methods=['GET'])
def live_data():
    """Poll newly arrived packets and up-to-the-second traffic statistics."""
    since = request.args.get('since', 0, type=int)
    data = CaptureService.get_live_data(since_index=since)
    return jsonify(data)

@api_bp.route('/sessions', methods=['GET'])
def list_sessions():
    """Retrieve history of capture sessions."""
    sessions = DatabaseManager.get_sessions(limit=50)
    return jsonify({"success": True, "sessions": sessions})

@api_bp.route('/sessions/<int:session_id>', methods=['GET'])
def get_session(session_id):
    """Get single session statistics and metadata."""
    data = CaptureService.get_session_dashboard_data(session_id)
    if not data:
        return jsonify({"success": False, "error": "Session not found"}), 404
    return jsonify({"success": True, "data": data})

@api_bp.route('/sessions/<int:session_id>/packets', methods=['GET'])
def get_session_packets(session_id):
    """Retrieve filtered and paginated packets for a session."""
    protocol = request.args.get('protocol', 'ALL')
    ip = request.args.get('ip')
    port = request.args.get('port')
    search = request.args.get('search')
    limit = min(request.args.get('limit', 100, type=int), 1000)
    offset = request.args.get('offset', 0, type=int)

    valid, err = validate_filter_input(protocol=protocol, ip=ip, port=port)
    if not valid:
        return jsonify({"success": False, "error": err}), 400

    packets, total_count = DatabaseManager.get_packets(
        session_id=session_id,
        protocol=protocol,
        ip=ip,
        port=port,
        search=search,
        limit=limit,
        offset=offset
    )

    return jsonify({
        "success": True,
        "session_id": session_id,
        "total": total_count,
        "limit": limit,
        "offset": offset,
        "packets": packets
    })

@api_bp.route('/sessions/<int:session_id>', methods=['DELETE', 'POST'])
def delete_session(session_id):
    """Delete a capture session from database."""
    success = DatabaseManager.delete_session(session_id)
    return jsonify({"success": success})

@api_bp.route('/packet/<int:packet_id>', methods=['GET'])
def get_packet_detail(packet_id):
    """Retrieve deep inspection details for a single packet."""
    packet = DatabaseManager.get_packet_by_id(packet_id)
    if not packet:
        return jsonify({"success": False, "error": "Packet not found"}), 404

    # Parse layers json
    layers = []
    if packet.get('layers_json'):
        try:
            layers = json.loads(packet['layers_json'])
        except Exception:
            layers = []

    packet['layers'] = layers
    return jsonify({"success": True, "packet": packet})

@api_bp.route('/pcap/upload', methods=['POST'])
def upload_pcap():
    """Upload and process a PCAP file."""
    if 'file' not in request.files:
        return jsonify({"success": False, "error": "No file uploaded"}), 400

    file = request.files['file']
    if not file or file.filename == '':
        return jsonify({"success": False, "error": "Empty filename"}), 400

    if not allowed_file(file.filename):
        return jsonify({
            "success": False,
            "error": f"Invalid format. Allowed formats: {', '.join(Config.ALLOWED_EXTENSIONS)}"
        }), 400

    safe_name = validate_and_sanitize_filename(file.filename)
    os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)
    target_path = os.path.join(Config.UPLOAD_FOLDER, safe_name)

    # Save file
    file.save(target_path)

    # Process PCAP
    result = PcapService.process_pcap_file(target_path, original_filename=file.filename)
    return jsonify(result)

@api_bp.route('/pcap/samples', methods=['GET'])
def list_samples():
    """List educational sample PCAP captures."""
    samples = PcapService.list_available_samples()
    return jsonify({"success": True, "samples": samples})

@api_bp.route('/pcap/load-sample', methods=['POST'])
def load_sample():
    """Load a pre-bundled sample PCAP capture into a new session."""
    data = request.get_json(silent=True) or {}
    sample_name = data.get('filename')
    if not sample_name:
        return jsonify({"success": False, "error": "Missing filename parameter"}), 400

    safe_name = secure_filename(sample_name)
    sample_path = os.path.join(Config.SAMPLE_PCAPS_FOLDER, safe_name)

    if not os.path.exists(sample_path):
        return jsonify({"success": False, "error": "Sample file not found"}), 404

    result = PcapService.process_pcap_file(sample_path, original_filename=safe_name)
    return jsonify(result)

@api_bp.route('/export/csv/<int:session_id>', methods=['GET'])
def export_csv_route(session_id):
    """Generate and download CSV export for a session."""
    try:
        csv_data, filename = ExportService.export_csv(session_id)
        return Response(
            csv_data,
            mimetype="text/csv",
            headers={"Content-Disposition": f"attachment;filename={filename}"}
        )
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 404

@api_bp.route('/export/pdf/<int:session_id>', methods=['GET'])
def export_pdf_route(session_id):
    """Generate and download PDF cybersecurity report for a session."""
    try:
        pdf_path = ExportService.generate_pdf_report(session_id)
        return send_file(
            pdf_path,
            mimetype="application/pdf",
            as_attachment=True,
            download_name=os.path.basename(pdf_path)
        )
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 404

@api_bp.route('/export/pcap/<int:session_id>', methods=['GET'])
def export_pcap_route(session_id):
    """Download PCAP file for an imported or captured session."""
    session = DatabaseManager.get_session(session_id)
    if not session or not session.get('pcap_path') or not os.path.exists(session['pcap_path']):
        return jsonify({"success": False, "error": "PCAP file not available for this session"}), 404

    return send_file(
        session['pcap_path'],
        mimetype="application/vnd.tcpdump.pcap",
        as_attachment=True,
        download_name=os.path.basename(session['pcap_path'])
    )
