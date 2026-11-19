import os
import sys
from flask import Flask, render_template, jsonify
from config import Config
from database.models import DatabaseManager
from backend.routes.views import views_bp
from backend.routes.api import api_bp

def create_app(config_class=Config):
    """PacketScope application factory."""
    app = Flask(
        __name__,
        template_folder=config_class.TEMPLATE_FOLDER,
        static_folder=config_class.STATIC_FOLDER
    )
    app.config.from_object(config_class)

    # Initialize SQLite Database & Ensure Directories
    with app.app_context():
        DatabaseManager.init_db()
        os.makedirs(config_class.UPLOAD_FOLDER, exist_ok=True)
        os.makedirs(config_class.SAMPLE_PCAPS_FOLDER, exist_ok=True)
        os.makedirs(config_class.REPORTS_FOLDER, exist_ok=True)

    # Register Blueprints
    app.register_blueprint(views_bp)
    app.register_blueprint(api_bp)

    # Context Processors
    @app.context_processor
    def inject_global_vars():
        return {
            "app_name": Config.APP_NAME,
            "app_tagline": Config.APP_TAGLINE,
            "app_version": Config.APP_VERSION
        }

    # Error Handlers
    @app.errorhandler(404)
    def page_not_found(e):
        return render_template('base.html', error_message="Page Not Found (404)"), 404

    @app.errorhandler(413)
    def file_too_large(e):
        return jsonify({"success": False, "error": "File exceeds maximum 50MB size limit"}), 413

    @app.errorhandler(500)
    def internal_error(e):
        return jsonify({"success": False, "error": "Internal server error occurred"}), 500

    return app

app = create_app()

if __name__ == '__main__':
    print(f"[*] Starting {Config.APP_NAME} on http://{Config.HOST}:{Config.PORT}")
    app.run(host=Config.HOST, port=Config.PORT, debug=Config.DEBUG)
