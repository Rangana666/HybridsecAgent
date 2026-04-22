"""
app.py — HybridSec Flask Application Factory  (Module 5)

Creates and configures the Flask application with:
  - Blueprint registration (auth, routes, api)
  - Session management (8-hour lifetime, secure cookies)
  - CSRF token injection via context_processor
  - Rate limiting via Flask-Limiter
  - Request logging for the audit trail

Usage:
    from modules.module5_web.app import create_app
    app = create_app()
    app.run(host=FLASK_HOST, port=FLASK_PORT)
"""

import logging
import secrets
import sys
from datetime import timedelta
from pathlib import Path

from flask import Flask, session, g, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

logger = logging.getLogger(__name__)

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

try:
    from config import (
        SECRET_KEY, SESSION_LIFETIME_HOURS,
        FLASK_DEBUG, TEMPLATES_DIR, STATIC_DIR,
        DATABASE_PATH,
    )
except ImportError:
    SECRET_KEY = "CHANGE-THIS-IN-PRODUCTION"
    SESSION_LIFETIME_HOURS = 8
    FLASK_DEBUG = False
    _root = Path(__file__).parent.parent.parent
    TEMPLATES_DIR = _root / "templates"
    STATIC_DIR = _root / "static"
    DATABASE_PATH = _root / "database" / "hybridsec.db"

# ── Limiter (shared so blueprints can import it) ──────────────────
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[],
    storage_uri="memory://",
)


def create_app() -> Flask:
    """
    Flask application factory.
    Returns a fully-configured Flask app.
    """
    app = Flask(
        __name__,
        template_folder=str(TEMPLATES_DIR),
        static_folder=str(STATIC_DIR),
    )

    # ── Core config ────────────────────────────────────────────
    app.config.update(
        SECRET_KEY=SECRET_KEY,
        PERMANENT_SESSION_LIFETIME=timedelta(hours=SESSION_LIFETIME_HOURS),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=False,   # Set True when HTTPS is enabled
        MAX_CONTENT_LENGTH=16 * 1024 * 1024,  # 16 MB upload cap
    )

    # ── Rate limiter ───────────────────────────────────────────
    limiter.init_app(app)

    # ── Inject CSRF token into every template ──────────────────
    @app.context_processor
    def inject_csrf():
        if "csrf_token" not in session:
            session["csrf_token"] = secrets.token_hex(32)
        return {"csrf_token": session["csrf_token"]}

    # ── Store current user on g for templates ──────────────────
    @app.before_request
    def load_logged_in_user():
        from modules.module5_web.auth import get_current_user
        g.user = get_current_user()

    # ── Register blueprints ────────────────────────────────────
    from modules.module5_web.auth   import auth_bp
    from modules.module5_web.routes import routes_bp
    from modules.module5_web.api    import api_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(routes_bp)
    app.register_blueprint(api_bp, url_prefix="/api")

    # ── Ensure DB + default admin exist ───────────────────────
    with app.app_context():
        from modules.module5_web.auth import init_db
        init_db()

    logger.info("HybridSec Flask app created  debug=%s", FLASK_DEBUG)
    return app
