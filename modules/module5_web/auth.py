"""
auth.py — Authentication, 2FA, Session & DB Init  (Module 5)

Provides:
  - init_db()            — Creates all SQLite tables + default admin user
  - login_required       — Decorator that redirects to /login if not authenticated
  - get_current_user()   — Returns the user dict from session, or None
  - Blueprint auth_bp    — Handles /login, /logout, /setup-2fa, /verify-2fa

Security features:
  - werkzeug pbkdf2:sha256 password hashing
  - TOTP 2FA via pyotp (Google Authenticator compatible)
  - Account lockout after MAX_LOGIN_ATTEMPTS failures
  - Rate limiting on /login via Flask-Limiter
  - Audit log for every login attempt (success + failure)
  - CSRF token validation on all POST endpoints
"""

import functools
import logging
import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import pyotp
from flask import (
    Blueprint, flash, g, redirect, render_template,
    request, session, url_for, abort
)
from werkzeug.security import check_password_hash, generate_password_hash

logger = logging.getLogger(__name__)

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

try:
    from config import (
        DATABASE_PATH, MAX_LOGIN_ATTEMPTS, SESSION_LIFETIME_HOURS,
        LOGIN_RATE_LIMIT,
    )
except ImportError:
    _root = Path(__file__).parent.parent.parent
    DATABASE_PATH = _root / "database" / "hybridsec.db"
    MAX_LOGIN_ATTEMPTS = 10
    SESSION_LIFETIME_HOURS = 8
    LOGIN_RATE_LIMIT = "5 per minute"

DEFAULT_ADMIN_USER     = "admin"
DEFAULT_ADMIN_PASSWORD = "Admin@HybridSec2025!"

auth_bp = Blueprint("auth", __name__)

# ── Import limiter lazily to avoid circular import ────────────────
def _limiter():
    from modules.module5_web.app import limiter
    return limiter


# ══════════════════════════════════════════════════════════════════
#   DATABASE
# ══════════════════════════════════════════════════════════════════

def _get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DATABASE_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    """
    Create all required tables and insert the default admin user
    if it does not already exist.
    """
    db = _get_db()
    try:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                username            TEXT UNIQUE NOT NULL,
                password_hash       TEXT NOT NULL,
                totp_secret         TEXT DEFAULT NULL,
                totp_enabled        INTEGER DEFAULT 0,
                is_active           INTEGER DEFAULT 1,
                login_attempts_count INTEGER DEFAULT 0,
                locked_until        TEXT DEFAULT NULL,
                created_at          TEXT DEFAULT (datetime('now')),
                last_login          TEXT DEFAULT NULL
            );

            CREATE TABLE IF NOT EXISTS audit_log (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   TEXT DEFAULT (datetime('now')),
                user_id     INTEGER REFERENCES users(id),
                username    TEXT,
                action      TEXT NOT NULL,
                detail      TEXT,
                ip_address  TEXT,
                success     INTEGER DEFAULT 1
            );

            CREATE TABLE IF NOT EXISTS login_attempts (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address  TEXT NOT NULL,
                username    TEXT,
                attempted_at TEXT DEFAULT (datetime('now')),
                success     INTEGER DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS scan_results (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id         TEXT UNIQUE NOT NULL,
                scan_type       TEXT,
                target          TEXT,
                started_at      TEXT DEFAULT (datetime('now')),
                completed_at    TEXT,
                status          TEXT DEFAULT 'pending',
                result_json     TEXT,
                triggered_by    INTEGER REFERENCES users(id)
            );
        """)
        db.commit()
        logger.info("DB tables created/verified.")

        # Insert default admin if missing
        cur = db.execute("SELECT id FROM users WHERE username = ?", (DEFAULT_ADMIN_USER,))
        if cur.fetchone() is None:
            ph = generate_password_hash(DEFAULT_ADMIN_PASSWORD)
            db.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (DEFAULT_ADMIN_USER, ph),
            )
            db.commit()
            logger.info("Default admin user created: %s", DEFAULT_ADMIN_USER)
    finally:
        db.close()


# ══════════════════════════════════════════════════════════════════
#   SESSION HELPERS
# ══════════════════════════════════════════════════════════════════

def get_current_user() -> Optional[dict]:
    """Return the logged-in user dict from session, or None."""
    user_id = session.get("user_id")
    if user_id is None:
        return None
    db = _get_db()
    try:
        row = db.execute(
            "SELECT id, username, totp_enabled, is_active FROM users WHERE id = ?",
            (user_id,)
        ).fetchone()
        if row and row["is_active"]:
            return dict(row)
        return None
    finally:
        db.close()


def login_required(view):
    """Decorator: redirect to /login if the user is not authenticated."""
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            return redirect(url_for("auth.login"))
        return view(*args, **kwargs)
    return wrapped


def _validate_csrf(form_token: str) -> bool:
    return form_token and form_token == session.get("csrf_token")


# ══════════════════════════════════════════════════════════════════
#   AUDIT LOG
# ══════════════════════════════════════════════════════════════════

def audit(action: str, detail: str = "", success: bool = True, user_id: int = None,
          username: str = None):
    """Insert a row into audit_log."""
    try:
        db = _get_db()
        db.execute(
            """INSERT INTO audit_log
               (user_id, username, action, detail, ip_address, success)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                user_id or session.get("user_id"),
                username or session.get("username"),
                action, detail,
                request.remote_addr,
                1 if success else 0,
            ),
        )
        db.commit()
        db.close()
    except Exception as exc:
        logger.warning("Audit log write failed: %s", exc)


# ══════════════════════════════════════════════════════════════════
#   AUTH ROUTES
# ══════════════════════════════════════════════════════════════════

@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if g.user:
        return redirect(url_for("routes.dashboard"))

    error = None

    if request.method == "POST":
        # CSRF check
        if not _validate_csrf(request.form.get("csrf_token", "")):
            abort(403)

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        db = _get_db()
        try:
            user = db.execute(
                "SELECT * FROM users WHERE username = ?", (username,)
            ).fetchone()

            # Record attempt
            db.execute(
                "INSERT INTO login_attempts (ip_address, username, success) VALUES (?,?,0)",
                (request.remote_addr, username),
            )
            db.commit()

            if not user or not user["is_active"]:
                error = "Invalid credentials."
                audit("LOGIN_FAIL", f"user={username} not found", success=False,
                      username=username)
            elif user["locked_until"] and datetime.fromisoformat(user["locked_until"]) > datetime.now(timezone.utc):
                error = "Account temporarily locked. Try again later."
                audit("LOGIN_BLOCKED", f"user={username} locked", success=False,
                      username=username)
            elif not check_password_hash(user["password_hash"], password):
                # Increment attempt counter
                new_count = user["login_attempts_count"] + 1
                locked_until = None
                if new_count >= MAX_LOGIN_ATTEMPTS:
                    locked_until = (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat()
                db.execute(
                    "UPDATE users SET login_attempts_count=?, locked_until=? WHERE id=?",
                    (new_count, locked_until, user["id"]),
                )
                db.commit()
                error = "Invalid credentials."
                audit("LOGIN_FAIL", f"user={username} wrong password", success=False,
                      username=username)
            else:
                # Valid password — reset counter
                db.execute(
                    "UPDATE users SET login_attempts_count=0, locked_until=NULL, last_login=? WHERE id=?",
                    (datetime.now(timezone.utc).isoformat(), user["id"]),
                )
                db.commit()

                if user["totp_enabled"]:
                    # Store partial auth in session, redirect to 2FA
                    session["pending_user_id"] = user["id"]
                    session["pending_username"] = user["username"]
                    return redirect(url_for("auth.verify_2fa"))

                # Full login
                session.permanent = True
                session["user_id"]  = user["id"]
                session["username"] = user["username"]
                audit("LOGIN_OK", f"user={username}", success=True,
                      user_id=user["id"], username=username)
                return redirect(url_for("routes.dashboard"))
        finally:
            db.close()

    return render_template("login.html", error=error)


@auth_bp.route("/logout")
def logout():
    audit("LOGOUT")
    session.clear()
    return redirect(url_for("auth.login"))


@auth_bp.route("/verify-2fa", methods=["GET", "POST"])
def verify_2fa():
    pending_id = session.get("pending_user_id")
    if not pending_id:
        return redirect(url_for("auth.login"))

    error = None
    if request.method == "POST":
        if not _validate_csrf(request.form.get("csrf_token", "")):
            abort(403)

        otp_input = request.form.get("otp_code", "").strip()
        db = _get_db()
        try:
            user = db.execute(
                "SELECT * FROM users WHERE id = ?", (pending_id,)
            ).fetchone()

            if not user:
                session.pop("pending_user_id", None)
                return redirect(url_for("auth.login"))

            totp = pyotp.TOTP(user["totp_secret"])
            if totp.verify(otp_input, valid_window=1):
                session.pop("pending_user_id", None)
                session.pop("pending_username", None)
                session.permanent = True
                session["user_id"]  = user["id"]
                session["username"] = user["username"]
                audit("2FA_OK", f"user={user['username']}", success=True,
                      user_id=user["id"], username=user["username"])
                return redirect(url_for("routes.dashboard"))
            else:
                error = "Invalid OTP code. Please try again."
                audit("2FA_FAIL", f"user={user['username']}", success=False,
                      user_id=user["id"], username=user["username"])
        finally:
            db.close()

    return render_template("verify_2fa.html", error=error)


@auth_bp.route("/setup-2fa", methods=["GET", "POST"])
@login_required
def setup_2fa():
    user_id = session["user_id"]
    db = _get_db()
    try:
        user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if not user:
            return redirect(url_for("auth.login"))

        if request.method == "POST":
            if not _validate_csrf(request.form.get("csrf_token", "")):
                abort(403)

            action = request.form.get("action")

            if action == "generate":
                new_secret = pyotp.random_base32()
                db.execute(
                    "UPDATE users SET totp_secret=?, totp_enabled=0 WHERE id=?",
                    (new_secret, user_id),
                )
                db.commit()
                totp = pyotp.TOTP(new_secret)
                provisioning_uri = totp.provisioning_uri(
                    name=user["username"], issuer_name="HybridSec"
                )
                # Generate QR code server-side as base64 PNG
                qr_b64 = ""
                try:
                    import qrcode, io, base64
                    qr = qrcode.QRCode(version=1, box_size=8, border=4)
                    qr.add_data(provisioning_uri)
                    qr.make(fit=True)
                    img = qr.make_image(fill_color="black", back_color="white")
                    buf = io.BytesIO()
                    img.save(buf, format="PNG")
                    qr_b64 = base64.b64encode(buf.getvalue()).decode()
                except Exception:
                    pass
                audit("2FA_SETUP_GENERATE")
                return render_template(
                    "setup_2fa.html",
                    provisioning_uri=provisioning_uri,
                    totp_secret=new_secret,
                    qr_b64=qr_b64,
                    step="confirm",
                    user=dict(user),
                )

            elif action == "confirm":
                otp_input = request.form.get("otp_code", "").strip()
                secret = request.form.get("totp_secret", "").strip()
                totp = pyotp.TOTP(secret)
                if totp.verify(otp_input, valid_window=1):
                    db.execute(
                        "UPDATE users SET totp_secret=?, totp_enabled=1 WHERE id=?",
                        (secret, user_id),
                    )
                    db.commit()
                    audit("2FA_ENABLED")
                    flash("Two-factor authentication enabled successfully!", "success")
                    return redirect(url_for("routes.settings"))
                else:
                    flash("OTP verification failed. Please try again.", "danger")
                    return redirect(url_for("auth.setup_2fa"))

            elif action == "disable":
                db.execute(
                    "UPDATE users SET totp_secret=NULL, totp_enabled=0 WHERE id=?",
                    (user_id,),
                )
                db.commit()
                audit("2FA_DISABLED")
                flash("Two-factor authentication disabled.", "warning")
                return redirect(url_for("routes.settings"))

        # GET — show current 2FA status
        return render_template("setup_2fa.html", step="status", user=dict(user))
    finally:
        db.close()


@auth_bp.route("/change-password", methods=["POST"])
@login_required
def change_password():
    if not _validate_csrf(request.form.get("csrf_token", "")):
        abort(403)

    current = request.form.get("current_password", "")
    new_pw  = request.form.get("new_password", "")
    confirm = request.form.get("confirm_password", "")

    if new_pw != confirm:
        flash("Passwords do not match.", "danger")
        return redirect(url_for("routes.settings"))
    if len(new_pw) < 12:
        flash("Password must be at least 12 characters.", "danger")
        return redirect(url_for("routes.settings"))

    db = _get_db()
    try:
        user = db.execute(
            "SELECT * FROM users WHERE id = ?", (session["user_id"],)
        ).fetchone()
        if not check_password_hash(user["password_hash"], current):
            flash("Current password is incorrect.", "danger")
            return redirect(url_for("routes.settings"))

        db.execute(
            "UPDATE users SET password_hash=? WHERE id=?",
            (generate_password_hash(new_pw), session["user_id"]),
        )
        db.commit()
        audit("PASSWORD_CHANGED")
        flash("Password changed successfully.", "success")
    finally:
        db.close()

    return redirect(url_for("routes.settings"))
