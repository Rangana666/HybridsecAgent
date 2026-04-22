"""
routes.py — Page Routes Blueprint  (Module 5)

Handles all HTML page renders (non-API routes).
Every route is protected by @login_required.

Routes:
  /                  → redirect to /dashboard
  /dashboard         → main stats overview
  /scan              → run / view scan
  /profile           → SME context profile form
  /risks             → scored vulnerability list
  /remediation       → remediation cards
  /threats           → live guard events
  /reports           → download reports
  /audit             → audit log table
  /settings          → password + 2FA settings
"""

import json
import logging
import mimetypes
import os
import sqlite3
import sys
from pathlib import Path

from flask import Blueprint, render_template, redirect, url_for, request, flash, g, send_file, abort

logger = logging.getLogger(__name__)

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

# ── .env file helpers ─────────────────────────────────────────
_ENV_FILE = Path(__file__).parent.parent.parent / ".env"

_SENSITIVE_KEYS = {
    "OPENAI_API_KEY", "OPENROUTER_API_KEY", "GEMINI_API_KEY",
    "TELEGRAM_BOT_TOKEN", "SMTP_PASSWORD",
}

def _read_env_file() -> dict:
    """Parse .env file into a dict (ignores comments and blank lines)."""
    result = {}
    if not _ENV_FILE.exists():
        return result
    for line in _ENV_FILE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, _, v = line.partition("=")
            result[k.strip()] = v.strip()
    return result

def _write_env_key(key: str, value: str) -> None:
    """Update or append a single key in the .env file."""
    if not _ENV_FILE.exists():
        _ENV_FILE.write_text(f"{key}={value}\n", encoding="utf-8")
        return
    lines = _ENV_FILE.read_text(encoding="utf-8").splitlines(keepends=True)
    found = False
    new_lines = []
    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and "=" in stripped:
            k = stripped.split("=", 1)[0].strip()
            if k == key:
                new_lines.append(f"{key}={value}\n")
                found = True
                continue
        new_lines.append(line)
    if not found:
        new_lines.append(f"{key}={value}\n")
    _ENV_FILE.write_text("".join(new_lines), encoding="utf-8")

def _apply_env(key: str, value: str) -> None:
    """Apply an env var to the running process and update config module globals."""
    os.environ[key] = value
    try:
        import config as _cfg
        # Re-derive booleans/ints that depend on this key
        if key == "OPENAI_API_KEY":
            _cfg.OPENAI_API_KEY = value
        elif key == "OPENROUTER_API_KEY":
            _cfg.OPENROUTER_API_KEY = value
        elif key == "GEMINI_API_KEY":
            _cfg.GEMINI_API_KEY = value
        elif key == "LLM_PROVIDER":
            _cfg.LLM_PROVIDER = value
        elif key == "OPENROUTER_MODEL":
            _cfg.OPENROUTER_MODEL = value
        elif key == "GEMINI_MODEL":
            _cfg.GEMINI_MODEL = value
        elif key == "TELEGRAM_BOT_TOKEN":
            _cfg.TELEGRAM_BOT_TOKEN = value
            _cfg.TELEGRAM_ENABLED = bool(value and _cfg.TELEGRAM_CHAT_ID)
        elif key == "TELEGRAM_CHAT_ID":
            _cfg.TELEGRAM_CHAT_ID = value
            _cfg.TELEGRAM_ENABLED = bool(_cfg.TELEGRAM_BOT_TOKEN and value)
        elif key == "ALERT_EMAIL":
            _cfg.ALERT_EMAIL = value
            _cfg.EMAIL_ALERTS_ENABLED = bool(value and _cfg.SMTP_PASSWORD)
        elif key == "SMTP_PASSWORD":
            _cfg.SMTP_PASSWORD = value
            _cfg.EMAIL_ALERTS_ENABLED = bool(_cfg.ALERT_EMAIL and value)
        elif key == "SMTP_HOST":
            _cfg.SMTP_HOST = value
        elif key == "SMTP_PORT":
            _cfg.SMTP_PORT = int(value) if value.isdigit() else 587
        elif key == "USE_LOCAL_LLM":
            _cfg.USE_LOCAL_LLM = value.lower() == "true"
        elif key == "LOCAL_LLM_URL":
            _cfg.LOCAL_LLM_URL = value
        elif key == "LOCAL_LLM_MODEL":
            _cfg.LOCAL_LLM_MODEL = value
        elif key == "NVD_API_KEY":
            _cfg.NVD_API_KEY = value
        elif key == "ENGINE_RULE_ENABLED":
            _cfg.ENGINE_RULE_ENABLED = val.lower() == "true" if (val := value) else True
        elif key == "ENGINE_ML_ENABLED":
            _cfg.ENGINE_ML_ENABLED = value.lower() == "true"
        elif key == "ENGINE_LLM_ENABLED":
            _cfg.ENGINE_LLM_ENABLED = value.lower() == "true"
        # llm_scorer now reads from _cfg directly, no extra propagation needed
    except Exception as exc:
        logger.warning("_apply_env: could not update module globals: %s", exc)

def _mask(value: str) -> str:
    """Return a masked version of a sensitive value for display."""
    if not value or value.startswith("your-") or value.startswith("sk-your"):
        return ""
    if len(value) <= 8:
        return "••••••••"
    return value[:4] + "••••••••" + value[-4:]

_PLACEHOLDERS = (
    "your-", "sk-your", "AIza-your", "sk-or-your",
    "change-this", "your_", "example",
    # NOTE: do NOT add "" here — str.startswith("") is always True in Python
)

def _real_key(val: str) -> bool:
    """Return True only if val looks like a real secret (not a placeholder)."""
    v = (val or "").strip()
    if not v:
        return False   # empty string handled explicitly, not via startswith
    return not any(v.startswith(p) for p in _PLACEHOLDERS)

from modules.module5_web.auth import login_required, _get_db, audit

routes_bp = Blueprint("routes", __name__)


# ── Helper: load latest completed scan from DB ─────────────────────
def _latest_scan() -> dict | None:
    db = _get_db()
    try:
        row = db.execute(
            """SELECT * FROM scan_results
               WHERE status = 'completed'
               ORDER BY completed_at DESC LIMIT 1"""
        ).fetchone()
        if row and row["result_json"]:
            result = dict(row)
            result["data"] = json.loads(row["result_json"])
            return result
        return None
    finally:
        db.close()


def _last_lynis_score() -> int:
    """Return the most recent non-zero lynis_score from any completed scan."""
    db = _get_db()
    try:
        rows = db.execute(
            """SELECT result_json FROM scan_results
               WHERE status = 'completed' AND result_json IS NOT NULL
               ORDER BY completed_at DESC LIMIT 20"""
        ).fetchall()
        for row in rows:
            try:
                data = json.loads(row["result_json"])
                score = data.get("lynis_score", 0)
                if score and score > 0:
                    return int(score)
            except Exception:
                continue
        return 0
    finally:
        db.close()


def _get_scan_by_id(scan_id: str) -> dict | None:
    db = _get_db()
    try:
        row = db.execute(
            "SELECT * FROM scan_results WHERE scan_id = ?", (scan_id,)
        ).fetchone()
        if row:
            result = dict(row)
            if row["result_json"]:
                result["data"] = json.loads(row["result_json"])
            return result
        return None
    finally:
        db.close()


# ══════════════════════════════════════════════════════════════════
#   ROUTES
# ══════════════════════════════════════════════════════════════════

@routes_bp.route("/")
@login_required
def index():
    return redirect(url_for("routes.dashboard"))


@routes_bp.route("/dashboard")
@login_required
def dashboard():
    scan = _latest_scan()
    stats = {
        "critical": 0, "high": 0, "medium": 0, "low": 0,
        "total": 0, "lynis_score": 0, "lynis_has_data": False,
        "scan_time": "Never", "server_hostname": "—",
    }

    recent_vulns = []
    if scan and scan.get("data"):
        data = scan["data"]
        all_vulns = data.get("vulnerabilities", [])

        # Recount from actual scored vulnerabilities (scan_summary can be stale)
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for v in all_vulns:
            p = (v.get("priority") or "LOW").upper()
            if p in counts:
                counts[p] += 1

        _lynis_now = int(data.get("lynis_score") or 0)
        _lynis_best = _lynis_now if _lynis_now > 0 else _last_lynis_score()
        stats.update({
            "critical":       counts["CRITICAL"],
            "high":           counts["HIGH"],
            "medium":         counts["MEDIUM"],
            "low":            counts["LOW"],
            "total":          len(all_vulns),
            "lynis_score":    _lynis_best,
            "lynis_has_data": _lynis_best > 0,
            "scan_time":   scan.get("completed_at", "—")[:16].replace("T", " "),
            "server_hostname": data.get("server_info", {}).get("hostname", "—"),
        })

        recent_vulns = [
            v for v in all_vulns
            if (v.get("priority") or "").upper() in ("CRITICAL", "HIGH")
        ][:5]

    # Model status — read fresh from .env so we don't depend on startup state
    ml_model_path = Path(__file__).parent.parent / "module3_scoring" / "models" / "risk_model.pkl"

    try:
        _env = _read_env_file()
        _ok_openai    = _real_key(_env.get("OPENAI_API_KEY", ""))
        _ok_openrouter = _real_key(_env.get("OPENROUTER_API_KEY", ""))
        _ok_gemini    = _real_key(_env.get("GEMINI_API_KEY", ""))
        _ok_local     = _env.get("USE_LOCAL_LLM", "").lower() == "true"
        llm_ok = _ok_openai or _ok_openrouter or _ok_gemini or _ok_local
        llm_provider = _env.get("LLM_PROVIDER", "openai")
        logger.info(
            "LLM status: ok=%s provider=%s openai=%s openrouter=%s gemini=%s local=%s",
            llm_ok, llm_provider, _ok_openai, _ok_openrouter, _ok_gemini, _ok_local
        )
    except Exception as _e:
        logger.error("dashboard LLM status error: %s", _e, exc_info=True)
        llm_ok, llm_provider = False, "openai"

    rule_enabled = _env.get("ENGINE_RULE_ENABLED", "true").lower() != "false"
    ml_enabled   = _env.get("ENGINE_ML_ENABLED",   "true").lower() != "false"
    llm_enabled  = _env.get("ENGINE_LLM_ENABLED",  "true").lower() != "false"

    model_status = {
        "rule": {"ok": True,                   "label": "Rule-based",       "enabled": rule_enabled},
        "ml":   {"ok": ml_model_path.exists(), "label": "ML (Random Forest)","enabled": ml_enabled},
        "llm":  {"ok": llm_ok,                 "label": f"LLM ({llm_provider})", "enabled": llm_enabled},
    }

    return render_template(
        "dashboard.html",
        stats=stats,
        recent_vulns=recent_vulns,
        scan=scan,
        model_status=model_status,
    )


@routes_bp.route("/scan")
@login_required
def scan():
    # Check if there is a running scan
    db = _get_db()
    try:
        running = db.execute(
            "SELECT scan_id FROM scan_results WHERE status='running' ORDER BY started_at DESC LIMIT 1"
        ).fetchone()
        running_scan_id = running["scan_id"] if running else None
    finally:
        db.close()

    # History: last 10 scans
    db = _get_db()
    try:
        rows = db.execute(
            """SELECT scan_id, scan_type, target, started_at, completed_at, status
               FROM scan_results ORDER BY started_at DESC LIMIT 10"""
        ).fetchall()
        history = [dict(r) for r in rows]
    finally:
        db.close()

    return render_template(
        "scan.html",
        running_scan_id=running_scan_id,
        history=history,
    )


@routes_bp.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    from modules.module2_context.context_manager import ContextManager
    from modules.module2_context.profile_validator import VALID_OPTIONS, QUESTION_LABELS

    cm = ContextManager()

    if request.method == "POST":
        data = {
            "business_name":  request.form.get("business_name", ""),
            "business_type":  request.form.get("business_type", ""),
            "employee_count": request.form.get("employee_count", ""),
            "server_purpose": request.form.get("server_purpose", ""),
            "sensitive_data": request.form.get("sensitive_data", ""),
            "has_it_staff":   request.form.get("has_it_staff", ""),
            "security_budget": request.form.get("security_budget", ""),
        }
        from modules.module2_context.profile_validator import ProfileValidator
        ok, errors = ProfileValidator().validate(data)
        if not ok:
            flash("Validation errors: " + "; ".join(errors), "danger")
        else:
            existing = cm.get_active_profile()
            if existing:
                cm.update_profile(existing["id"], data)
                flash("Profile updated.", "success")
            else:
                cm.save_profile(data)
                flash("Profile saved.", "success")
            audit("PROFILE_SAVED", json.dumps(data))
        return redirect(url_for("routes.profile"))

    active = cm.get_active_profile()
    return render_template(
        "profile.html",
        profile=active,
        valid_options=VALID_OPTIONS,
        labels=QUESTION_LABELS,
    )


@routes_bp.route("/risks")
@login_required
def risks():
    scan_id = request.args.get("scan_id")
    if scan_id:
        scan = _get_scan_by_id(scan_id)
    else:
        scan = _latest_scan()

    vulnerabilities = []
    if scan and scan.get("data"):
        vulnerabilities = scan["data"].get("vulnerabilities", [])

    priority_filter = request.args.get("priority", "all").upper()
    if priority_filter != "ALL":
        vulnerabilities = [v for v in vulnerabilities if v.get("priority") == priority_filter]

    return render_template(
        "risks.html",
        vulnerabilities=vulnerabilities,
        priority_filter=priority_filter,
        scan=scan,
    )


@routes_bp.route("/remediation")
@login_required
def remediation():
    from modules.module4_remediation.remediation_generator import RemediationGenerator
    from modules.module4_remediation.backup_manager import BackupManager
    from modules.module2_context.context_manager import ContextManager

    scan = _latest_scan()
    remediations = []

    if scan and scan.get("data"):
        gen = RemediationGenerator(use_llm=False)
        cm = ContextManager()
        context = cm.get_active_profile()
        vulns = scan["data"].get("vulnerabilities", [])
        remediations = gen.get_all_remediations(vulns, context)

    bm = BackupManager()
    recent_fixes = bm.list_backups()[:10]

    return render_template(
        "remediation.html",
        remediations=remediations,
        recent_fixes=recent_fixes,
        scan=scan,
    )


@routes_bp.route("/actions")
@login_required
def actions():
    return render_template("actions.html")


@routes_bp.route("/threats")
@login_required
def threats():
    try:
        from config import INCIDENTS_FILE
        incidents_path = INCIDENTS_FILE
    except ImportError:
        incidents_path = Path(__file__).parent.parent.parent / "logs" / "incidents.json"

    incidents = []
    try:
        if Path(incidents_path).exists():
            with open(incidents_path) as f:
                incidents = json.load(f)
            incidents = sorted(incidents, key=lambda x: x.get("timestamp", ""), reverse=True)[:50]
    except Exception as e:
        logger.warning("Could not load incidents: %s", e)

    return render_template("threats.html", incidents=incidents)


@routes_bp.route("/reports")
@login_required
def reports():
    db = _get_db()
    try:
        scans = db.execute(
            """SELECT scan_id, scan_type, target, completed_at, status
               FROM scan_results WHERE status='completed'
               ORDER BY completed_at DESC LIMIT 20"""
        ).fetchall()
        scan_list = [dict(s) for s in scans]
    finally:
        db.close()

    # Load already-generated report files
    generated = []
    try:
        from modules.module7_reports.report_generator import ReportGenerator
        generated = ReportGenerator().list_reports()
    except Exception:
        pass

    return render_template("reports.html", scans=scan_list, generated=generated)


@routes_bp.route("/reports/download/<path:filename>")
@login_required
def report_download(filename: str):
    """Serve a generated report file for download."""
    try:
        from config import BASE_DIR
    except ImportError:
        BASE_DIR = Path(__file__).parent.parent.parent

    reports_dir = Path(BASE_DIR) / "data" / "reports"

    # Resolve safely — reject any path traversal attempts
    safe_path = (reports_dir / filename).resolve()
    if not str(safe_path).startswith(str(reports_dir.resolve())):
        abort(403)

    if not safe_path.exists():
        abort(404)

    mime = "application/pdf" if safe_path.suffix == ".pdf" else "text/html"
    return send_file(safe_path, mimetype=mime, as_attachment=True, download_name=safe_path.name)


@routes_bp.route("/audit")
@login_required
def audit_log():
    db = _get_db()
    try:
        rows = db.execute(
            """SELECT al.*, u.username as u_name
               FROM audit_log al
               LEFT JOIN users u ON al.user_id = u.id
               ORDER BY al.timestamp DESC LIMIT 200"""
        ).fetchall()
        entries = [dict(r) for r in rows]
    finally:
        db.close()

    return render_template("audit.html", entries=entries)


@routes_bp.route("/settings")
@login_required
def settings():
    db = _get_db()
    try:
        user = db.execute(
            "SELECT id, username, totp_enabled, created_at, last_login FROM users WHERE id=?",
            (g.user["id"],)
        ).fetchone()
        user_data = dict(user) if user else {}
    finally:
        db.close()

    env = _read_env_file()

    def _rk(k): return _real_key(env.get(k, ""))  # use placeholder-aware check

    integ = {
        "llm_provider":          env.get("LLM_PROVIDER", "openai"),
        "openai_key_masked":     _mask(env.get("OPENAI_API_KEY", "")),
        "openai_key_set":        _rk("OPENAI_API_KEY"),
        "openrouter_key_masked": _mask(env.get("OPENROUTER_API_KEY", "")),
        "openrouter_key_set":    _rk("OPENROUTER_API_KEY"),
        "openrouter_model":      env.get("OPENROUTER_MODEL", "openai/gpt-4o-mini"),
        "gemini_key_masked":     _mask(env.get("GEMINI_API_KEY", "")),
        "gemini_key_set":        _rk("GEMINI_API_KEY"),
        "gemini_model":          env.get("GEMINI_MODEL", "gemini-1.5-flash"),
        "use_local_llm":         env.get("USE_LOCAL_LLM", "false").lower() == "true",
        "local_llm_url":         env.get("LOCAL_LLM_URL", "http://localhost:11434/api/generate"),
        "local_llm_model":       env.get("LOCAL_LLM_MODEL", "llama3"),
        "nvd_key_masked":        _mask(env.get("NVD_API_KEY", "")),
        "nvd_key_set":           _rk("NVD_API_KEY"),
        "telegram_token_masked": _mask(env.get("TELEGRAM_BOT_TOKEN", "")),
        "telegram_token_set":    _rk("TELEGRAM_BOT_TOKEN"),
        "telegram_chat_id":      env.get("TELEGRAM_CHAT_ID", ""),
        "telegram_enabled":      _rk("TELEGRAM_BOT_TOKEN") and bool(env.get("TELEGRAM_CHAT_ID", "").strip()),
        "smtp_host":             env.get("SMTP_HOST", "smtp.gmail.com"),
        "smtp_port":             env.get("SMTP_PORT", "587"),
        "alert_email":           env.get("ALERT_EMAIL", ""),
        "smtp_password_masked":  _mask(env.get("SMTP_PASSWORD", "")),
        "smtp_password_set":     _rk("SMTP_PASSWORD"),
        "email_enabled":         bool(env.get("ALERT_EMAIL", "").strip()) and _rk("SMTP_PASSWORD"),
    }
    return render_template("settings.html", user=user_data, integ=integ)


@routes_bp.route("/settings/integrations", methods=["POST"])
@login_required
def settings_integrations():
    """Save integration settings to .env and apply immediately."""
    from modules.module5_web.auth import _validate_csrf
    if not _validate_csrf(request.form.get("csrf_token", "")):
        abort(403)

    # Which section was submitted?
    section = request.form.get("section", "")

    def _save(key: str, form_key: str = None, *, keep_if_empty=True):
        """Write key to .env; skip if empty and keep_if_empty=True."""
        val = request.form.get(form_key or key, "").strip()
        if not val and keep_if_empty:
            return  # don't overwrite existing value with blank
        _write_env_key(key, val)
        _apply_env(key, val)

    if section == "llm":
        _save("LLM_PROVIDER",       keep_if_empty=False)
        _save("OPENAI_API_KEY",     keep_if_empty=True)
        _save("OPENROUTER_API_KEY", keep_if_empty=True)
        _save("OPENROUTER_MODEL",   keep_if_empty=False)
        _save("GEMINI_API_KEY",     keep_if_empty=True)
        _save("GEMINI_MODEL",       keep_if_empty=False)
        _save("USE_LOCAL_LLM",      keep_if_empty=False)
        _save("LOCAL_LLM_URL",      keep_if_empty=False)
        _save("LOCAL_LLM_MODEL",    keep_if_empty=False)
        _save("NVD_API_KEY",        keep_if_empty=True)
        flash("LLM & API keys updated.", "success")

    elif section == "telegram":
        _save("TELEGRAM_BOT_TOKEN", keep_if_empty=True)
        _save("TELEGRAM_CHAT_ID",   keep_if_empty=False)
        flash("Telegram settings updated.", "success")

    elif section == "email":
        _save("SMTP_HOST",     keep_if_empty=False)
        _save("SMTP_PORT",     keep_if_empty=False)
        _save("ALERT_EMAIL",   keep_if_empty=False)
        _save("SMTP_PASSWORD", keep_if_empty=True)
        flash("Email alert settings updated.", "success")

    audit("INTEGRATIONS_UPDATED", section)
    return redirect(url_for("routes.settings") + "#integrations")


@routes_bp.route("/settings/integrations/remove-key", methods=["POST"])
@login_required
def settings_remove_key():
    """Erase a single API key from .env and apply the change immediately."""
    from modules.module5_web.auth import _validate_csrf
    if not _validate_csrf(request.form.get("csrf_token", "")):
        abort(403)

    allowed = {
        "OPENAI_API_KEY", "OPENROUTER_API_KEY", "GEMINI_API_KEY",
        "NVD_API_KEY", "TELEGRAM_BOT_TOKEN", "SMTP_PASSWORD",
    }
    key = request.form.get("key_name", "").strip()
    if key not in allowed:
        flash("Unknown key name.", "danger")
        return redirect(url_for("routes.settings") + "#integrations")

    _write_env_key(key, "")
    _apply_env(key, "")
    audit("KEY_REMOVED", key)
    flash(f"{key} removed successfully.", "success")
    return redirect(url_for("routes.settings") + "#integrations")
