"""
api.py — REST API Blueprint  (Module 5)

JSON endpoints consumed by the frontend JavaScript.
All endpoints require login (session cookie).

Endpoints:
  POST /api/scan/start                — start a background scan
  GET  /api/scan/status/<scan_id>     — poll scan progress
  GET  /api/dashboard/stats           — live dashboard numbers
  POST /api/autofix                   — execute auto-fix command
  POST /api/autofix/rollback          — rollback a fix
  GET  /api/profile                   — get active SME profile
  GET  /api/threats/recent            — recent live-guard incidents
  POST /api/reports/generate          — trigger PDF/HTML report
  POST /api/integrations/test         — test Telegram or Email alert connection
  GET  /api/system/resources          — live CPU / RAM / disk usage
"""

import json
import logging
import sys
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path

from flask import Blueprint, jsonify, request, session, g

logger = logging.getLogger(__name__)

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from modules.module5_web.auth import login_required, _get_db, audit, _validate_csrf

api_bp = Blueprint("api", __name__)

# Active background scan threads: scan_id → thread
_scan_threads: dict[str, threading.Thread] = {}


@api_bp.route("/engines/toggle", methods=["POST"])
@login_required
def engines_toggle():
    """Enable or disable a scoring engine (rule/ml/llm)."""
    data = request.get_json(silent=True) or {}
    if not _validate_csrf(data.get("csrf_token", "")):
        return jsonify({"error": "Invalid CSRF token"}), 403

    engine  = data.get("engine", "").lower()   # "rule" | "ml" | "llm"
    enabled = bool(data.get("enabled", True))

    key_map = {
        "rule": "ENGINE_RULE_ENABLED",
        "ml":   "ENGINE_ML_ENABLED",
        "llm":  "ENGINE_LLM_ENABLED",
    }
    if engine not in key_map:
        return jsonify({"error": "Unknown engine. Use rule, ml, or llm."}), 400

    env_key = key_map[engine]
    val = "true" if enabled else "false"

    from modules.module5_web.routes import _write_env_key, _apply_env
    _write_env_key(env_key, val)
    _apply_env(env_key, val)

    audit("ENGINE_TOGGLE", f"{engine}={val}")
    logger.info("Engine toggle: %s → %s", engine, val)
    return jsonify({"ok": True, "engine": engine, "enabled": enabled})


@api_bp.route("/debug/llm-status", methods=["GET"])
@login_required
def debug_llm_status():
    """Temporary debug endpoint — shows raw env values and _real_key results."""
    from modules.module5_web.routes import _read_env_file, _real_key, _ENV_FILE
    env = _read_env_file()
    placeholders = ("your-", "sk-your", "AIza-your", "sk-or-your", "change-this", "your_", "example", "")
    def rk(v): return bool(v.strip()) and not any(v.strip().startswith(p) or v.strip() == p for p in placeholders)
    keys = ["OPENAI_API_KEY", "OPENROUTER_API_KEY", "GEMINI_API_KEY", "LLM_PROVIDER", "USE_LOCAL_LLM"]
    result = {
        "env_file_path": str(_ENV_FILE),
        "env_file_exists": _ENV_FILE.exists(),
        "keys": {}
    }
    for k in keys:
        raw = env.get(k, "__NOT_FOUND__")
        result["keys"][k] = {
            "raw_value": raw[:30] + "..." if len(raw) > 30 else raw,
            "real_key": rk(raw) if k not in ("LLM_PROVIDER", "USE_LOCAL_LLM") else "n/a",
        }
    return jsonify(result)


# ══════════════════════════════════════════════════════════════════
#   SCAN
# ══════════════════════════════════════════════════════════════════

@api_bp.route("/scan/start", methods=["POST"])
@login_required
def scan_start():
    """Start a quick or deep scan in a background thread."""
    data = request.get_json(silent=True) or {}

    if not _validate_csrf(data.get("csrf_token", "")):
        return jsonify({"error": "Invalid CSRF token"}), 403

    scan_type = data.get("scan_type", "quick")   # "quick" | "deep"
    target    = data.get("target", "127.0.0.1")

    scan_id = "scan_" + uuid.uuid4().hex[:12]

    db = _get_db()
    try:
        db.execute(
            """INSERT INTO scan_results (scan_id, scan_type, target, status, triggered_by)
               VALUES (?, ?, ?, 'running', ?)""",
            (scan_id, scan_type, target, session.get("user_id")),
        )
        db.commit()
    finally:
        db.close()

    audit("SCAN_STARTED", f"type={scan_type} target={target}")

    t = threading.Thread(
        target=_run_scan_background,
        args=(scan_id, scan_type, target),
        daemon=True,
    )
    _scan_threads[scan_id] = t
    t.start()

    return jsonify({"scan_id": scan_id, "status": "running"})


def _run_scan_background(scan_id: str, scan_type: str, target: str):
    """Execute the scan in a background thread and save result to DB."""
    try:
        from modules.module1_collection.scanner import Scanner
        from modules.module3_scoring.hybrid_engine import HybridEngine
        from modules.module2_context.context_manager import ContextManager

        scanner = Scanner(target=target, enrich_nvd=False)
        if scan_type == "deep":
            raw = scanner.run_deep_scan()
        else:
            raw = scanner.run_quick_scan()

        # Score all vulnerabilities (use empty context if no SME profile saved yet)
        cm = ContextManager()
        context = cm.get_active_profile() or {}
        engine = HybridEngine()
        scored_vulns = engine.score_all(raw.get("vulnerabilities", []), context)
        raw["vulnerabilities"] = scored_vulns

        db = _get_db()
        try:
            db.execute(
                """UPDATE scan_results
                   SET status='completed', completed_at=?, result_json=?
                   WHERE scan_id=?""",
                (datetime.now(timezone.utc).isoformat(), json.dumps(raw), scan_id),
            )
            db.commit()
        finally:
            db.close()
        logger.info("Scan %s completed: %d vulns", scan_id, len(scored_vulns))

    except Exception as exc:
        logger.error("Scan %s failed: %s", scan_id, exc, exc_info=True)
        db = _get_db()
        try:
            db.execute(
                "UPDATE scan_results SET status='failed', completed_at=? WHERE scan_id=?",
                (datetime.now(timezone.utc).isoformat(), scan_id),
            )
            db.commit()
        finally:
            db.close()
    finally:
        _scan_threads.pop(scan_id, None)


@api_bp.route("/scan/status/<scan_id>", methods=["GET"])
@login_required
def scan_status(scan_id: str):
    db = _get_db()
    try:
        row = db.execute(
            "SELECT scan_id, status, started_at, completed_at, scan_type FROM scan_results WHERE scan_id=?",
            (scan_id,),
        ).fetchone()
    finally:
        db.close()

    if not row:
        return jsonify({"error": "Scan not found"}), 404

    return jsonify(dict(row))


# ══════════════════════════════════════════════════════════════════
#   SYSTEM RESOURCES
# ══════════════════════════════════════════════════════════════════

@api_bp.route("/system/resources", methods=["GET"])
@login_required
def system_resources():
    """Return live CPU %, RAM %, disk %, and core count via psutil."""
    try:
        import psutil
        cpu_pct  = psutil.cpu_percent(interval=0.3)
        cpu_cores = psutil.cpu_count(logical=False) or psutil.cpu_count()
        cpu_freq  = psutil.cpu_freq()
        ram       = psutil.virtual_memory()
        disk      = psutil.disk_usage("/")
        return jsonify({
            "cpu_pct":    round(cpu_pct, 1),
            "cpu_cores":  cpu_cores,
            "cpu_freq_mhz": round(cpu_freq.current, 0) if cpu_freq else 0,
            "ram_pct":    round(ram.percent, 1),
            "ram_used_gb": round(ram.used  / 1024**3, 2),
            "ram_total_gb":round(ram.total / 1024**3, 2),
            "disk_pct":   round(disk.percent, 1),
            "disk_used_gb": round(disk.used  / 1024**3, 2),
            "disk_total_gb":round(disk.total / 1024**3, 2),
            "available": True,
        })
    except ImportError:
        return jsonify({"available": False, "error": "psutil not installed"})
    except Exception as exc:
        logger.warning("system_resources error: %s", exc)
        return jsonify({"available": False, "error": str(exc)})


# ══════════════════════════════════════════════════════════════════
#   DASHBOARD STATS
# ══════════════════════════════════════════════════════════════════

@api_bp.route("/dashboard/stats", methods=["GET"])
@login_required
def dashboard_stats():
    db = _get_db()
    try:
        row = db.execute(
            """SELECT result_json, completed_at FROM scan_results
               WHERE status='completed' ORDER BY completed_at DESC LIMIT 1"""
        ).fetchone()
    finally:
        db.close()

    if not row or not row["result_json"]:
        return jsonify({"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0})

    data = json.loads(row["result_json"])
    # Recount from actual scored vulnerabilities so counts match the list
    vulns = data.get("vulnerabilities", [])
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for v in vulns:
        p = (v.get("priority") or "low").lower()
        if p in counts:
            counts[p] += 1
    counts["total"] = len(vulns)
    return jsonify({
        **counts,
        "lynis_score": data.get("lynis_score", 0),
        "scan_time":   row["completed_at"],
        "hostname":    data.get("server_info", {}).get("hostname", ""),
    })


# ══════════════════════════════════════════════════════════════════
#   AUTO-FIX
# ══════════════════════════════════════════════════════════════════

@api_bp.route("/autofix", methods=["POST"])
@login_required
def autofix():
    data = request.get_json(silent=True) or {}

    if not _validate_csrf(data.get("csrf_token", "")):
        return jsonify({"error": "Invalid CSRF token"}), 403

    vuln = data.get("vuln")
    confirmed = data.get("confirmed", False)

    if not vuln or not vuln.get("type"):
        return jsonify({"error": "Missing vuln.type"}), 400

    try:
        from modules.module4_remediation.autofix_agent import AutoFixAgent
        agent = AutoFixAgent()
        result = agent.execute_fix(vuln, confirmed=confirmed)
        if result.get("success"):
            audit("AUTOFIX_APPLIED",
                  f"type={vuln.get('type')} backup={result.get('backup_id')}")
        else:
            audit("AUTOFIX_FAILED",
                  f"type={vuln.get('type')} error={(result.get('error') or '')[:100]}",
                  success=False)
        return jsonify(result)
    except Exception as exc:
        logger.error("autofix endpoint error: %s", exc, exc_info=True)
        return jsonify({"error": str(exc)}), 500


@api_bp.route("/autofix/rollback", methods=["POST"])
@login_required
def autofix_rollback():
    data = request.get_json(silent=True) or {}

    if not _validate_csrf(data.get("csrf_token", "")):
        return jsonify({"error": "Invalid CSRF token"}), 403

    backup_id = data.get("backup_id", "")
    if not backup_id:
        return jsonify({"error": "Missing backup_id"}), 400

    try:
        from modules.module4_remediation.autofix_agent import AutoFixAgent
        agent = AutoFixAgent()
        result = agent.rollback(backup_id)
        if result.get("success"):
            audit("AUTOFIX_ROLLBACK", f"backup_id={backup_id}")
        return jsonify(result)
    except Exception as exc:
        logger.error("rollback endpoint error: %s", exc, exc_info=True)
        return jsonify({"error": str(exc)}), 500


@api_bp.route("/autofix/delete", methods=["POST"])
@login_required
def autofix_delete():
    data = request.get_json(silent=True) or {}

    if not _validate_csrf(data.get("csrf_token", "")):
        return jsonify({"error": "Invalid CSRF token"}), 403

    backup_id = data.get("backup_id", "")
    if not backup_id:
        return jsonify({"error": "Missing backup_id"}), 400

    try:
        from modules.module4_remediation.backup_manager import BackupManager
        bm = BackupManager()
        result = bm.delete(backup_id)
        if result.get("success"):
            audit("AUTOFIX_DELETE", f"backup_id={backup_id}")
        return jsonify(result)
    except Exception as exc:
        logger.error("delete backup endpoint error: %s", exc, exc_info=True)
        return jsonify({"error": str(exc)}), 500


@api_bp.route("/autofix/history", methods=["GET"])
@login_required
def autofix_history():
    try:
        from modules.module4_remediation.autofix_agent import AutoFixAgent
        agent = AutoFixAgent()
        return jsonify(agent.list_recent_fixes())
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500




# ══════════════════════════════════════════════════════════════════
#   PROFILE
# ══════════════════════════════════════════════════════════════════

@api_bp.route("/profile", methods=["GET"])
@login_required
def get_profile():
    try:
        from modules.module2_context.context_manager import ContextManager
        cm = ContextManager()
        profile = cm.get_active_profile()
        return jsonify(profile or {})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


# ══════════════════════════════════════════════════════════════════
#   THREATS / LIVE GUARD
# ══════════════════════════════════════════════════════════════════

def _get_live_guard():
    """Return the LiveGuard instance stored on the Flask app config, or None."""
    from flask import current_app
    return current_app.config.get("LIVE_GUARD")


@api_bp.route("/threats/recent", methods=["GET"])
@login_required
def threats_recent():
    # Try Live Guard first (running instance)
    guard = _get_live_guard()
    if guard:
        try:
            return jsonify(guard.get_incidents(20))
        except Exception as exc:
            logger.warning("live_guard.get_incidents error: %s", exc)

    # Fallback: read incidents.json directly
    try:
        from config import INCIDENTS_FILE
        incidents_path = INCIDENTS_FILE
    except ImportError:
        incidents_path = Path(__file__).parent.parent.parent / "logs" / "incidents.json"

    try:
        if Path(incidents_path).exists():
            with open(incidents_path) as f:
                incidents = json.load(f)
            return jsonify(sorted(
                incidents,
                key=lambda x: x.get("timestamp", ""),
                reverse=True
            )[:20])
    except Exception as exc:
        logger.warning("threats_recent fallback error: %s", exc)

    return jsonify([])


@api_bp.route("/threats/status", methods=["GET"])
@login_required
def threats_status():
    """Return full Live Guard status (monitors, blocked IPs, scheduler jobs)."""
    guard = _get_live_guard()
    if guard:
        try:
            return jsonify(guard.get_status())
        except Exception as exc:
            return jsonify({"error": str(exc)}), 500
    return jsonify({"running": False, "message": "Live Guard not started."})


@api_bp.route("/threats/unblock", methods=["POST"])
@login_required
def threats_unblock():
    """Manually unblock an IP."""
    data = request.get_json(silent=True) or {}
    if not _validate_csrf(data.get("csrf_token", "")):
        return jsonify({"error": "Invalid CSRF token"}), 403

    ip = data.get("ip", "").strip()
    if not ip:
        return jsonify({"error": "Missing ip"}), 400

    guard = _get_live_guard()
    if guard:
        result = guard.unblock_ip(ip)
        if result.get("success"):
            audit("IP_UNBLOCKED", f"ip={ip}")
        return jsonify(result)

    # Fallback: use IPBlocker directly
    try:
        from modules.module6_liveguard.ip_blocker import IPBlocker
        result = IPBlocker().unblock_ip(ip)
        if result.get("success"):
            audit("IP_UNBLOCKED", f"ip={ip}")
        return jsonify(result)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@api_bp.route("/threats/incidents/clear-one", methods=["POST"])
@login_required
def threats_clear_one():
    """Remove a single incident by index from incidents.json."""
    data = request.get_json(silent=True) or {}
    if not _validate_csrf(data.get("csrf_token", "")):
        return jsonify({"error": "Invalid CSRF token"}), 403
    idx = data.get("index")
    if idx is None:
        return jsonify({"error": "Missing index"}), 400
    try:
        incidents_path = Path(
            getattr(__import__("config"), "LOGS_DIR", "logs")
        ) / "incidents.json"
        if not incidents_path.exists():
            return jsonify({"ok": True})
        with open(incidents_path) as f:
            incidents = json.load(f)
        if not isinstance(incidents, list) or idx < 0 or idx >= len(incidents):
            return jsonify({"error": "Invalid index"}), 400
        incidents.pop(idx)
        with open(incidents_path, "w") as f:
            json.dump(incidents, f, indent=2)
        audit("INCIDENT_CLEARED", f"index={idx}")
        return jsonify({"ok": True})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@api_bp.route("/threats/incidents/clear-all", methods=["POST"])
@login_required
def threats_clear_all():
    """Wipe all incidents from incidents.json."""
    data = request.get_json(silent=True) or {}
    if not _validate_csrf(data.get("csrf_token", "")):
        return jsonify({"error": "Invalid CSRF token"}), 403
    try:
        incidents_path = Path(
            getattr(__import__("config"), "LOGS_DIR", "logs")
        ) / "incidents.json"
        with open(incidents_path, "w") as f:
            json.dump([], f)
        audit("INCIDENTS_CLEARED_ALL")
        return jsonify({"ok": True})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


# ══════════════════════════════════════════════════════════════════
#   REPORTS
# ══════════════════════════════════════════════════════════════════

@api_bp.route("/reports/generate", methods=["POST"])
@login_required
def generate_report():
    """
    Trigger report generation (Module 7 — stub for now).
    Returns the file path or a not-available message.
    """
    data = request.get_json(silent=True) or {}

    if not _validate_csrf(data.get("csrf_token", "")):
        return jsonify({"error": "Invalid CSRF token"}), 403

    scan_id   = data.get("scan_id", "latest")
    fmt       = data.get("format", "pdf")   # "pdf" | "html"

    try:
        from modules.module7_reports.report_generator import ReportGenerator
        rg = ReportGenerator()
        scan_data = _get_scan_data(scan_id)
        if not scan_data:
            return jsonify({"error": "Scan data not found"}), 404
        path = rg.generate(scan_data, format=fmt)
        audit("REPORT_GENERATED", f"scan={scan_id} format={fmt}")
        return jsonify({"success": True, "file": str(path)})
    except ImportError:
        return jsonify({
            "success": False,
            "message": "Report generator (Module 7) not yet available.",
        }), 200
    except Exception as exc:
        logger.error("report generation error: %s", exc, exc_info=True)
        return jsonify({"error": str(exc)}), 500


def _get_scan_data(scan_id: str) -> dict | None:
    db = _get_db()
    try:
        if scan_id == "latest":
            row = db.execute(
                "SELECT result_json FROM scan_results WHERE status='completed' ORDER BY completed_at DESC LIMIT 1"
            ).fetchone()
        else:
            row = db.execute(
                "SELECT result_json FROM scan_results WHERE scan_id=?", (scan_id,)
            ).fetchone()
        if row and row["result_json"]:
            return json.loads(row["result_json"])
        return None
    finally:
        db.close()


# ══════════════════════════════════════════════════════════════════
#   INTEGRATIONS TEST
# ══════════════════════════════════════════════════════════════════

@api_bp.route("/integrations/test-llm", methods=["POST"])
@login_required
def integrations_test_llm():
    """Test an LLM API key by making a minimal real API call."""
    data = request.get_json(silent=True) or {}
    if not _validate_csrf(data.get("csrf_token", "")):
        return jsonify({"error": "Invalid CSRF token"}), 403

    provider = data.get("provider", "").strip()   # "openai" | "openrouter" | "gemini"

    try:
        import os

        if provider == "openai":
            key = os.environ.get("OPENAI_API_KEY", "")
            if not key or key.startswith("sk-your"):
                return jsonify({"ok": False, "message": "No OpenAI API key configured."})
            if key.startswith("sk-or-"):
                return jsonify({"ok": False, "message": "This looks like an OpenRouter key (sk-or-). Save it in the OpenRouter field instead."})
            from openai import OpenAI
            client = OpenAI(api_key=key)
            client.models.list()
            audit("TEST_LLM_KEY", "openai")
            return jsonify({"ok": True, "message": "OpenAI key is valid and active."})

        elif provider == "openrouter":
            key = os.environ.get("OPENROUTER_API_KEY", "")
            if not key or key.startswith("sk-or-your"):
                return jsonify({"ok": False, "message": "No OpenRouter API key configured."})
            from openai import OpenAI
            client = OpenAI(api_key=key, base_url="https://openrouter.ai/api/v1")
            client.models.list()
            audit("TEST_LLM_KEY", "openrouter")
            return jsonify({"ok": True, "message": "OpenRouter key is valid and active."})

        elif provider == "gemini":
            key = os.environ.get("GEMINI_API_KEY", "")
            if not key:
                return jsonify({"ok": False, "message": "No Gemini API key configured."})
            try:
                import google.generativeai as genai
            except ImportError:
                return jsonify({"ok": False, "message": "Package not installed. Run: pip install google-generativeai"})
            genai.configure(api_key=key)
            models = list(genai.list_models())
            if not models:
                return jsonify({"ok": False, "message": "Key accepted but no models returned."})
            audit("TEST_LLM_KEY", "gemini")
            return jsonify({"ok": True, "message": f"Gemini key is valid. {len(models)} model(s) available."})

        else:
            return jsonify({"error": "Unknown provider. Use openai, openrouter, or gemini."}), 400

    except Exception as exc:
        msg = str(exc)
        # Trim verbose OpenAI error messages to essentials
        if "AuthenticationError" in type(exc).__name__ or "401" in msg:
            msg = "Invalid API key — authentication failed."
        elif "RateLimitError" in type(exc).__name__:
            msg = "Rate limit hit, but key is valid."
            return jsonify({"ok": True, "message": msg})
        logger.warning("test-llm %s error: %s", provider, exc)
        return jsonify({"ok": False, "message": msg})


@api_bp.route("/integrations/test", methods=["POST"])
@login_required
def integrations_test():
    """Test Telegram or Email alert connectivity."""
    data = request.get_json(silent=True) or {}
    if not _validate_csrf(data.get("csrf_token", "")):
        return jsonify({"error": "Invalid CSRF token"}), 403

    channel = data.get("channel", "")   # "telegram" | "email"

    try:
        from modules.module6_liveguard.alert_system import AlertSystem
        alert = AlertSystem()

        if channel == "telegram":
            ok, msg = alert.send_test_telegram()
            audit("TEST_ALERT", "telegram")
            return jsonify({"ok": ok, "message": msg})

        elif channel == "email":
            ok, msg = alert.send_test_email()
            audit("TEST_ALERT", "email")
            return jsonify({"ok": ok, "message": msg})

        else:
            return jsonify({"error": "Unknown channel. Use 'telegram' or 'email'."}), 400

    except Exception as exc:
        logger.error("integrations_test error: %s", exc)
        return jsonify({"ok": False, "message": str(exc)}), 500


# ══════════════════════════════════════════════════════════════════
#   DELETE — Scans / Reports / Audit Log
# ══════════════════════════════════════════════════════════════════

def _reports_dir() -> Path:
    try:
        from config import BASE_DIR
    except ImportError:
        BASE_DIR = Path(__file__).parent.parent.parent
    return Path(BASE_DIR) / "data" / "reports"


@api_bp.route("/scans/delete", methods=["POST"])
@login_required
def scan_delete():
    """Delete a single scan record (not running scans)."""
    data = request.get_json(silent=True) or {}
    if not _validate_csrf(data.get("csrf_token", "")):
        return jsonify({"error": "Invalid CSRF token"}), 403

    scan_id = data.get("scan_id", "").strip()
    if not scan_id:
        return jsonify({"error": "Missing scan_id"}), 400

    db = _get_db()
    try:
        row = db.execute("SELECT status FROM scan_results WHERE scan_id=?", (scan_id,)).fetchone()
        if not row:
            return jsonify({"error": "Scan not found"}), 404
        if row["status"] == "running":
            return jsonify({"error": "Cannot delete a running scan"}), 400
        db.execute("DELETE FROM scan_results WHERE scan_id=?", (scan_id,))
        db.commit()
    finally:
        db.close()

    audit("SCAN_DELETED", f"scan_id={scan_id}")
    return jsonify({"ok": True, "deleted": scan_id})


@api_bp.route("/scans/delete-all", methods=["POST"])
@login_required
def scan_delete_all():
    """Delete all completed/failed scan records (keeps running scans)."""
    data = request.get_json(silent=True) or {}
    if not _validate_csrf(data.get("csrf_token", "")):
        return jsonify({"error": "Invalid CSRF token"}), 403

    db = _get_db()
    try:
        cur = db.execute("DELETE FROM scan_results WHERE status != 'running'")
        deleted = cur.rowcount
        db.commit()
    finally:
        db.close()

    audit("SCAN_DELETE_ALL", f"deleted={deleted}")
    return jsonify({"ok": True, "deleted": deleted})


@api_bp.route("/reports/delete", methods=["POST"])
@login_required
def report_delete():
    """Delete a single generated report file."""
    data = request.get_json(silent=True) or {}
    if not _validate_csrf(data.get("csrf_token", "")):
        return jsonify({"error": "Invalid CSRF token"}), 403

    filename = data.get("filename", "").strip()
    if not filename or "/" in filename or "\\" in filename or ".." in filename:
        return jsonify({"error": "Invalid filename"}), 400

    rdir = _reports_dir()
    target = (rdir / filename).resolve()
    if not str(target).startswith(str(rdir.resolve())):
        return jsonify({"error": "Path traversal rejected"}), 403

    if not target.exists():
        return jsonify({"error": "File not found"}), 404

    target.unlink()
    audit("REPORT_DELETED", f"file={filename}")
    return jsonify({"ok": True, "deleted": filename})


@api_bp.route("/reports/delete-all", methods=["POST"])
@login_required
def report_delete_all():
    """Delete all generated report files."""
    data = request.get_json(silent=True) or {}
    if not _validate_csrf(data.get("csrf_token", "")):
        return jsonify({"error": "Invalid CSRF token"}), 403

    rdir = _reports_dir()
    deleted = 0
    if rdir.exists():
        for f in rdir.iterdir():
            if f.is_file() and f.suffix in (".pdf", ".html"):
                f.unlink()
                deleted += 1

    audit("REPORT_DELETE_ALL", f"deleted={deleted}")
    return jsonify({"ok": True, "deleted": deleted})


@api_bp.route("/audit/clear", methods=["POST"])
@login_required
def audit_clear():
    """Clear all audit log entries."""
    data = request.get_json(silent=True) or {}
    if not _validate_csrf(data.get("csrf_token", "")):
        return jsonify({"error": "Invalid CSRF token"}), 403

    db = _get_db()
    try:
        cur = db.execute("DELETE FROM audit_log")
        deleted = cur.rowcount
        db.commit()
    finally:
        db.close()

    # Re-add one entry so we know it was cleared
    audit("AUDIT_CLEARED", f"cleared {deleted} entries")
    return jsonify({"ok": True, "deleted": deleted})


# ══════════════════════════════════════════════════════════════════
#   ACTIONS — Firewall (UFW) & SSH Management
# ══════════════════════════════════════════════════════════════════

import re as _re
import subprocess as _sp
import shutil as _shutil
import tempfile as _tempfile

_SSHD_CONFIG = "/etc/ssh/sshd_config"


def _run(cmd: str, timeout: int = 15) -> tuple[str, str, int]:
    """Run a shell command, return (stdout, stderr, returncode)."""
    try:
        r = _sp.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except _sp.TimeoutExpired:
        return "", "Command timed out", 1
    except Exception as e:
        return "", str(e), 1


def _parse_sshd_config() -> dict:
    """Return effective key→value pairs from /etc/ssh/sshd_config (skip comments/blanks)."""
    cfg = {}
    try:
        for line in Path(_SSHD_CONFIG).read_text(errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            if len(parts) == 2:
                cfg[parts[0].lower()] = parts[1].strip()
    except Exception:
        pass
    return cfg


# ── Firewall ──────────────────────────────────────────────────────

@api_bp.route("/actions/firewall", methods=["GET"])
@login_required
def actions_firewall_status():
    stdout, _, _ = _run("sudo -n ufw status verbose 2>&1")
    if not stdout:
        stdout, _, _ = _run("ufw status verbose 2>&1")

    enabled = "Status: active" in stdout

    ports = []
    in_rules = False
    for line in stdout.splitlines():
        if line.startswith("To ") or line.startswith("--"):
            in_rules = True
            continue
        if in_rules and line.strip() and "(v6)" not in line:
            parts = line.split()
            if len(parts) >= 2:
                ports.append({"port_proto": parts[0], "action": parts[1]})

    return jsonify({"ok": True, "enabled": enabled, "ports": ports})


@api_bp.route("/actions/firewall/toggle", methods=["POST"])
@login_required
def actions_firewall_toggle():
    data = request.get_json(silent=True) or {}
    if not _validate_csrf(data.get("csrf_token", "")):
        return jsonify({"error": "Invalid CSRF token"}), 403

    enable = bool(data.get("enable", True))
    cmd = "echo y | sudo -n ufw enable 2>&1" if enable else "sudo -n ufw disable 2>&1"
    stdout, stderr, rc = _run(cmd, timeout=20)
    ok = rc == 0 or (enable and "active" in stdout.lower())
    audit("FIREWALL_TOGGLE", f"enable={enable} ok={ok}")
    return jsonify({"ok": ok, "error": stderr if not ok else None})


@api_bp.route("/actions/firewall/port", methods=["POST"])
@login_required
def actions_firewall_port():
    data = request.get_json(silent=True) or {}
    if not _validate_csrf(data.get("csrf_token", "")):
        return jsonify({"error": "Invalid CSRF token"}), 403

    port  = str(data.get("port", "")).strip()
    proto = data.get("proto", "tcp").strip().lower()
    action = data.get("action", "allow").strip().lower()

    if not port.isdigit() or not (1 <= int(port) <= 65535):
        return jsonify({"error": "Invalid port number (1–65535)"}), 400
    if proto not in ("tcp", "udp"):
        return jsonify({"error": "Protocol must be tcp or udp"}), 400
    if action not in ("allow", "deny", "delete"):
        return jsonify({"error": "Action must be allow, deny, or delete"}), 400

    if action == "delete":
        cmd = f"sudo -n ufw delete allow {port}/{proto} 2>&1"
    else:
        cmd = f"sudo -n ufw {action} {port}/{proto} 2>&1"

    _, stderr, rc = _run(cmd)
    ok = rc == 0
    audit("FIREWALL_PORT", f"action={action} port={port}/{proto} ok={ok}")
    return jsonify({"ok": ok, "error": stderr if not ok else None})


# ── SSH Status ────────────────────────────────────────────────────

@api_bp.route("/actions/ssh", methods=["GET"])
@login_required
def actions_ssh_status():
    cfg = _parse_sshd_config()

    # Also check sshd -T for runtime effective values
    stdout, _, rc = _run("sudo -n sshd -T 2>/dev/null")
    effective = {}
    if rc == 0:
        for line in stdout.splitlines():
            parts = line.split(None, 1)
            if len(parts) == 2:
                effective[parts[0].lower()] = parts[1].strip()

    def val(key, default="unknown"):
        return effective.get(key) or cfg.get(key, default)

    return jsonify({
        "ok": True,
        "port":                  val("port", "22"),
        "permit_root_login":     val("permitrootlogin", "unknown"),
        "password_auth":         val("passwordauthentication", "unknown"),
        "pubkey_auth":           val("pubkeyauthentication", "unknown"),
        "x11_forwarding":        val("x11forwarding", "unknown"),
        "max_auth_tries":        val("maxauthtries", "6"),
        "permit_empty_passwords":val("permitemptypasswords", "unknown"),
        "login_grace_time":      val("logingracetime", "120"),
        "allow_users":           val("allowusers", ""),
        "sshd_config_readable":  Path(_SSHD_CONFIG).exists(),
    })


# ── SSH Configure ─────────────────────────────────────────────────

_SSH_ALLOWED_SETTINGS = {
    "PermitRootLogin":       ["yes", "no", "prohibit-password"],
    "PasswordAuthentication":["yes", "no"],
    "PubkeyAuthentication":  ["yes", "no"],
    "X11Forwarding":         ["yes", "no"],
    "PermitEmptyPasswords":  ["yes", "no"],
    "MaxAuthTries":          None,   # validated as integer
    "LoginGraceTime":        None,   # validated as integer/string
}


@api_bp.route("/actions/ssh/configure", methods=["POST"])
@login_required
def actions_ssh_configure():
    data = request.get_json(silent=True) or {}
    if not _validate_csrf(data.get("csrf_token", "")):
        return jsonify({"error": "Invalid CSRF token"}), 403

    setting = data.get("setting", "").strip()
    value   = data.get("value",   "").strip()

    if setting not in _SSH_ALLOWED_SETTINGS:
        return jsonify({"error": f"Setting '{setting}' not configurable here"}), 400

    allowed_vals = _SSH_ALLOWED_SETTINGS[setting]
    if allowed_vals and value not in allowed_vals:
        return jsonify({"error": f"Invalid value. Allowed: {allowed_vals}"}), 400
    if setting == "MaxAuthTries" and not value.isdigit():
        return jsonify({"error": "MaxAuthTries must be a number"}), 400
    if setting == "LoginGraceTime" and not _re.match(r'^\d+[smh]?$', value):
        return jsonify({"error": "LoginGraceTime must be a number (e.g. 60 or 2m)"}), 400

    # Safely replace or append the setting in sshd_config
    escaped_val = value.replace("/", r"\/")
    sed_cmd = (
        f"sudo -n sed -i "
        f"'s/^#*[[:space:]]*{setting}[[:space:]].*/{setting} {escaped_val}/' "
        f"{_SSHD_CONFIG}"
    )
    _, stderr, rc = _run(sed_cmd)
    if rc != 0:
        return jsonify({"ok": False, "error": f"sed failed: {stderr}"}), 500

    # If the line wasn't there at all, append it
    check, _, _ = _run(f"grep -qE '^{setting}[[:space:]]' {_SSHD_CONFIG}")
    # grep returns 1 if not found
    _, _, grep_rc = _run(f"grep -qE '^{setting}' {_SSHD_CONFIG}")
    if grep_rc != 0:
        _run(f"echo '{setting} {value}' | sudo -n tee -a {_SSHD_CONFIG}")

    # Validate config before reloading
    _, test_err, test_rc = _run("sudo -n sshd -t 2>&1")
    if test_rc != 0:
        return jsonify({"ok": False, "error": f"sshd config test failed: {test_err}"}), 500

    _run("sudo -n systemctl reload sshd 2>/dev/null || sudo -n systemctl reload ssh 2>/dev/null")
    audit("SSH_CONFIGURE", f"{setting}={value}")
    return jsonify({"ok": True, "message": f"{setting} set to {value} and SSH reloaded."})


# ── SSL Certificate Generation ───────────────────────────────────

@api_bp.route("/actions/ssl/self-signed", methods=["POST"])
@login_required
def actions_ssl_self_signed():
    """Generate a self-signed SSL cert and write paths to .env."""
    data = request.get_json(silent=True) or {}
    if not _validate_csrf(data.get("csrf_token", "")):
        return jsonify({"error": "Invalid CSRF token"}), 403

    ip = str(data.get("ip", "")).strip()
    if not ip:
        return jsonify({"error": "Missing IP or hostname"}), 400

    ssl_dir = Path("/opt/hybridsec/ssl")
    ssl_dir.mkdir(parents=True, exist_ok=True)
    cert = ssl_dir / "cert.pem"
    key  = ssl_dir / "key.pem"

    cmd = (
        f'openssl req -x509 -newkey rsa:4096 -keyout {key} -out {cert} '
        f'-days 365 -nodes -subj "/CN={ip}/O=HybridSec/C=LK" 2>&1'
    )
    stdout, stderr, rc = _run(cmd, timeout=60)
    if rc != 0:
        return jsonify({"error": f"openssl failed: {(stdout or stderr)[-300:]}"}), 500

    _ssl_write_env(str(cert), str(key))
    audit("SSL_SELF_SIGNED", f"ip={ip} cert={cert}")
    return jsonify({"ok": True, "cert": str(cert), "key": str(key)})


def _ssl_write_env(cert: str, key: str):
    """Update SSL_CERT and SSL_KEY in /opt/hybridsec/.env."""
    env_file = Path("/opt/hybridsec/.env")
    lines = env_file.read_text().splitlines() if env_file.exists() else []
    to_set = {"SSL_CERT": cert, "SSL_KEY": key}
    new_lines = []
    for line in lines:
        k = line.split("=", 1)[0].strip()
        if k in to_set:
            new_lines.append(f"{k}={to_set.pop(k)}")
        else:
            new_lines.append(line)
    for k, v in to_set.items():
        new_lines.append(f"{k}={v}")
    env_file.write_text("\n".join(new_lines) + "\n")


@api_bp.route("/actions/ssl/certbot", methods=["POST"])
@login_required
def actions_ssl_certbot():
    """Run certbot --standalone for a domain and apply the cert to .env."""
    data = request.get_json(silent=True) or {}
    if not _validate_csrf(data.get("csrf_token", "")):
        return jsonify({"error": "Invalid CSRF token"}), 403

    import re as _re2
    domain = str(data.get("domain", "")).strip().lower()
    email  = str(data.get("email", "")).strip()
    if not domain or not _re2.match(r'^[a-z0-9][a-z0-9\.\-]{2,253}$', domain):
        return jsonify({"error": "Invalid domain name"}), 400
    if not email:
        email = f"admin@{domain}"

    cmd = (
        f"certbot certonly --standalone --non-interactive --agree-tos "
        f"-m {email} -d {domain} 2>&1"
    )
    stdout, stderr, rc = _run(cmd, timeout=120)
    output = (stdout or stderr or "")[-1200:]

    if rc != 0:
        return jsonify({"ok": False, "error": "Certbot failed", "output": output})

    cert = f"/etc/letsencrypt/live/{domain}/fullchain.pem"
    key  = f"/etc/letsencrypt/live/{domain}/privkey.pem"
    try:
        _ssl_write_env(cert, key)
    except Exception as exc:
        return jsonify({"ok": False, "error": f"Cert issued but .env update failed: {exc}", "output": output})

    audit("SSL_CERTBOT", f"domain={domain}")
    return jsonify({"ok": True, "cert": cert, "key": key, "output": output})


# ── SSH Key Generation ────────────────────────────────────────────

# ── Software Installer ───────────────────────────────────────────

@api_bp.route("/actions/packages/status", methods=["POST"])
@login_required
def actions_packages_status():
    """Check which packages from a list are installed (dpkg -l)."""
    data = request.get_json(silent=True) or {}
    packages = data.get("packages", [])
    if not isinstance(packages, list):
        return jsonify({"error": "packages must be a list"}), 400

    statuses = {}
    for pkg in packages[:30]:  # cap to prevent abuse
        pkg = str(pkg).strip()
        if not pkg or not _re.match(r'^[a-z0-9][a-z0-9\.\-\+]{0,63}$', pkg):
            continue
        # CyberPanel uses a custom installer — check via which/directory
        if pkg == "cyberpanel":
            _, _, rc2 = _run("which cyberpanel 2>/dev/null || test -d /usr/local/CyberCP")
            statuses["cyberpanel"] = {"installed": rc2 == 0, "version": "CyberPanel" if rc2 == 0 else ""}
            continue
        stdout, _, rc = _run(f"dpkg -l {pkg} 2>/dev/null | grep -E '^ii\\s+{pkg}\\s'")
        version = ""
        if rc == 0 and stdout:
            parts = stdout.split()
            version = parts[2] if len(parts) > 2 else ""
        installed = rc == 0 and bool(stdout)
        entry = {"installed": installed, "version": version}
        # For certbot, also report whether SSL is already configured
        if pkg == "certbot" and installed:
            ssl_self  = Path("/opt/hybridsec/ssl/cert.pem").exists()
            le_dir    = Path("/etc/letsencrypt/live")
            ssl_le    = le_dir.exists() and any(True for _ in le_dir.iterdir())
            entry["ssl_active"] = ssl_self or ssl_le
        statuses[pkg] = entry

    return jsonify({"ok": True, "statuses": statuses})


@api_bp.route("/actions/packages/install", methods=["POST"])
@login_required
def actions_packages_install():
    """Install a single apt package. Runs synchronously — may take 1-3 min."""
    data = request.get_json(silent=True) or {}
    if not _validate_csrf(data.get("csrf_token", "")):
        return jsonify({"error": "Invalid CSRF token"}), 403

    pkg = str(data.get("package", "")).strip()
    if not pkg or not _re.match(r'^[a-z0-9][a-z0-9\.\-\+]{0,63}$', pkg):
        return jsonify({"error": "Invalid package name"}), 400

    # Run apt-get install non-interactively
    env_prefix = "DEBIAN_FRONTEND=noninteractive "
    cmd = f"{env_prefix}apt-get install -y {pkg} 2>&1"
    stdout, stderr, rc = _run(cmd, timeout=180)

    ok = rc == 0
    # Get version if installed
    version = ""
    if ok:
        ver_out, _, _ = _run(f"dpkg -l {pkg} 2>/dev/null | grep -E '^ii\\s+{pkg}\\s'")
        parts = ver_out.split()
        version = parts[2] if len(parts) > 2 else ""

    audit("PKG_INSTALL", f"package={pkg} ok={ok}")
    return jsonify({
        "ok":      ok,
        "package": pkg,
        "version": version,
        "output":  (stdout or stderr)[-800:],
        "error":   None if ok else f"apt-get exited with code {rc}",
    })


@api_bp.route("/actions/packages/uninstall", methods=["POST"])
@login_required
def actions_packages_uninstall():
    """Purge a single apt package."""
    data = request.get_json(silent=True) or {}
    if not _validate_csrf(data.get("csrf_token", "")):
        return jsonify({"error": "Invalid CSRF token"}), 403

    pkg = str(data.get("package", "")).strip()
    if not pkg or not _re.match(r'^[a-z0-9][a-z0-9\.\-\+]{0,63}$', pkg):
        return jsonify({"error": "Invalid package name"}), 400
    if pkg == "cyberpanel":
        return jsonify({"error": "Use the CyberPanel uninstall guide shown in the UI"}), 400

    env_prefix = "DEBIAN_FRONTEND=noninteractive "
    cmd = f"{env_prefix}apt-get purge -y {pkg} 2>&1"
    stdout, stderr, rc = _run(cmd, timeout=120)

    ok = rc == 0
    audit("PKG_UNINSTALL", f"package={pkg} ok={ok}")
    return jsonify({
        "ok":      ok,
        "package": pkg,
        "output":  (stdout or stderr)[-800:],
        "error":   None if ok else f"apt-get purge exited with code {rc}",
    })


@api_bp.route("/actions/ssh/users", methods=["GET"])
@login_required
def actions_ssh_users():
    """Return list of real login users on the system (uid >= 1000, or root)."""
    users = []
    try:
        stdout, _, _ = _run("getent passwd")
        for line in stdout.splitlines():
            parts = line.split(":")
            if len(parts) < 7:
                continue
            name, _, uid, _, _, home, shell = parts[:7]
            uid = int(uid)
            if (uid >= 1000 or name == "root") and shell not in ("/usr/sbin/nologin", "/sbin/nologin", "/bin/false"):
                users.append({"username": name, "home": home, "uid": uid})
    except Exception as e:
        logger.warning("Could not list users: %s", e)
    return jsonify({"ok": True, "users": users})


@api_bp.route("/actions/ssh/keygen", methods=["POST"])
@login_required
def actions_ssh_keygen():
    data = request.get_json(silent=True) or {}
    if not _validate_csrf(data.get("csrf_token", "")):
        return jsonify({"error": "Invalid CSRF token"}), 403

    username = data.get("username", "").strip()
    if not username or not _re.match(r'^[a-z_][a-z0-9_\-]{0,31}$', username):
        return jsonify({"error": "Invalid Linux username"}), 400

    add_to_auth = bool(data.get("add_to_authorized_keys", False))

    # Check the user actually exists on the system
    _, _, uid_rc = _run(f"id {username} 2>/dev/null")
    user_exists = uid_rc == 0

    # For root user, home is /root not /home/root
    home_dir = "/root" if username == "root" else f"/home/{username}"

    if add_to_auth and not user_exists:
        return jsonify({
            "error": (
                f"User '{username}' does not exist on this server. "
                f"Create it first with: sudo useradd -m -s /bin/bash {username}  "
                f"— or use an existing user (e.g. 'ubuntu' on AWS EC2)."
            )
        }), 400

    tmpdir = _tempfile.mkdtemp(prefix="hybridsec_key_")
    key_path = Path(tmpdir) / "id_rsa"

    try:
        result = _sp.run(
            ["ssh-keygen", "-t", "rsa", "-b", "4096",
             "-f", str(key_path), "-N", "",
             "-C", f"hybridsec-{username}"],
            capture_output=True, timeout=30
        )
        if result.returncode != 0:
            _shutil.rmtree(tmpdir, ignore_errors=True)
            return jsonify({"error": "ssh-keygen failed: " + result.stderr.decode()}), 500

        pub_key  = (key_path.parent / "id_rsa.pub").read_text().strip()

        # Store ONLY the path in session — NOT the full key (key is ~3KB,
        # which bloats the Flask session cookie beyond the 4KB browser limit
        # and causes the downloaded .pem to be silently truncated/corrupted).
        session["keygen_tmpdir"] = tmpdir
        session["keygen_user"]   = username

        auth_key_added = False
        auth_key_error = None

        if add_to_auth and user_exists:
            try:
                ssh_dir = f"{home_dir}/.ssh"
                auth_file = f"{ssh_dir}/authorized_keys"
                _, mk_err, mk_rc = _run(
                    f"mkdir -p {ssh_dir} && chmod 700 {ssh_dir} && chown {username}:{username} {ssh_dir}"
                )
                pub_escaped = pub_key.replace("'", "'\\''")
                _, wr_err, wr_rc = _run(
                    f"echo '{pub_escaped}' >> {auth_file} && "
                    f"chmod 600 {auth_file} && chown {username}:{username} {auth_file}"
                )
                if wr_rc == 0:
                    auth_key_added = True
                else:
                    auth_key_error = wr_err or mk_err or "Could not write authorized_keys"
            except Exception as e:
                auth_key_error = str(e)

        audit("SSH_KEYGEN", f"user={username} auth_added={auth_key_added}")
        return jsonify({
            "ok":             True,
            "public_key":     pub_key,
            "filename":       f"{username}-hybridsec.pem",
            "user_exists":    user_exists,
            "auth_key_added": auth_key_added,
            "auth_key_error": auth_key_error,
            "home_dir":       home_dir,
        })
    except Exception as e:
        _shutil.rmtree(tmpdir, ignore_errors=True)
        return jsonify({"error": str(e)}), 500


@api_bp.route("/actions/ssh/download-key", methods=["GET"])
@login_required
def actions_ssh_download_key():
    """One-time download of the generated private key from temp file, then purge."""
    from flask import Response
    tmpdir   = session.pop("keygen_tmpdir", None)
    username = session.pop("keygen_user", "user")

    if not tmpdir:
        return "Key not available — generate a new key pair first.", 404

    key_path = Path(tmpdir) / "id_rsa"
    if not key_path.exists():
        return "Key file not found — it may have already been downloaded.", 404

    try:
        content = key_path.read_bytes()
    except Exception as e:
        return f"Could not read key file: {e}", 500
    finally:
        _shutil.rmtree(tmpdir, ignore_errors=True)

    return Response(
        content,
        mimetype="application/x-pem-file",
        headers={
            "Content-Disposition": f'attachment; filename="{username}-hybridsec.pem"',
            "Cache-Control": "no-store, no-cache",
            "Pragma": "no-cache",
        }
    )
