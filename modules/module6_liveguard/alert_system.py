"""
alert_system.py — Telegram + Email Alert System  (Module 6)

Sends security incident notifications to the admin via:
  1. Telegram Bot API  (instant push notification)
  2. SMTP Email        (fallback / additional channel)

Alert format (Telegram):
  🔴 HYBRIDSEC ALERT 🔴
  ━━━━━━━━━━━━━━━━━━━━
  🚨 Threat   : BRUTE_FORCE_SSH
  🌍 Attacker : 185.220.101.47
  ⚠️ Severity : CRITICAL
  📋 Details  : 8 failed SSH attempts in 60s
  🕐 Time     : 2025-04-17 14:23:45
  ━━━━━━━━━━━━━━━━━━━━
  ✅ IP automatically BLOCKED!

Public API:
    alert = AlertSystem()
    alert.send_alert(incident)     → sends Telegram + Email
    alert.send_test()              → test connectivity
"""

import logging
import smtplib
import sys
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

logger = logging.getLogger(__name__)

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

try:
    import config as _cfg
except ImportError:
    _cfg = None  # type: ignore

def _tg_token()   -> str:  return getattr(_cfg, "TELEGRAM_BOT_TOKEN", "") or ""
def _tg_chat()    -> str:  return getattr(_cfg, "TELEGRAM_CHAT_ID", "") or ""
def _tg_enabled() -> bool: return bool(_tg_token() and _tg_chat())
def _smtp_host()  -> str:  return getattr(_cfg, "SMTP_HOST", "smtp.gmail.com") or "smtp.gmail.com"
def _smtp_port()  -> int:  return int(getattr(_cfg, "SMTP_PORT", 587) or 587)
def _smtp_tls()   -> bool: return bool(getattr(_cfg, "SMTP_USE_TLS", True))
def _alert_email()-> str:  return getattr(_cfg, "ALERT_EMAIL", "") or ""
def _smtp_pass()  -> str:  return getattr(_cfg, "SMTP_PASSWORD", "") or ""
def _em_enabled() -> bool: return bool(_alert_email() and _smtp_pass())

# Severity emoji map
_SEV_EMOJI = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🟢",
    "info":     "ℹ️",
}

_BLOCK_EMOJI = {True: "✅ IP automatically BLOCKED!", False: "⚠️ Manual review required."}

_geo_cache: dict = {}

def _get_location(ip: str) -> str:
    """Return 'City, Region, Country (ISP)' for an IP using ip-api.com (free, no key)."""
    if not ip or ip in ("0.0.0.0", "127.0.0.1", "localhost"):
        return "Local / Internal"
    if ip in _geo_cache:
        return _geo_cache[ip]
    try:
        import requests
        r = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,country,regionName,city,isp"},
            timeout=5,
        )
        d = r.json()
        if d.get("status") == "success":
            parts = [d.get("city"), d.get("regionName"), d.get("country")]
            location = ", ".join(p for p in parts if p)
            isp = d.get("isp", "")
            result = f"{location} ({isp})" if isp else location
        else:
            result = "Unknown location"
    except Exception:
        result = "Unknown location"
    _geo_cache[ip] = result
    return result


class AlertSystem:
    """
    Sends security alerts via Telegram and/or Email.
    Gracefully no-ops if credentials are not configured.
    """

    def __init__(self):
        if not _tg_enabled():
            logger.info("Telegram alerts disabled (TELEGRAM_BOT_TOKEN not set)")
        if not _em_enabled():
            logger.info("Email alerts disabled (ALERT_EMAIL/SMTP_PASSWORD not set)")

    # ── Public API ─────────────────────────────────────────────

    def send_alert(self, incident: dict) -> dict:
        """
        Send an alert for a security incident.

        Args:
            incident: dict with keys:
                type        — e.g. "ssh_brute_force"
                source_ip   — attacker IP
                severity    — "critical"|"high"|"medium"|"low"
                detail      — human-readable description
                blocked     — True if IP was automatically blocked
                timestamp   — ISO string (defaults to now)

        Returns:
            {"telegram": bool, "email": bool}
        """
        incident.setdefault("timestamp", datetime.now(timezone.utc).isoformat(timespec="seconds"))
        incident.setdefault("location", _get_location(incident.get("source_ip", "")))

        msg_telegram = self._build_telegram_message(incident)
        msg_email    = self._build_email_body(incident)
        subject      = self._build_subject(incident)

        tg_ok = self._send_telegram(msg_telegram) if _tg_enabled() else False
        em_ok = self._send_email(subject, msg_email) if _em_enabled() else False

        logger.info(
            "Alert sent: type=%s ip=%s  telegram=%s  email=%s",
            incident.get("type"), incident.get("source_ip"), tg_ok, em_ok,
        )
        return {"telegram": tg_ok, "email": em_ok}

    def send_test(self) -> dict:
        """Send a test alert to verify connectivity."""
        return self.send_alert({
            "type":      "test_alert",
            "source_ip": "0.0.0.0",
            "severity":  "info",
            "detail":    "HybridSec Alert System test — this is a test message.",
            "blocked":   False,
        })

    def send_test_telegram(self) -> tuple[bool, str]:
        """Test Telegram connectivity; returns (ok, message)."""
        if not _tg_token() or not _tg_chat():
            return False, "Telegram not configured — add Bot Token and Chat ID in Settings."
        try:
            import requests
            url = f"https://api.telegram.org/bot{_tg_token()}/sendMessage"
            resp = requests.post(url, json={
                "chat_id": _tg_chat(),
                "text": "✅ HybridSec test message — Telegram alerts are working!",
                "parse_mode": "Markdown",
            }, timeout=10)
            if resp.ok:
                return True, "Test message sent to Telegram successfully!"
            return False, f"Telegram API error: {resp.json().get('description', resp.text[:100])}"
        except Exception as exc:
            return False, f"Connection error: {exc}"

    def send_test_email(self) -> tuple[bool, str]:
        """Test SMTP email connectivity; returns (ok, message)."""
        if not _alert_email() or not _smtp_pass():
            return False, "Email not configured — add Alert Email and SMTP Password in Settings."
        try:
            em = _alert_email()
            msg = MIMEMultipart("alternative")
            msg["Subject"] = "[HybridSec] Test Alert — Email is working!"
            msg["From"]    = em
            msg["To"]      = em
            msg.attach(MIMEText(
                "This is a test email from HybridSec Agent.\n"
                "Email alerts are configured correctly.",
                "plain",
            ))
            with smtplib.SMTP(_smtp_host(), _smtp_port(), timeout=15) as server:
                if _smtp_tls():
                    server.starttls()
                server.login(em, _smtp_pass())
                server.sendmail(em, [em], msg.as_string())
            return True, f"Test email sent to {em} successfully!"
        except Exception as exc:
            return False, f"SMTP error: {exc}"

    def is_configured(self) -> dict:
        return {
            "telegram": _tg_enabled(),
            "email":    _em_enabled(),
        }

    # ── Message Builders ───────────────────────────────────────

    @staticmethod
    def _build_telegram_message(inc: dict) -> str:
        sev  = inc.get("severity", "medium").lower()
        sev_emoji = _SEV_EMOJI.get(sev, "⚠️")
        ts   = inc.get("timestamp", "")[:19].replace("T", " ")
        blocked_line = _BLOCK_EMOJI.get(bool(inc.get("blocked")), "")

        location = inc.get("location", "")
        return (
            f"{sev_emoji} *HYBRIDSEC ALERT* {sev_emoji}\n"
            f"━━━━━━━━━━━━━━━━━━━━\n"
            f"🚨 *Threat*   : `{inc.get('type', '—').upper().replace('_', ' ')}`\n"
            f"🌍 *Attacker* : `{inc.get('source_ip', '—')}`\n"
            f"📍 *Location* : {location}\n"
            f"⚠️ *Severity* : `{sev.upper()}`\n"
            f"📋 *Details*  : {inc.get('detail', '—')}\n"
            f"🕐 *Time*     : `{ts}`\n"
            f"━━━━━━━━━━━━━━━━━━━━\n"
            f"{blocked_line}"
        )

    @staticmethod
    def _build_subject(inc: dict) -> str:
        sev = inc.get("severity", "medium").upper()
        t   = inc.get("type", "UNKNOWN").upper().replace("_", " ")
        return f"[HybridSec {sev}] {t} from {inc.get('source_ip', '—')}"

    @staticmethod
    def _build_email_body(inc: dict) -> str:
        sev  = inc.get("severity", "medium").upper()
        ts   = inc.get("timestamp", "")[:19].replace("T", " ")
        blocked_txt = "YES — IP was automatically blocked." if inc.get("blocked") else "NO — Manual review required."

        location = inc.get("location", "Unknown location")
        return f"""
HybridSec Agent — Security Alert
===================================

Threat Type   : {inc.get('type', '—').upper().replace('_', ' ')}
Attacker IP   : {inc.get('source_ip', '—')}
Location      : {location}
Severity      : {sev}
Details       : {inc.get('detail', '—')}
Time          : {ts}
Automatically Blocked: {blocked_txt}

===================================
This alert was generated by HybridSec Agent v1.0
Do not reply to this email.
"""

    # ── Transport ──────────────────────────────────────────────

    @staticmethod
    def _send_telegram(message: str) -> bool:
        try:
            import requests
            url = f"https://api.telegram.org/bot{_tg_token()}/sendMessage"
            resp = requests.post(
                url,
                json={
                    "chat_id":    _tg_chat(),
                    "text":       message,
                    "parse_mode": "Markdown",
                },
                timeout=10,
            )
            if resp.ok:
                return True
            logger.warning("Telegram send failed: %s", resp.text[:200])
            return False
        except Exception as exc:
            logger.error("Telegram send error: %s", exc)
            return False

    @staticmethod
    def _send_email(subject: str, body: str) -> bool:
        try:
            em = _alert_email()
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"]    = em
            msg["To"]      = em
            msg.attach(MIMEText(body, "plain"))

            with smtplib.SMTP(_smtp_host(), _smtp_port(), timeout=10) as server:
                if _smtp_tls():
                    server.starttls()
                server.login(em, _smtp_pass())
                server.sendmail(em, [em], msg.as_string())
            return True
        except Exception as exc:
            logger.error("Email send error: %s", exc)
            return False


# ── Standalone test ────────────────────────────────────────────
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")
    a = AlertSystem()
    print("Alert system configured:", a.is_configured())

    # Build a fake incident for preview only (does not send unless .env is set)
    fake = {
        "type": "ssh_brute_force",
        "source_ip": "185.220.101.47",
        "severity": "critical",
        "detail": "8 failed SSH attempts in 60s",
        "blocked": True,
    }
    print("\n--- Telegram message preview ---")
    print(AlertSystem._build_telegram_message(fake))
    print("\n--- Email subject ---")
    print(AlertSystem._build_subject(fake))

    if TELEGRAM_ENABLED or EMAIL_ALERTS_ENABLED:
        result = a.send_test()
        print(f"\nTest alert sent: {result}")
    else:
        print("\n[SKIP] No alert credentials in .env — skipping live send.")
