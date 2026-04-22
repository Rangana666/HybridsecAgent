"""
run.py — HybridSec Agent Entry Point  v1.0

Usage:
    python3 run.py                      # HTTP on port 5000 + Live Guard
    python3 run.py --https              # HTTPS on port 5443 (self-signed cert)
    python3 run.py --no-liveguard       # web only (dev/test)
    python3 run.py --port 8080
    python3 run.py --debug
    python3 run.py --check              # pre-flight check only (no start)
"""

import argparse
import logging
import os
import signal
import sys
from pathlib import Path

# ── Logging setup ─────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("hybridsec")

sys.path.insert(0, str(Path(__file__).parent))

VERSION = "1.0.0"
DEFAULT_HTTP_PORT  = 5000
DEFAULT_HTTPS_PORT = 5443
SSL_DIR  = Path(__file__).parent / "ssl"
SSL_CERT = SSL_DIR / "hybridsec.crt"
SSL_KEY  = SSL_DIR / "hybridsec.key"


# ── Pre-flight checks ─────────────────────────────────────────

def _preflight() -> list[str]:
    """Return a list of warning strings (empty = all good)."""
    warnings = []

    try:
        from config import SECRET_KEY
        if SECRET_KEY in ("CHANGE-THIS-IN-PRODUCTION",
                          "CHANGE-THIS-TO-A-RANDOM-32-CHAR-STRING",
                          "change-this-to-a-random-string"):
            warnings.append("SECRET_KEY is still the default — change it in .env!")
    except ImportError:
        warnings.append("config.py not found — using built-in defaults.")

    db_path = Path(__file__).parent / "database"
    if not db_path.exists():
        warnings.append(f"Database directory missing: {db_path}")

    logs_path = Path(__file__).parent / "logs"
    if not logs_path.exists():
        try:
            logs_path.mkdir(parents=True)
        except OSError:
            warnings.append(f"Could not create logs directory: {logs_path}")

    rules_file = Path(__file__).parent / "data" / "rules" / "security_rules.json"
    if not rules_file.exists():
        warnings.append(f"Rules file missing: {rules_file}")

    return warnings


# ── SSL certificate generation ────────────────────────────────

def _ensure_ssl():
    """Generate a self-signed certificate if one does not exist."""
    if SSL_CERT.exists() and SSL_KEY.exists():
        return True

    SSL_DIR.mkdir(parents=True, exist_ok=True)
    logger.info("Generating self-signed SSL certificate…")
    ret = os.system(
        f'openssl req -x509 -newkey rsa:4096 -nodes '
        f'-keyout "{SSL_KEY}" -out "{SSL_CERT}" '
        f'-days 3650 '
        f'-subj "/C=LK/ST=Western/L=Colombo/O=HybridSec/CN=hybridsec.local" '
        f'2>/dev/null'
    )
    if ret != 0 or not SSL_CERT.exists():
        logger.error("openssl not found — cannot generate SSL certificate. "
                     "Install openssl or run without --https.")
        return False

    SSL_KEY.chmod(0o600)
    logger.info("SSL certificate generated: %s", SSL_CERT)
    return True


# ── Banner ────────────────────────────────────────────────────

def _print_banner(host: str, port: int, https: bool, debug: bool,
                  live_guard_status: str, warnings: list[str]):
    scheme  = "https" if https else "http"
    display = "localhost" if host == "0.0.0.0" else host

    print()
    print("=" * 62)
    print(f"  HybridSec Agent  v{VERSION}")
    print("  Linux Security Risk Analysis — Sri Lankan SME Edition")
    print("=" * 62)
    print(f"\n  Dashboard    →  {scheme}://{display}:{port}/")
    print(f"  Login        →  admin / Admin@HybridSec2025!")
    print(f"  HTTPS        →  {'ON  (self-signed cert)' if https else 'OFF (HTTP only)'}")
    print(f"  Live Guard   →  {live_guard_status}")
    print(f"  Debug mode   →  {'ON' if debug else 'OFF'}")

    if warnings:
        print()
        for w in warnings:
            print(f"  ⚠  {w}")

    print("\n  Press CTRL+C to stop.\n")


# ── Main ──────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description=f"HybridSec Agent v{VERSION}")
    parser.add_argument("--host",  default=None)
    parser.add_argument("--port",  type=int, default=None)
    parser.add_argument("--debug", action="store_true")
    parser.add_argument("--https", action="store_true",
                        help="Enable HTTPS with a self-signed certificate")
    parser.add_argument("--no-liveguard", action="store_true",
                        help="Disable Live Guard (useful for dev/testing)")
    parser.add_argument("--check", action="store_true",
                        help="Run pre-flight checks and exit")
    args = parser.parse_args()

    # Config values
    try:
        from config import FLASK_HOST, FLASK_PORT, FLASK_DEBUG
    except ImportError:
        FLASK_HOST, FLASK_PORT, FLASK_DEBUG = "0.0.0.0", DEFAULT_HTTP_PORT, False

    host  = args.host  or FLASK_HOST
    debug = args.debug or FLASK_DEBUG

    if args.https:
        port = args.port or DEFAULT_HTTPS_PORT
    else:
        port = args.port or FLASK_PORT

    # Pre-flight
    warnings = _preflight()

    if args.check:
        print(f"HybridSec Agent v{VERSION} — Pre-flight check")
        if warnings:
            for w in warnings:
                print(f"  WARN  {w}")
            sys.exit(1)
        else:
            print("  All checks passed.")
            sys.exit(0)

    # HTTPS
    ssl_context = None
    if args.https:
        if _ensure_ssl():
            ssl_context = (str(SSL_CERT), str(SSL_KEY))
        else:
            logger.warning("HTTPS requested but SSL cert unavailable — falling back to HTTP.")
            args.https = False

    # Live Guard
    live_guard = None
    if not args.no_liveguard:
        try:
            from modules.module6_liveguard.live_guard import LiveGuard
            live_guard = LiveGuard()
            live_guard.start()
            lg_status = "RUNNING (SSH + Web + Port scan monitors)"
        except Exception as exc:
            logger.warning("Live Guard failed to start: %s — continuing without it", exc)
            lg_status = f"FAILED ({exc})"
    else:
        lg_status = "DISABLED (--no-liveguard)"

    _print_banner(host, port, args.https, debug, lg_status, warnings)

    # Graceful shutdown
    def _shutdown(sig, frame):
        print("\nShutting down HybridSec Agent…")
        if live_guard:
            live_guard.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT,  _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    # Flask
    from modules.module5_web.app import create_app
    app = create_app()
    app.config["LIVE_GUARD"] = live_guard

    app.run(
        host=host,
        port=port,
        debug=debug,
        use_reloader=False,
        ssl_context=ssl_context,
    )


if __name__ == "__main__":
    main()
