"""
live_guard.py — Live Guard Master Orchestrator  (Module 6)

Coordinates all real-time detection monitors and the APScheduler-based
scan scheduler into one unified daemon:

  Monitors (daemon threads, run 24/7):
    ├── SSHMonitor       — brute force via auth.log
    ├── WebMonitor       — SQLi/XSS/DDoS via access.log
    └── PortScanMonitor  — port scans via UFW/syslog

  Scheduler (APScheduler):
    ├── Quick Scan  — every QUICK_SCAN_INTERVAL_HOURS (default: 6h)
    └── Deep Scan   — daily at DEEP_SCAN_TIME (default: 03:00)

  Shared resources (injected into all monitors):
    ├── IPBlocker        — UFW/iptables firewall commands
    ├── AlertSystem      — Telegram + Email notifications
    └── IncidentLog      — JSON append-only incident store

Usage (from run.py):
    guard = LiveGuard()
    guard.start()           # starts all threads + scheduler
    guard.stop()            # graceful shutdown
    guard.get_status()      # dict with all component states

Usage (standalone daemon):
    python3 -m modules.module6_liveguard.live_guard
"""

import logging
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

try:
    from config import (
        QUICK_SCAN_INTERVAL_HOURS,
        DEEP_SCAN_TIME,
        LOGS_DIR,
    )
except ImportError:
    QUICK_SCAN_INTERVAL_HOURS = 6
    DEEP_SCAN_TIME = "03:00"
    LOGS_DIR = Path(__file__).parent.parent.parent / "logs"

from modules.module6_liveguard.ip_blocker       import IPBlocker
from modules.module6_liveguard.alert_system     import AlertSystem
from modules.module6_liveguard.ssh_monitor      import SSHMonitor, IncidentLog
from modules.module6_liveguard.web_monitor      import WebMonitor
from modules.module6_liveguard.port_scan_monitor import PortScanMonitor


class LiveGuard:
    """
    Master Live Guard daemon.

    Instantiate once in run.py and call start() alongside the Flask web server.
    Thread-safe; all subcomponents run as daemon threads so they exit
    automatically when the main process exits.
    """

    def __init__(self):
        # Shared infrastructure
        self._blocker      = IPBlocker()
        self._alerter      = AlertSystem()
        self._incidents    = IncidentLog()

        # Detection monitors
        self._ssh_mon  = SSHMonitor(self._blocker, self._alerter, self._incidents)
        self._web_mon  = WebMonitor(self._blocker, self._alerter, self._incidents)
        self._port_mon = PortScanMonitor(self._blocker, self._alerter, self._incidents)

        # APScheduler (lazy-init in start() to avoid import cost at module load)
        self._scheduler = None
        self._started   = False
        self._lock      = threading.Lock()

    # ── Public API ─────────────────────────────────────────────

    def start(self):
        """Start all monitors and the scan scheduler."""
        with self._lock:
            if self._started:
                logger.warning("LiveGuard already running")
                return

            logger.info("Starting LiveGuard...")

            # Start monitors
            self._ssh_mon.start()
            self._web_mon.start()
            self._port_mon.start()

            # Start scheduler
            self._start_scheduler()

            self._started = True
            logger.info(
                "LiveGuard started — SSH monitor, Web monitor, Port scan monitor, Scheduler"
            )

    def stop(self):
        """Gracefully shut down all monitors and the scheduler."""
        with self._lock:
            if not self._started:
                return

            logger.info("Stopping LiveGuard...")
            self._ssh_mon.stop()
            self._web_mon.stop()
            self._port_mon.stop()

            if self._scheduler and self._scheduler.running:
                self._scheduler.shutdown(wait=False)

            self._started = False
            logger.info("LiveGuard stopped.")

    def get_status(self) -> dict:
        """Return a status dict for the web UI /api/threats endpoint."""
        blocked = self._blocker.list_blocked()
        recent  = self._incidents.read_recent(20)

        return {
            "running":       self._started,
            "monitors": {
                "ssh":       self._ssh_mon.get_stats(),
                "web":       self._web_mon.get_stats(),
                "port_scan": self._port_mon.get_stats(),
            },
            "alerts": self._alerter.is_configured(),
            "blocked_ips":     blocked,
            "blocked_count":   len(blocked),
            "recent_incidents": recent,
            "incident_count":  len(recent),
            "scheduler": self._get_scheduler_status(),
        }

    def unblock_ip(self, ip: str) -> dict:
        """Manually unblock an IP (called from web UI)."""
        return self._blocker.unblock_ip(ip)

    def get_incidents(self, n: int = 50) -> list[dict]:
        return self._incidents.read_recent(n)

    # ── Scheduler ──────────────────────────────────────────────

    def _start_scheduler(self):
        try:
            from apscheduler.schedulers.background import BackgroundScheduler
            from apscheduler.triggers.cron import CronTrigger
            from apscheduler.triggers.interval import IntervalTrigger

            self._scheduler = BackgroundScheduler(
                job_defaults={"misfire_grace_time": 300},
                timezone="UTC",
            )

            # Quick scan every N hours
            self._scheduler.add_job(
                func=self._run_quick_scan,
                trigger=IntervalTrigger(hours=QUICK_SCAN_INTERVAL_HOURS),
                id="quick_scan",
                name=f"Quick scan every {QUICK_SCAN_INTERVAL_HOURS}h",
                replace_existing=True,
            )

            # Deep scan daily at configured time (e.g. "03:00")
            hour, minute = _parse_time(DEEP_SCAN_TIME)
            self._scheduler.add_job(
                func=self._run_deep_scan,
                trigger=CronTrigger(hour=hour, minute=minute),
                id="deep_scan",
                name=f"Deep scan daily at {DEEP_SCAN_TIME} UTC",
                replace_existing=True,
            )

            self._scheduler.start()
            logger.info(
                "Scheduler started: quick scan every %dh, deep scan at %s UTC",
                QUICK_SCAN_INTERVAL_HOURS, DEEP_SCAN_TIME,
            )
        except ImportError:
            logger.warning("APScheduler not installed — scheduled scans disabled.")
        except Exception as exc:
            logger.error("Scheduler start failed: %s", exc)

    def _get_scheduler_status(self) -> dict:
        if not self._scheduler:
            return {"running": False, "jobs": []}
        jobs = []
        if self._scheduler.running:
            for job in self._scheduler.get_jobs():
                jobs.append({
                    "id":       job.id,
                    "name":     job.name,
                    "next_run": str(job.next_run_time)[:19] if job.next_run_time else None,
                })
        return {"running": self._scheduler.running if self._scheduler else False, "jobs": jobs}

    # ── Scheduled scan runners ─────────────────────────────────

    def _run_quick_scan(self):
        logger.info("Scheduled QUICK scan starting...")
        try:
            self._execute_scan("quick")
        except Exception as exc:
            logger.error("Scheduled quick scan failed: %s", exc, exc_info=True)

    def _run_deep_scan(self):
        logger.info("Scheduled DEEP scan starting...")
        try:
            self._execute_scan("deep")
        except Exception as exc:
            logger.error("Scheduled deep scan failed: %s", exc, exc_info=True)

    @staticmethod
    def _execute_scan(scan_type: str):
        """Run a scan and persist result to the database."""
        import json, uuid
        from modules.module1_collection.scanner import Scanner
        from modules.module3_scoring.hybrid_engine import HybridEngine
        from modules.module2_context.context_manager import ContextManager

        scan_id = "scan_" + uuid.uuid4().hex[:12]
        scanner = Scanner(target="127.0.0.1", enrich_nvd=False)

        if scan_type == "deep":
            raw = scanner.run_deep_scan()
        else:
            raw = scanner.run_quick_scan()

        cm      = ContextManager()
        context = cm.get_active_profile()
        engine  = HybridEngine()
        scored  = engine.score_all(raw.get("vulnerabilities", []), context)
        raw["vulnerabilities"] = scored

        # Save to database via auth._get_db()
        from modules.module5_web.auth import _get_db
        db = _get_db()
        try:
            db.execute(
                """INSERT OR REPLACE INTO scan_results
                   (scan_id, scan_type, target, status, started_at, completed_at, result_json)
                   VALUES (?, ?, '127.0.0.1', 'completed', ?, ?, ?)""",
                (
                    scan_id, scan_type,
                    datetime.now(timezone.utc).isoformat(),
                    datetime.now(timezone.utc).isoformat(),
                    json.dumps(raw),
                ),
            )
            db.commit()
        finally:
            db.close()

        logger.info(
            "Scheduled %s scan complete: id=%s  vulns=%d",
            scan_type, scan_id, len(scored),
        )

        # Alert if new critical vulnerabilities were found
        critical = [v for v in scored if v.get("priority") == "CRITICAL"]
        if critical:
            alerter = AlertSystem()
            alerter.send_alert({
                "type":      "new_critical_vulnerabilities",
                "source_ip": "localhost",
                "severity":  "critical",
                "detail":    f"{len(critical)} CRITICAL vulnerabilities found in {scan_type} scan",
                "blocked":   False,
            })


# ── Helpers ────────────────────────────────────────────────────

def _parse_time(time_str: str) -> tuple[int, int]:
    """Parse '03:00' → (3, 0)."""
    try:
        h, m = time_str.strip().split(":")
        return int(h), int(m)
    except Exception:
        return 3, 0


# ── Standalone daemon mode ─────────────────────────────────────
if __name__ == "__main__":
    import signal

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    guard = LiveGuard()
    guard.start()

    print("\n" + "=" * 60)
    print("  HybridSec Live Guard — Running")
    print("=" * 60)

    status = guard.get_status()
    print(f"\n  SSH Monitor    : {'ON' if status['monitors']['ssh']['running'] else 'OFF'}")
    print(f"  Web Monitor    : {'ON' if status['monitors']['web']['running'] else 'OFF'}")
    print(f"  Port Monitor   : {'ON' if status['monitors']['port_scan']['running'] else 'OFF'}")
    print(f"  Telegram alerts: {'ON' if status['alerts']['telegram'] else 'OFF (not configured)'}")
    print(f"  Email alerts   : {'ON' if status['alerts']['email'] else 'OFF (not configured)'}")

    sched = status.get("scheduler", {})
    if sched.get("jobs"):
        print("\n  Scheduled jobs:")
        for job in sched["jobs"]:
            print(f"    • {job['name']}  →  next: {job['next_run']}")

    print("\n  Press CTRL+C to stop.")

    def _shutdown(sig, frame):
        print("\nShutting down Live Guard...")
        guard.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT,  _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    # Block main thread
    import time
    while True:
        time.sleep(60)
        status = guard.get_status()
        logger.info(
            "Live Guard heartbeat — blocked_ips=%d  incidents=%d",
            status["blocked_count"], status["incident_count"],
        )
