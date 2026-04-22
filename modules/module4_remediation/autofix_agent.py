"""
autofix_agent.py — Safe Auto-Fix Executor  (Module 4)

Executes fix commands for a vulnerability following this safety protocol:

  1. Look up fix template (abort if unsupported or autofix_available=False)
  2. Backup the config file  (BackupManager)
  3. Require explicit confirmation ("YES")  — optional, config-controlled
  4. Execute each command in sequence
  5. Restart the affected service if required
  6. Verify the fix worked
  7. Return result with backup_id (for rollback button in web UI)

The web UI calls execute_fix() from a confirmed POST endpoint.
The CLI uses the --confirm flag.

IMPORTANT: All fix commands run as the user that started HybridSec.
In production this is root (or sudo). Never run this as an untrusted user.
"""

import logging
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from modules.module4_remediation.remediation_generator import RemediationGenerator
from modules.module4_remediation.backup_manager import BackupManager

try:
    from config import AUTOFIX_REQUIRE_CONFIRMATION, AUTOFIX_CREATE_BACKUP
except ImportError:
    AUTOFIX_REQUIRE_CONFIRMATION = True
    AUTOFIX_CREATE_BACKUP = True

COMMAND_TIMEOUT = 120   # seconds per command


class AutoFixAgent:
    """
    Executes auto-fix commands for supported vulnerability types.
    Maintains a backup for every fix so the web UI can offer rollback.
    """

    def __init__(self):
        self._gen     = RemediationGenerator(use_llm=False)
        self._backup  = BackupManager()

    # ── Public API ─────────────────────────────────────────────

    def execute_fix(
        self,
        vuln: dict,
        confirmed: bool = False,
    ) -> dict:
        """
        Execute the auto-fix for a vulnerability.

        Args:
            vuln:      vulnerability dict (needs at least 'type', 'id')
            confirmed: True if the admin has already typed "YES" (web UI
                       sends this after the confirmation modal).
                       If False and AUTOFIX_REQUIRE_CONFIRMATION is True,
                       the function returns needs_confirmation=True without
                       executing anything.

        Returns:
            AutoFixResult dict (see keys below).
        """
        vuln_type = vuln.get("type", "")
        vuln_id   = vuln.get("id",   "")

        # ── 1. Get template ─────────────────────────────────
        remediation = self._gen.get_remediation(vuln)

        if not remediation or not remediation.get("autofix_available"):
            return self._result(
                success=False,
                vuln_type=vuln_type,
                vuln_id=vuln_id,
                error=f"Auto-fix is not available for '{vuln_type}'. "
                      "See manual steps in the Remediation page.",
            )

        commands = remediation.get("commands", [])
        if not commands:
            return self._result(
                success=False, vuln_type=vuln_type, vuln_id=vuln_id,
                error="Template has no commands defined.",
            )

        # ── 2. Confirmation gate ────────────────────────────
        if AUTOFIX_REQUIRE_CONFIRMATION and not confirmed:
            return {
                **self._result(success=False, vuln_type=vuln_type, vuln_id=vuln_id),
                "needs_confirmation": True,
                "confirmation_message": (
                    f"You are about to auto-fix: {remediation.get('title', vuln_type)}\n"
                    f"Risk level: {(remediation.get('risk_level') or 'unknown').upper()}\n"
                    f"This will execute {len(commands)} command(s) as root.\n"
                    f"Type YES to proceed."
                ),
            }

        # ── 3. Backup config file ───────────────────────────
        backup_id = ""
        config_file = remediation.get("config_file")
        if AUTOFIX_CREATE_BACKUP and config_file:
            backup_result = self._backup.backup(config_file, vuln_type=vuln_type)
            if not backup_result["success"]:
                logger.warning(
                    "Backup failed for %s: %s — proceeding without backup",
                    config_file, backup_result["error"],
                )
            else:
                backup_id = backup_result["backup_id"]
                logger.info("Config backed up: %s → %s", config_file, backup_id)

        # ── 4. Execute commands ─────────────────────────────
        commands_run: list[dict] = []
        execution_error: Optional[str] = None

        for cmd in commands:
            cmd_result = self._run_command(cmd)
            commands_run.append(cmd_result)
            if not cmd_result["success"]:
                execution_error = (
                    f"Command failed: {cmd}\n"
                    f"Exit code: {cmd_result['returncode']}\n"
                    f"Stderr: {cmd_result['stderr'][:300]}"
                )
                logger.error("Auto-fix command failed: %s", execution_error)
                break   # Stop on first failure

        if execution_error:
            return self._result(
                success=False, vuln_type=vuln_type, vuln_id=vuln_id,
                backup_id=backup_id, commands_run=commands_run,
                error=execution_error,
            )

        # ── 5. Restart service ─────────────────────────────
        service = remediation.get("service_to_restart")
        service_restarted = False
        service_error = None

        if service:
            svc_result = self._restart_service(service)
            service_restarted = svc_result["success"]
            if not service_restarted:
                service_error = svc_result.get("error")
                logger.warning("Service restart failed: %s — %s", service, service_error)

        # ── 6. Verify fix ──────────────────────────────────
        verify_result = {"passed": False, "output": "", "skipped": True}
        verify_cmd = remediation.get("verify_command")
        if verify_cmd:
            verify_result = self._verify_fix(
                verify_cmd,
                expected=remediation.get("verify_expected"),
            )
            if not verify_result["passed"]:
                logger.warning(
                    "Verification failed for %s: expected '%s' in '%s'",
                    vuln_type,
                    remediation.get("verify_expected"),
                    verify_result["output"][:100],
                )

        # ── 7. Build final result ──────────────────────────
        logger.info(
            "Auto-fix complete: type=%s  backup=%s  verify=%s",
            vuln_type, backup_id, verify_result["passed"],
        )
        return self._result(
            success=True,
            vuln_type=vuln_type,
            vuln_id=vuln_id,
            backup_id=backup_id,
            commands_run=commands_run,
            service_restarted=service_restarted,
            service_error=service_error,
            verify_result=verify_result,
        )

    def rollback(self, backup_id: str) -> dict:
        """
        Restore the backed-up config file (undo the last auto-fix).

        Returns:
            dict with success, message, error.
        """
        if not backup_id:
            return {"success": False, "message": "", "error": "No backup_id provided."}

        result = self._backup.restore(backup_id)
        if result["success"]:
            logger.info("Rollback successful: %s", backup_id)
        return result

    def list_recent_fixes(self) -> list[dict]:
        """Return a list of recent backups (=recent auto-fixes) for the UI."""
        return self._backup.list_backups()

    # ── Private Helpers ────────────────────────────────────────

    @staticmethod
    def _run_command(cmd: str) -> dict:
        """Run a single shell command, return result dict."""
        try:
            proc = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=COMMAND_TIMEOUT,
            )
            return {
                "command":    cmd,
                "returncode": proc.returncode,
                "stdout":     proc.stdout.strip(),
                "stderr":     proc.stderr.strip(),
                "success":    proc.returncode == 0,
            }
        except subprocess.TimeoutExpired:
            return {
                "command": cmd, "returncode": -1,
                "stdout": "", "stderr": f"Timed out after {COMMAND_TIMEOUT}s",
                "success": False,
            }
        except Exception as e:
            return {
                "command": cmd, "returncode": -1,
                "stdout": "", "stderr": str(e),
                "success": False,
            }

    @staticmethod
    def _restart_service(service: str) -> dict:
        """Restart a systemd service."""
        result = AutoFixAgent._run_command(f"systemctl restart {service}")
        if not result["success"]:
            # Some services use different names (e.g. sshd vs ssh)
            alt = "ssh" if service == "sshd" else "sshd"
            alt_result = AutoFixAgent._run_command(f"systemctl restart {alt}")
            if alt_result["success"]:
                return alt_result
        return result

    @staticmethod
    def _verify_fix(verify_cmd: str, expected: Optional[str]) -> dict:
        """Run the verification command and check expected output."""
        result = AutoFixAgent._run_command(verify_cmd)
        output = (result["stdout"] + result["stderr"]).lower()

        if expected is None:
            # No expected string — just check exit code
            passed = result["returncode"] == 0
        else:
            passed = expected.lower() in output

        return {
            "passed":    passed,
            "output":    (result["stdout"] + result["stderr"]).strip(),
            "expected":  expected,
            "skipped":   False,
        }

    @staticmethod
    def _result(
        success: bool,
        vuln_type: str,
        vuln_id: str,
        backup_id: str = "",
        commands_run: Optional[list] = None,
        service_restarted: bool = False,
        service_error: Optional[str] = None,
        verify_result: Optional[dict] = None,
        error: Optional[str] = None,
    ) -> dict:
        return {
            "success":           success,
            "vuln_type":         vuln_type,
            "vuln_id":           vuln_id,
            "backup_id":         backup_id,
            "commands_run":      commands_run or [],
            "service_restarted": service_restarted,
            "service_error":     service_error,
            "verify_result":     verify_result or {"passed": False, "skipped": True},
            "error":             error,
            "needs_confirmation": False,
            "applied_at":        datetime.now().isoformat(timespec="seconds"),
        }


# ── Standalone test (dry-run — does not touch system files) ───
if __name__ == "__main__":
    import json
    logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")

    agent = AutoFixAgent()
    gen = RemediationGenerator(use_llm=False)

    print("\n" + "=" * 60)
    print("  AutoFixAgent — Dry-Run Mode")
    print("  (no system changes — just showing what WOULD happen)")
    print("=" * 60)

    # Show what fix templates are loaded
    supported = gen.list_supported_types()
    auto_fixable = [
        t for t in supported
        if gen.get_remediation({"type": t}).get("autofix_available")
    ]
    print(f"\n  Total supported types : {len(supported)}")
    print(f"  Auto-fixable types    : {len(auto_fixable)}")
    print(f"\n  Auto-fixable list:")
    for t in sorted(auto_fixable):
        r = gen.get_remediation({"type": t})
        print(f"    ✅  {t:<35}  risk={r['risk_level']:<6}  cmds={len(r['commands'])}")

    print(f"\n  Manual/semi-auto types:")
    manual = [t for t in supported if t not in auto_fixable]
    for t in sorted(manual):
        r = gen.get_remediation({"type": t})
        print(f"    📋  {t:<35}  risk={r['risk_level']}")

    # Simulate confirmation gate (no changes to disk)
    print("\n" + "=" * 60)
    print("  Simulating fix request for ssh_root_login_enabled")
    print("=" * 60)
    vuln = {"id": "VULN-001", "type": "ssh_root_login_enabled",
            "title": "SSH Root Login Enabled"}
    result = agent.execute_fix(vuln, confirmed=False)
    print(f"\n  needs_confirmation : {result.get('needs_confirmation')}")
    print(f"  confirmation_msg   :\n    {result.get('confirmation_message', '').replace(chr(10), chr(10)+'    ')}")

    # Simulate unsupported type
    print("\n" + "=" * 60)
    print("  Simulating fix request for unsupported type")
    print("=" * 60)
    vuln2 = {"id": "VULN-002", "type": "lynis_low_hardening_score"}
    result2 = agent.execute_fix(vuln2, confirmed=True)
    print(f"  success : {result2['success']}")
    print(f"  error   : {result2['error']}")
