"""
nmap_scanner.py — Nmap Port & Service Scanner Wrapper
Runs Nmap against the target (default: localhost) and returns
structured port/service data plus detected network-level vulnerabilities.

Requires: nmap installed  (sudo apt install nmap)
Requires: python-nmap     (pip install python-nmap)
Note: Full version detection (-sV) requires root on some systems.
"""

import logging
import socket
from typing import Optional

logger = logging.getLogger(__name__)

# Ports that should NEVER be exposed on a public interface
SENSITIVE_PORTS = {
    3306: "MySQL/MariaDB",
    5432: "PostgreSQL",
    27017: "MongoDB",
    6379: "Redis",
    11211: "Memcached",
    2181: "ZooKeeper",
    9200: "Elasticsearch",
    8080: "HTTP Alternate (admin panel?)",
    8443: "HTTPS Alternate",
    10000: "Webmin",
    2375: "Docker daemon (UNAUTHENTICATED)",
    2376: "Docker daemon (TLS)",
    4848: "GlassFish Admin",
    9000: "PHP-FPM / SonarQube",
}

# Ports that indicate services which should be version-checked
WEB_PORTS = {80, 443, 8080, 8443}
SSH_PORTS = {22}
DB_PORTS = {3306, 5432, 27017, 6379, 11211}


class NmapScanner:
    """Wraps python-nmap to scan a host and extract security findings."""

    def __init__(self, target: str = "127.0.0.1"):
        self.target = target

    def scan(self) -> dict:
        """
        Run Nmap against self.target with service version detection.

        Returns:
            dict with keys:
              available (bool)     — was nmap installed and usable?
              target (str)         — scanned host/IP
              open_ports (list)    — list of port detail dicts
              vulnerabilities (list) — network-level vulns detected
              error (str|None)
        """
        result = {
            "available": False,
            "target": self.target,
            "open_ports": [],
            "vulnerabilities": [],
            "error": None,
        }

        try:
            import nmap  # python-nmap
        except ImportError:
            result["error"] = "python-nmap not installed. Run: pip install python-nmap"
            logger.warning("python-nmap not installed")
            return result

        if not self._is_nmap_installed(nmap):
            result["error"] = (
                "nmap binary not found. "
                "Install with: sudo apt install nmap  (Debian/Ubuntu) "
                "or: sudo yum install nmap  (RHEL/CentOS)"
            )
            logger.warning("nmap binary not found")
            return result

        result["available"] = True

        try:
            open_ports = self._run_scan(nmap)
            result["open_ports"] = open_ports
            result["vulnerabilities"] = self._detect_vulns(open_ports)

            logger.info(
                "Nmap scan of %s complete — %d open ports, %d network vulns",
                self.target,
                len(open_ports),
                len(result["vulnerabilities"]),
            )

        except nmap.PortScannerError as e:
            result["error"] = f"Nmap error: {e}"
            logger.error("Nmap scan error: %s", e)
        except Exception as e:
            result["error"] = str(e)
            logger.error("Nmap unexpected error: %s", e)

        return result

    # ── Private Helpers ────────────────────────────────────────

    def _is_nmap_installed(self, nmap_module) -> bool:
        """Check nmap binary exists by trying to init PortScanner."""
        try:
            nmap_module.PortScanner()
            return True
        except nmap.PortScannerError:
            return False
        except Exception:
            return False

    def _run_scan(self, nmap_module) -> list:
        """
        Execute nmap with:
          -sV  — service/version detection
          -sS  — SYN scan (faster, requires root; falls back to -sT)
          -T4  — aggressive timing (faster)
          -p-  — all 65535 ports (use --top-ports 1000 for speed)
          --open — only show open ports

        For research purposes we scan top 1000 ports by default.
        Change to -p- for a full scan (takes much longer).
        """
        nm = nmap_module.PortScanner()

        logger.info("Scanning %s (top 1000 ports, version detection)...", self.target)

        # Attempt SYN scan first; if it fails (non-root), fall back to connect scan
        try:
            nm.scan(
                hosts=self.target,
                arguments="-sS -sV -T4 --top-ports 1000 --open",
                timeout=120,
            )
        except nmap.PortScannerError:
            logger.warning("SYN scan requires root, falling back to TCP connect scan")
            nm.scan(
                hosts=self.target,
                arguments="-sT -sV -T4 --top-ports 1000 --open",
                timeout=120,
            )

        return self._parse_results(nm)

    def _parse_results(self, nm) -> list:
        """Convert python-nmap PortScanner output into a list of port dicts."""
        ports = []

        for host in nm.all_hosts():
            host_info = nm[host]

            for proto in host_info.all_protocols():
                port_ids = sorted(host_info[proto].keys())

                for port_id in port_ids:
                    port_data = host_info[proto][port_id]

                    if port_data.get("state") != "open":
                        continue

                    ports.append({
                        "port": port_id,
                        "protocol": proto,
                        "state": port_data.get("state", "open"),
                        "service": port_data.get("name", "unknown"),
                        "product": port_data.get("product", ""),
                        "version": port_data.get("version", ""),
                        "extra_info": port_data.get("extrainfo", ""),
                        "is_sensitive": port_id in SENSITIVE_PORTS,
                        "is_web": port_id in WEB_PORTS,
                        "is_ssh": port_id in SSH_PORTS,
                        "is_db": port_id in DB_PORTS,
                    })

        return ports

    def _detect_vulns(self, open_ports: list) -> list:
        """
        Inspect open ports for network-level vulnerability patterns.
        Returns a list of partial vulnerability dicts (will be merged into
        the master vuln list by scanner.py).
        """
        vulns = []
        seen_types = set()

        for p in open_ports:
            port_num = p["port"]
            service = p.get("service", "")
            product = (p.get("product", "") + " " + p.get("version", "")).strip()

            # SSH on default port
            if port_num == 22 and "ssh_default_port" not in seen_types:
                vulns.append(self._make_vuln(
                    vuln_type="ssh_default_port",
                    evidence=f"SSH detected on default port 22",
                    affected_component="sshd",
                    port=port_num,
                ))
                seen_types.add("ssh_default_port")

            # Sensitive database / service port exposed
            if port_num in SENSITIVE_PORTS and port_num not in {22}:
                service_name = SENSITIVE_PORTS[port_num]
                vuln_type = "mysql_public_port" if port_num == 3306 else "open_sensitive_port"

                if vuln_type not in seen_types:
                    vulns.append(self._make_vuln(
                        vuln_type=vuln_type,
                        evidence=f"{service_name} (port {port_num}) is open and reachable",
                        affected_component=service_name,
                        port=port_num,
                    ))
                    seen_types.add(vuln_type)

            # Detect outdated Apache
            if "apache" in product.lower() and "apache_outdated" not in seen_types:
                vulns.append(self._make_vuln(
                    vuln_type="apache_outdated",
                    evidence=f"Apache detected: {product}",
                    affected_component="apache2",
                    port=port_num,
                ))
                seen_types.add("apache_outdated")

            # Detect outdated Nginx
            if "nginx" in product.lower() and "nginx_outdated" not in seen_types:
                vulns.append(self._make_vuln(
                    vuln_type="nginx_outdated",
                    evidence=f"Nginx detected: {product}",
                    affected_component="nginx",
                    port=port_num,
                ))
                seen_types.add("nginx_outdated")

        return vulns

    @staticmethod
    def _make_vuln(
        vuln_type: str,
        evidence: str,
        affected_component: str,
        port: int,
    ) -> dict:
        """Create a minimal vulnerability dict for nmap-detected issues."""
        return {
            "type": vuln_type,
            "evidence": evidence,
            "affected_component": affected_component,
            "detected_port": port,
            "detected_by": "nmap_scanner",
        }


# ── Standalone test ────────────────────────────────────────────
if __name__ == "__main__":
    import json
    import os
    import sys
    logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")

    target = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    print(f"\n[NmapScanner] Scanning {target}...\n")

    scanner = NmapScanner(target=target)
    result = scanner.scan()

    if result["error"]:
        print(f"[ERROR] {result['error']}")
    else:
        print(f"  Open ports ({len(result['open_ports'])}):")
        for p in result["open_ports"]:
            sensitive = " <-- SENSITIVE" if p["is_sensitive"] else ""
            print(f"    {p['port']}/{p['protocol']}  {p['service']}  {p['product']} {p['version']}{sensitive}")

        print(f"\n  Network vulns detected ({len(result['vulnerabilities'])}):")
        for v in result["vulnerabilities"]:
            print(f"    [{v['type']}] {v['evidence']}")
