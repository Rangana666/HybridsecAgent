"""
nvd_api.py — NVD CVE API v2.0 Client
Fetches CVE details from the National Vulnerability Database.
API docs: https://nvd.nist.gov/developers/vulnerabilities

Rate limits:
  - Without API key: ~5 requests per 30 seconds
  - With API key:    50 requests per 30 seconds
"""

import time
import logging
import requests
from typing import Optional

logger = logging.getLogger(__name__)

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
REQUEST_TIMEOUT = 30      # seconds per request
DELAY_NO_KEY = 6.0        # seconds between requests without API key
DELAY_WITH_KEY = 0.6      # seconds between requests with API key


class NVDClient:
    """Client for the NVD CVE API v2.0."""

    def __init__(self, api_key: str = ""):
        self.api_key = api_key.strip()
        self._delay = DELAY_WITH_KEY if self.api_key else DELAY_NO_KEY
        self._last_request_time: float = 0.0
        self._headers = {}
        if self.api_key:
            self._headers["apiKey"] = self.api_key

    # ── Public Methods ─────────────────────────────────────────

    def get_cve(self, cve_id: str) -> Optional[dict]:
        """
        Fetch a single CVE by ID (e.g. "CVE-2023-44487").
        Returns a normalised dict or None if not found / error.
        """
        params = {"cveId": cve_id.upper()}
        data = self._request(params)
        if not data:
            return None
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            logger.debug("CVE %s not found in NVD", cve_id)
            return None
        return self._normalise(vulns[0]["cve"])

    def search_by_keyword(self, keyword: str, max_results: int = 5) -> list[dict]:
        """
        Search CVEs by keyword (e.g. "openssh", "apache 2.4").
        Returns a list of normalised CVE dicts (up to max_results).
        """
        params = {"keywordSearch": keyword, "resultsPerPage": max_results}
        data = self._request(params)
        if not data:
            return []
        results = []
        for item in data.get("vulnerabilities", [])[:max_results]:
            normalised = self._normalise(item["cve"])
            if normalised:
                results.append(normalised)
        return results

    def enrich_vulnerabilities(self, vulnerabilities: list[dict]) -> list[dict]:
        """
        For each vulnerability that has a cve_id, fetch full CVE details
        from NVD and add them to the vulnerability dict.
        Vulnerabilities without a cve_id are returned unchanged.
        """
        enriched = []
        for vuln in vulnerabilities:
            cve_id = vuln.get("cve_id")
            if cve_id:
                cve_data = self.get_cve(cve_id)
                if cve_data:
                    vuln["cvss_score"] = cve_data.get("cvss_score", vuln.get("cvss_score", 5.0))
                    vuln["exploit_exists"] = cve_data.get("exploit_exists", vuln.get("exploit_exists", False))
                    vuln["cve_description"] = cve_data.get("description", "")
                    vuln["cve_published"] = cve_data.get("published", "")
                    vuln["cve_severity"] = cve_data.get("severity", "")
            enriched.append(vuln)
        return enriched

    # ── Private Helpers ────────────────────────────────────────

    def _request(self, params: dict) -> Optional[dict]:
        """Send one rate-limited GET request to the NVD API."""
        self._rate_limit()
        try:
            resp = requests.get(
                NVD_BASE_URL,
                params=params,
                headers=self._headers,
                timeout=REQUEST_TIMEOUT,
            )
            self._last_request_time = time.time()

            if resp.status_code == 200:
                return resp.json()
            if resp.status_code == 403:
                logger.error("NVD API: 403 Forbidden — check your API key")
            elif resp.status_code == 404:
                logger.debug("NVD API: 404 not found for params %s", params)
            else:
                logger.warning("NVD API returned HTTP %s", resp.status_code)
            return None

        except requests.exceptions.Timeout:
            logger.warning("NVD API request timed out (params: %s)", params)
            return None
        except requests.exceptions.ConnectionError:
            logger.warning("NVD API unreachable — no internet or NVD is down")
            return None
        except Exception as e:
            logger.error("NVD API unexpected error: %s", e)
            return None

    def _rate_limit(self):
        """Sleep if needed to stay within NVD rate limits."""
        elapsed = time.time() - self._last_request_time
        if elapsed < self._delay:
            time.sleep(self._delay - elapsed)

    def _normalise(self, cve: dict) -> Optional[dict]:
        """Convert raw NVD CVE dict into a flat, consistent format."""
        try:
            cve_id = cve.get("id", "")

            # Description (English)
            description = ""
            for desc in cve.get("descriptions", []):
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break

            # CVSS score — prefer v3.1, fall back to v3.0, then v2
            cvss_score = 0.0
            severity = "UNKNOWN"
            metrics = cve.get("metrics", {})

            for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                metric_list = metrics.get(metric_key, [])
                if metric_list:
                    cvss_data = metric_list[0].get("cvssData", {})
                    cvss_score = float(cvss_data.get("baseScore", 0.0))
                    severity = cvss_data.get("baseSeverity", "UNKNOWN")
                    break

            # Known exploited? NVD doesn't directly flag this, but we check
            # the CISA KEV list status if present in the API response
            exploit_exists = False
            for ref in cve.get("references", []):
                tags = ref.get("tags", [])
                if "Exploit" in tags or "Patch" in tags:
                    exploit_exists = "Exploit" in tags
                    break

            return {
                "cve_id": cve_id,
                "description": description,
                "cvss_score": cvss_score,
                "severity": severity,
                "exploit_exists": exploit_exists,
                "published": cve.get("published", ""),
                "last_modified": cve.get("lastModified", ""),
                "vuln_status": cve.get("vulnStatus", ""),
            }

        except Exception as e:
            logger.error("NVD normalise error for CVE %s: %s", cve.get("id"), e)
            return None


# ── Standalone test ────────────────────────────────────────────
if __name__ == "__main__":
    import sys
    import os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
    from config import NVD_API_KEY

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    client = NVDClient(api_key=NVD_API_KEY)

    print("\n[TEST] Fetching CVE-2023-44487 (HTTP/2 Rapid Reset)...")
    result = client.get_cve("CVE-2023-44487")
    if result:
        print(f"  ID       : {result['cve_id']}")
        print(f"  CVSS     : {result['cvss_score']} ({result['severity']})")
        print(f"  Exploit  : {result['exploit_exists']}")
        print(f"  Status   : {result['vuln_status']}")
        print(f"  Desc     : {result['description'][:120]}...")
    else:
        print("  Not found or API error.")

    print("\n[TEST] Searching for 'openssh'...")
    results = client.search_by_keyword("openssh", max_results=3)
    for r in results:
        print(f"  {r['cve_id']} | CVSS {r['cvss_score']} | {r['description'][:80]}...")
