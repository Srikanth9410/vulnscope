"""Evidence Collector — the tool layer (Checkpoint 5.1).

Pulls hard facts only, no interpretation, through three public read-only APIs
plus the synthetic asset inventory:

    * NVD  — CVSS, description, CWE, references, affected products (CPE)
    * EPSS — exploitation probability (FIRST.org)
    * CISA KEV — known-exploited listing (whole feed, cached)
    * data/assets_synthetic.csv — internal exposure

Every live response is cached under data/cache/ keyed by CVE ID, so re-runs
are identical and the pipeline works offline (`--offline`) from the cache.
No tool here writes to the network; GET requests only.
"""

from __future__ import annotations

import csv
import json
import re
import time
from pathlib import Path

import requests

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CACHE = ROOT / "data" / "cache"
DEFAULT_ASSETS = ROOT / "data" / "assets_synthetic.csv"

_NVD_MIN_INTERVAL = 6.0  # keyless NVD limit is 5 requests / 30 s
_last_nvd_call = 0.0


class CollectorError(Exception):
    """A data source could not be reached and no cache entry exists."""


def _version_key(v: str) -> tuple:
    """Loose dotted-version key for range comparisons ('2019 CU11' -> words)."""
    parts = re.split(r"[.\-_ ]+", str(v))
    key = []
    for p in parts:
        key.append((0, int(p), "") if p.isdigit() else (1, 0, p.lower()))
    return tuple(key)


def _version_in_range(version: str, match: dict) -> bool:
    """Evaluate NVD cpeMatch version bounds against an asset version."""
    vk = _version_key(version)
    try:
        if "versionStartIncluding" in match and vk < _version_key(match["versionStartIncluding"]):
            return False
        if "versionStartExcluding" in match and vk <= _version_key(match["versionStartExcluding"]):
            return False
        if "versionEndIncluding" in match and vk > _version_key(match["versionEndIncluding"]):
            return False
        if "versionEndExcluding" in match and vk >= _version_key(match["versionEndExcluding"]):
            return False
    except Exception:
        return True  # unparseable bounds: treat as potentially exposed
    return True


# CPE product -> inventory product aliases for products whose CPE names do
# not token-match the inventory names.
_PRODUCT_ALIASES = {
    "log4j": "apache log4j 2",
    "http_server": "apache http server",
    "exchange_server": "microsoft exchange server",
    "windows_server": "windows server",
    "netscaler_adc": "citrix netscaler adc",
    "netscaler_application_delivery_controller": "citrix netscaler adc",
    "netscaler_gateway": "citrix netscaler adc",
    "citrix_adc": "citrix netscaler adc",
    "ios_xe": "cisco ios xe",
    "xz": "xz utils",
    "mysql_server": "mysql",
    "gitlab": "gitlab ce",
    "chrome": "google chrome",
}


class Collector:
    def __init__(self, cache_dir: Path = DEFAULT_CACHE,
                 assets_path: Path = DEFAULT_ASSETS, offline: bool = False):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.assets_path = Path(assets_path)
        self.offline = offline
        self.calls: list[dict] = []  # audit: every tool call, incl. failures

    # -- plumbing ----------------------------------------------------------
    def _audit(self, tool: str, ok: bool, detail: str) -> None:
        self.calls.append({"tool": tool, "ok": ok, "detail": detail})

    def _cached(self, name: str):
        path = self.cache_dir / name
        if path.exists():
            return json.loads(path.read_text())
        return None

    def _save_cache(self, name: str, payload) -> None:
        (self.cache_dir / name).write_text(json.dumps(payload, indent=1))

    def _get_json(self, tool: str, url: str, params: dict, cache_name: str,
                  timeout: int = 60):
        cached = self._cached(cache_name)
        if cached is not None:
            self._audit(tool, True, f"cache hit {cache_name}")
            return cached
        if self.offline:
            self._audit(tool, False, f"offline, no cache for {cache_name}")
            raise CollectorError(f"{tool}: offline and no cached response")
        global _last_nvd_call
        payload, last_exc = None, None
        for attempt in range(3):  # keyless NVD intermittently returns 503
            if tool == "nvd":
                wait = _NVD_MIN_INTERVAL - (time.time() - _last_nvd_call)
                if wait > 0:
                    time.sleep(wait)
            try:
                resp = requests.get(
                    url, params=params, timeout=timeout,
                    headers={"User-Agent": "vulnscope-prototype/0.1"})
                if tool == "nvd":
                    _last_nvd_call = time.time()
                resp.raise_for_status()
                payload = resp.json()
                break
            except Exception as exc:  # network down, 4xx/5xx, bad JSON
                last_exc = exc
                if attempt < 2:
                    time.sleep(10 * (attempt + 1))
        if payload is None:
            self._audit(tool, False, f"{type(last_exc).__name__}: {last_exc}")
            raise CollectorError(f"{tool}: {last_exc}") from last_exc
        self._save_cache(cache_name, payload)
        self._audit(tool, True, f"live fetch -> {cache_name}")
        return payload

    # -- NVD ----------------------------------------------------------------
    def fetch_nvd(self, cve_id: str) -> dict:
        """Return the parsed facts VulnScope needs from the NVD entry."""
        raw = self._get_json("nvd", NVD_URL, {"cveId": cve_id},
                             f"{cve_id}_nvd.json")
        vulns = raw.get("vulnerabilities", [])
        if not vulns:
            raise CollectorError(f"nvd: no entry for {cve_id}")
        cve = vulns[0]["cve"]

        cvss, cvss_version = None, None
        metrics = cve.get("metrics", {})
        for key, label in (("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"),
                           ("cvssMetricV40", "4.0"), ("cvssMetricV2", "2.0")):
            entries = metrics.get(key)
            if entries:
                data = entries[0]["cvssData"]
                cvss, cvss_version = data.get("baseScore"), label
                break

        description = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                description = d.get("value", "")
                break

        cwes = []
        for w in cve.get("weaknesses", []):
            for d in w.get("description", []):
                if d.get("lang") == "en" and d.get("value", "").startswith("CWE-"):
                    cwes.append(d["value"])

        references = [{"url": r.get("url", ""), "tags": r.get("tags", []),
                       "source": r.get("source", "")}
                      for r in cve.get("references", [])]

        cpe_matches = []
        for cfg in cve.get("configurations", []):
            for node in cfg.get("nodes", []):
                for m in node.get("cpeMatch", []):
                    if m.get("vulnerable"):
                        cpe_matches.append(m)

        return {
            "cve_id": cve_id,
            "published": cve.get("published", "")[:10],
            "last_modified": cve.get("lastModified", "")[:10],
            "description": description,
            "cvss": cvss,
            "cvss_version": cvss_version,
            "cwes": sorted(set(cwes)),
            "references": references,
            "cpe_matches": cpe_matches,
        }

    # -- EPSS -----------------------------------------------------------------
    def fetch_epss(self, cve_id: str) -> dict:
        raw = self._get_json("epss", EPSS_URL, {"cve": cve_id},
                             f"{cve_id}_epss.json")
        data = raw.get("data", [])
        if not data:
            # A genuinely new CVE may have no EPSS score yet — an honest gap,
            # not an error (Checkpoint 3.1 trace case).
            return {"epss": None, "percentile": None, "date": None}
        row = data[0]
        return {"epss": float(row["epss"]),
                "percentile": float(row["percentile"]),
                "date": row.get("date")}

    # -- CISA KEV ---------------------------------------------------------------
    def fetch_kev(self, cve_id: str) -> dict:
        cache_name = "kev_feed.json"
        cached = self._cached(cache_name)
        if cached is not None:
            self._audit("kev", True, "cache hit kev_feed.json")
            feed = cached
        elif self.offline:
            self._audit("kev", False, "offline, no cached KEV feed")
            raise CollectorError("kev: offline and no cached feed")
        else:
            try:
                resp = requests.get(KEV_URL, timeout=60,
                                    headers={"User-Agent": "vulnscope-prototype/0.1"})
                resp.raise_for_status()
                feed = resp.json()
            except Exception as exc:
                self._audit("kev", False, f"{type(exc).__name__}: {exc}")
                raise CollectorError(f"kev: {exc}") from exc
            self._save_cache(cache_name, feed)
            self._audit("kev", True, "live fetch -> kev_feed.json")
        for v in feed.get("vulnerabilities", []):
            if v.get("cveID") == cve_id:
                return {"listed": True,
                        "date_added": v.get("dateAdded"),
                        "name": v.get("vulnerabilityName"),
                        "ransomware": v.get("knownRansomwareCampaignUse"),
                        "catalog_version": feed.get("catalogVersion")}
        return {"listed": False, "date_added": None, "name": None,
                "ransomware": None, "catalog_version": feed.get("catalogVersion")}

    # -- Asset inventory ---------------------------------------------------------
    def load_assets(self) -> list[dict]:
        with open(self.assets_path, newline="") as fh:
            return list(csv.DictReader(fh))

    def match_exposure(self, nvd: dict) -> list[dict]:
        """Assets whose product+version fall in the CVE's NVD CPE ranges."""
        assets = self.load_assets()
        matched, seen = [], set()
        for m in nvd.get("cpe_matches", []):
            criteria = m.get("criteria", "")
            parts = criteria.split(":")
            if len(parts) < 6:
                continue
            product = parts[4].replace("_", " ").lower()
            cpe_version = parts[5]
            product = _PRODUCT_ALIASES.get(parts[4].lower(), product)
            for asset in assets:
                name = asset["product"].lower()
                # Token-level matching only. Raw substring matching is unsafe:
                # Siemens' product "nx" is a substring of "nginx" but is not
                # the same product. Token containment handles multi-word
                # names ('windows server 2019' vs 'windows server').
                ptoks, ntoks = set(product.split()), set(name.split())
                contained = product == name or ptoks <= ntoks or ntoks <= ptoks
                if not contained:
                    continue
                has_bounds = any(k in m for k in (
                    "versionStartIncluding", "versionStartExcluding",
                    "versionEndIncluding", "versionEndExcluding"))
                if has_bounds:
                    ok = _version_in_range(asset["version"], m)
                elif cpe_version not in ("*", "-"):
                    ok = _version_key(asset["version"])[:len(_version_key(cpe_version))] == \
                        _version_key(cpe_version)
                else:
                    ok = True
                key = (asset["hostname"], asset["product"])
                if ok and key not in seen:
                    seen.add(key)
                    matched.append(asset)
        return matched
