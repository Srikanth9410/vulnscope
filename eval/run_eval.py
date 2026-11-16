"""Prototype evaluation (Checkpoint 6.1 framework, honestly scoped).

Runs a fixed set of CVEs through the full pipeline and reports the metrics
a single prototype run can actually measure:

    * task completion rate   — briefs produced vs runs attempted
    * latency                — end-to-end seconds per CVE (live first run;
                               includes NVD's keyless rate-limit pacing)
    * KEV agreement          — of KEV-listed CVEs, the fraction the system
                               tiers "patch now" (must be 100%: hard rule)
    * path split             — linear vs trigger-gated ToT runs

NOT measurable in a prototype run, and therefore not claimed here:
    * time-lagged KEV accuracy (needs 90 days of maturation),
    * false-negative rate on watch/defer (needs the same maturation),
    * analyst override rate (needs analysts).

Usage:  python eval/run_eval.py [--offline]   (writes eval/results.md)
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.orchestrator import run_triage  # noqa: E402
from src.scorer import PATCH_NOW  # noqa: E402

EVAL_CVES = [
    "CVE-2021-44228",  # Log4Shell — KEV, EPSS ~1.0, Log4j in inventory
    "CVE-2017-0144",   # EternalBlue — KEV, Windows in inventory
    "CVE-2019-0708",   # BlueKeep — KEV, Windows RDP
    "CVE-2021-34527",  # PrintNightmare — KEV, Windows spooler
    "CVE-2023-4966",   # Citrix Bleed — KEV, NetScaler in inventory
    "CVE-2017-5638",   # Struts OGNL — KEV, Struts in inventory
    "CVE-2021-41773",  # Apache path traversal — KEV, httpd in inventory
    "CVE-2023-20198",  # Cisco IOS XE — KEV, IOS XE in inventory
    "CVE-2024-3094",   # XZ backdoor — NOT KEV, EPSS ~0.91, XZ in inventory
    "CVE-2020-15103",  # low-signal case — NOT KEV, EPSS ~0.01
]


def main() -> int:
    offline = "--offline" in sys.argv
    rows, failures = [], 0
    started = time.perf_counter()
    for cve in EVAL_CVES:
        r = run_triage(cve, offline=offline)
        if r["status"] != "completed":
            failures += 1
            rows.append((cve, "FAILED", r.get("error", "?"), "-", "-",
                         r["latency_s"]))
            continue
        kev = r["base_inputs"].kev_listed
        rows.append((cve, r["tier"], "yes" if kev else "no", r["path"],
                     r["confidence_label"], r["latency_s"]))
    wall = round(time.perf_counter() - started, 1)

    done = [r for r in rows if r[1] != "FAILED"]
    kev_rows = [r for r in done if r[2] == "yes"]
    kev_agree = (sum(1 for r in kev_rows if r[1] == PATCH_NOW)
                 / len(kev_rows)) if kev_rows else 0.0
    lat = sorted(r[5] for r in done)
    median = lat[len(lat) // 2] if lat else 0
    tot = sum(1 for r in done if r[3] == "tot")

    out = [
        "# VulnScope prototype evaluation — results",
        "",
        f"Mode: {'offline (cache)' if offline else 'live APIs + cache'}  |  "
        f"Set: {len(EVAL_CVES)} CVEs  |  Wall time: {wall}s",
        "",
        "| CVE | Tier | KEV-listed | Path | Confidence | Latency (s) |",
        "|---|---|---|---|---|---|",
    ]
    for cve, tier, kev, path, conf, secs in rows:
        out.append(f"| {cve} | {tier} | {kev} | {path} | {conf} | {secs} |")
    out += [
        "",
        "## Metrics (measurable in a prototype run)",
        "",
        f"- **Task completion rate:** {len(done)}/{len(rows)} "
        f"({100 * len(done) / len(rows):.0f}%) — target ≥95% (Checkpoint 6.1)",
        f"- **KEV agreement:** {sum(1 for r in kev_rows if r[1] == PATCH_NOW)}"
        f"/{len(kev_rows)} KEV-listed CVEs tiered \"patch now\" "
        f"({100 * kev_agree:.0f}%) — 100% expected; KEV listing is a hard rule",
        f"- **Median latency:** {median}s per CVE "
        f"(linear-path target <120s, Checkpoint 6.1)",
        f"- **Path split:** {len(done) - tot} linear, {tot} Tree-of-Thought",
        "",
        "## Not measured (by design, not omission)",
        "",
        "- Time-lagged KEV accuracy and the watch/defer false-negative rate "
        "require 90 days of outcome maturation (Checkpoint 6.1).",
        "- Analyst override rate requires analysts reviewing briefs.",
        "",
    ]
    text = "\n".join(out)
    (Path(__file__).parent / "results.md").write_text(text)
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
