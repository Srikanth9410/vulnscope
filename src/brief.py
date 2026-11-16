"""Brief Writer (Checkpoints 5.1 / 6.1).

Turns the scored decision into the analyst brief: tier, confidence, key
evidence with checkable citations (source, date, trust tier — drawn only
from the shared evidence store), recorded conflicts, and the human
intervention triggers that fired.

Every brief carries `requires_human_approval: true`: the system recommends,
it never acts. Any "patch now" is itself an intervention trigger.
"""

from __future__ import annotations

from .scorer import PATCH_NOW
from .store import EvidenceStore


def intervention_triggers(*, tier: str, confidence_label: str, cvss,
                          epss, kev_listed: bool, any_exploit_signal: bool,
                          unresolved_conflict: bool, retrieval_empty: bool,
                          tot_disagreement: bool) -> list[str]:
    """The six Checkpoint 6.1 triggers, evaluated by rule."""
    triggers = []
    if confidence_label == "low":
        triggers.append("1. low-confidence verdict")
    if (cvss or 0) >= 7.0 and epss is None and not kev_listed \
            and not any_exploit_signal:
        triggers.append("2. high-CVSS CVE with no exploit data")
    if unresolved_conflict:
        triggers.append("3. unresolved conflict between authoritative sources")
    if retrieval_empty:
        triggers.append("4. empty retrieval — brief rests on API facts alone")
    if tot_disagreement:
        triggers.append("5. Tree-of-Thought disagreement after the round cap")
    if tier == PATCH_NOW:
        triggers.append('6. "patch now" recommendation — explicit human '
                        "approval required")
    return triggers


def render(result: dict) -> str:
    """Render the analyst brief as Markdown from a triage result dict."""
    store: EvidenceStore = result["store"]
    lines = [
        f"# VulnScope Brief — {result['cve_id']}",
        "",
        f"**Tier: {result['tier'].upper()}** "
        f"(score {result['points']}/100)  |  "
        f"**Confidence: {result['confidence_label']}** "
        f"({result['confidence_value']})  |  "
        f"**Path: {result['path']}**"
        + (f", {result['rounds']} round(s)" if result["path"] == "tot" else "")
        + f"  |  **Latency: {result['latency_s']}s**",
        "",
        "## Key evidence",
        "",
        "| Fact | Source | Date | Trust tier |",
        "|---|---|---|---|",
    ]
    for item in store.items:
        if item.kind == "chunk":
            continue  # chunks are cited separately below
        lines.append(f"| {item.fact} | {item.source} | {item.date or '—'} "
                     f"| {item.trust_tier} |")
    chunks = store.facts("chunk")
    if chunks:
        lines += ["", "## Retrieved documentary evidence", ""]
        for item in chunks:
            lines.append(f"- [{item.source}, {item.date or 'n.d.'}, "
                         f"tier {item.trust_tier}] {item.fact}")
    if result.get("retrieval_empty"):
        lines += ["", "> **No documentary evidence found.** Retrieval "
                      "returned empty after the metadata pre-filter and "
                      "similarity floor; this brief rests on API facts "
                      "alone (Checkpoint 3.1 honest-gap rule)."]

    lines += ["", "## Conflicts", ""]
    if store.conflicts:
        for c in store.conflicts:
            status = (f"resolved — {c.resolution}" if c.resolved
                      else "**UNRESOLVED**")
            positions = "; ".join(f"{s}: {p}" for s, p in c.positions.items())
            lines.append(f"- **{c.topic}** — {positions} → {status}")
    else:
        lines.append("- None recorded.")

    if result.get("tot_detail"):
        d = result["tot_detail"]
        lines += ["", "## Decision node (Tree-of-Thought)", ""]
        for ev in d["evaluations"]:
            lines.append(
                f"- {ev.hyp_id} ({ev.stance}): quality {ev.quality}, "
                f"consistency {ev.consistency}, coverage {ev.coverage}, "
                f"total {ev.total}" + (" — PRUNED (hard-fact contradiction)"
                                       if ev.pruned else ""))
        lines.append(f"- Outcome: {d['outcome']}")

    lines += ["", "## Scorer breakdown", ""]
    for name, pts in result["breakdown"]:
        lines.append(f"- {name}: {pts}")
    lines += [f"- **total: {result['points']}** → {result['tier']}", ""]

    lines += ["## Human oversight", ""]
    lines.append("requires_human_approval: true")
    if result["triggers"]:
        lines.append("")
        lines.append("Intervention triggers fired:")
        for t in result["triggers"]:
            lines.append(f"- {t}")
    if result.get("escalation"):
        lines += ["", f"**Escalation:** {result['escalation']}"]
    lines += ["", "---",
              "*Prototype brief. All data public (NVD, EPSS, CISA KEV, "
              "MITRE CWE) or synthetic (asset inventory). The system "
              "recommends; a human analyst owns the decision.*"]
    return "\n".join(lines) + "\n"
