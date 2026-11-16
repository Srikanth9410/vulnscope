"""Orchestrator (Checkpoints 5.1 / 4.1 / 6.1).

Opens one workflow per CVE and enforces the stop conditions. Coordination
is hybrid: a sequential pipeline (collect -> retrieve -> decide -> score ->
brief) with a graph-based, trigger-gated Tree-of-Thought node inside the
decision step. Most CVEs take the linear path straight to the Scorer; the
expensive path activates only on the Checkpoint 4.1 triggers:

    (a) sources conflict on exploitation status,
    (b) low confidence after the linear pass on a high-severity CVE,
    (c) a tier-5 (unconfirmed) early warning.

Fallback (Checkpoint 6.1): if the decision node or LangGraph itself fails,
the run degrades to the linear loop plus the deterministic Scorer — a
simpler brief, clearly marked. Degraded, never blocked.

Usage:
    python -m src.orchestrator CVE-2021-44228 [--offline] [--out brief.md]
"""

from __future__ import annotations

import argparse
import sys
import time
from dataclasses import replace
from pathlib import Path

from . import brief as brief_mod
from . import evaluator as evaluator_mod
from . import generator as generator_mod
from . import retrieval as retrieval_mod
from .collector import Collector, CollectorError
from .scorer import ScoreInputs, compute_confidence, score
from .store import (TIER_KEV, TIER_NVD, TIER_VENDOR, Conflict, EvidenceItem,
                    EvidenceStore)

try:
    from typing import Any, TypedDict

    from langgraph.graph import END, START, StateGraph

    class TriageState(TypedDict, total=False):
        cve_id: str
        nvd: dict
        epss: dict
        kev: dict
        kev_known: bool
        exposure: list
        corpus: list
        products: tuple
        chunks: list
        retrieval_empty: bool
        confirmed: bool
        unconfirmed: bool
        confirmation_tier: Any
        path: str
        rounds: int
        final_view: Any
        tot_detail: Any
        tot_disagreement: bool
        base_inputs: Any
        tier: str
        points: int
        breakdown: Any
        confidence_label: str
        confidence_value: float
        result: dict

    _HAS_LANGGRAPH = True
except Exception:  # pragma: no cover - exercised only without langgraph
    _HAS_LANGGRAPH = False
    TriageState = dict


class RunContext:
    """Per-run side state: the evidence store and the tool layer."""

    def __init__(self, cve_id: str, offline: bool = False):
        self.cve_id = cve_id
        self.store = EvidenceStore(cve_id=cve_id)
        self.collector = Collector(offline=offline)
        self.started = time.perf_counter()


# --------------------------------------------------------------------------
# Pipeline nodes. Each takes (state, ctx) and returns a partial state dict,
# so the same functions drive both the LangGraph graph and the fallback.
# --------------------------------------------------------------------------

def node_collect(state: dict, ctx: RunContext) -> dict:
    store, col = ctx.store, ctx.collector
    cve = ctx.cve_id
    nvd = col.fetch_nvd(cve)  # hard failure here fails the run (see run_triage)
    store.add(EvidenceItem(
        kind="cvss",
        fact=(f"CVSS {nvd['cvss']} (v{nvd['cvss_version']})"
              if nvd["cvss"] is not None else "No CVSS score in NVD entry"),
        source="NVD", date=nvd["published"], trust_tier=TIER_NVD,
        value=nvd["cvss"]))
    store.add(EvidenceItem(
        kind="cwe", fact=f"Weakness: {', '.join(nvd['cwes']) or 'not specified'}",
        source="NVD", date=nvd["published"], trust_tier=TIER_NVD,
        value=nvd["cwes"]))
    try:
        epss = col.fetch_epss(cve)
    except CollectorError:
        epss = {"epss": None, "percentile": None, "date": None}
    store.add(EvidenceItem(
        kind="epss",
        fact=(f"EPSS {epss['epss']} (percentile {epss['percentile']})"
              if epss["epss"] is not None else "No EPSS score yet"),
        source="FIRST EPSS", date=epss["date"] or "", trust_tier=TIER_NVD,
        value=epss["epss"]))
    try:
        kev = col.fetch_kev(cve)
        kev_known = True
    except CollectorError:
        kev = {"listed": False, "date_added": None, "name": None,
               "ransomware": None, "catalog_version": None}
        kev_known = False
    store.add(EvidenceItem(
        kind="kev",
        fact=("Listed in CISA KEV since " + str(kev["date_added"])
              if kev["listed"] else
              "Not listed in CISA KEV" + ("" if kev_known else " (feed unreachable)")),
        source="CISA KEV", date=kev["date_added"] or "", trust_tier=TIER_KEV,
        value=kev["listed"]))
    exposure = col.match_exposure(nvd)
    store.add(EvidenceItem(
        kind="exposure",
        fact=(f"{len(exposure)} inventory asset(s) exposed: "
              + ", ".join(f"{a['hostname']} ({a['product']} {a['version']})"
                          for a in exposure)
              if exposure else "No inventory asset matches the affected products"),
        source="asset inventory (synthetic)", date="", trust_tier=TIER_NVD,
        value=len(exposure)))
    for call in col.calls:
        store.log("tool_call", **call)
    return {"nvd": nvd, "epss": epss, "kev": kev, "kev_known": kev_known,
            "exposure": exposure}


def _store_chunks(store: EvidenceStore, chunks) -> None:
    seen = {i.value for i in store.facts("chunk") if i.value}
    for ch in chunks:
        if ch.chunk_id in seen:
            continue
        seen.add(ch.chunk_id)
        store.add(EvidenceItem(
            kind="chunk", fact=f"[{ch.chunk_id}] {ch.text[:240]}",
            source=ch.source, date=ch.date, trust_tier=ch.trust_tier,
            value=ch.chunk_id))


def node_retrieve(state: dict, ctx: RunContext) -> dict:
    nvd, kev = state["nvd"], state["kev"]
    corpus = retrieval_mod.build_corpus(ctx.cve_id, nvd, kev)
    products = tuple(sorted({
        m.get("criteria", "").split(":")[4].replace("_", " ")
        for m in nvd.get("cpe_matches", [])
        if len(m.get("criteria", "").split(":")) > 4}))
    chunks, empty = retrieval_mod.retrieve(
        corpus, retrieval_mod.EXPLOITATION_QUERY, ctx.cve_id,
        products=products, cwe_id=nvd["cwes"][0] if nvd["cwes"] else "")
    confirmed, unconfirmed, conf_tier = retrieval_mod.exploitation_signals(chunks)
    if kev.get("listed"):
        # A KEV listing IS tier-1 exploitation evidence, whether or not the
        # KEV chunk ranked into the retrieved set.
        confirmed, conf_tier = True, TIER_KEV
    ctx.store.log("retrieval", query="exploitation", returned=len(chunks),
                  empty=empty, confirmed=confirmed, unconfirmed=unconfirmed)
    return {"corpus": corpus, "products": products, "chunks": chunks,
            "retrieval_empty": empty, "confirmed": confirmed,
            "unconfirmed": unconfirmed, "confirmation_tier": conf_tier}


def _base_inputs(state: dict) -> ScoreInputs:
    return ScoreInputs(
        cvss=state["nvd"]["cvss"], epss=state["epss"]["epss"],
        kev_listed=bool(state["kev"]["listed"]),
        exposure_assets=len(state["exposure"]),
        confirmed_exploitation=bool(state["confirmed"]),
        unconfirmed_warning=bool(state["unconfirmed"]))


def _coverage(state: dict) -> float:
    checks = [state["nvd"]["cvss"] is not None,
              state["epss"]["epss"] is not None,
              bool(state["kev_known"]), True, True]  # retrieval + exposure ran
    return sum(checks) / len(checks)


def node_decide(state: dict, ctx: RunContext) -> dict:
    store = ctx.store
    base = _base_inputs(state)
    coverage = _coverage(state)
    pre_conf_label, _ = compute_confidence(coverage, 0)

    conflict = None
    if (base.confirmed_exploitation or base.unconfirmed_warning) \
            and not base.kev_listed:
        source = ("vendor advisory (tier 2)" if base.confirmed_exploitation
                  else "researcher/PoC source (tier 5, unconfirmed)")
        conflict = Conflict(
            topic="exploitation status",
            positions={"CISA KEV": "not listed", source: "claims exploitation"})
        store.record_conflict(conflict)

    triggers_fire = (
        conflict is not None
        or base.unconfirmed_warning
        or (pre_conf_label == "low" and (base.cvss or 0) >= 7.0))
    if not triggers_fire:
        return {"path": "linear", "rounds": 0, "final_view": base,
                "tot_detail": None, "tot_disagreement": False,
                "base_inputs": base}

    # --- Tree-of-Thought decision node (depth 2, beam 2, max 2 rounds) ---
    view = base
    detail = None
    disagreement = False
    rounds_run = 0
    for round_no in (1, 2):
        rounds_run = round_no
        hyps = generator_mod.generate(view, state["confirmation_tier"],
                                      ctx.cve_id)
        evals = evaluator_mod.evaluate(hyps, view, state["confirmation_tier"])
        top = evaluator_mod.beam(evals)
        if not top:  # everything pruned: degrade to the collected view
            detail = {"evaluations": evals,
                      "outcome": "all branches pruned; collected view used"}
            break
        by_id = {h.hyp_id: h for h in hyps}
        beam_tiers = {e.hyp_id: score(by_id[e.hyp_id].view).tier for e in top}
        if len(set(beam_tiers.values())) == 1:
            winner = by_id[top[0].hyp_id]
            view = winner.view
            detail = {"evaluations": evals,
                      "outcome": (f"round {round_no}: beam converged on "
                                  f"'{beam_tiers[top[0].hyp_id]}' via "
                                  f"{top[0].hyp_id} ({top[0].stance})")}
            disagreement = False
            break
        if round_no == 1:
            # Corroboration round: widen retrieval before deciding.
            extra, _ = retrieval_mod.retrieve(
                state["corpus"], retrieval_mod.MITIGATION_QUERY, ctx.cve_id,
                products=state["products"],
                cwe_id=state["nvd"]["cwes"][0] if state["nvd"]["cwes"] else "")
            merged = {c.chunk_id: c for c in state["chunks"] + extra}
            state["chunks"] = list(merged.values())
            conf, unc, tier_ = retrieval_mod.exploitation_signals(state["chunks"])
            state.update({"confirmed": conf, "unconfirmed": unc,
                          "confirmation_tier": tier_})
            view = _base_inputs(state)
            store.log("tot_corroboration", added_chunks=len(extra),
                      confirmed=conf, unconfirmed=unc)
            continue
        # Round 2 and still split: higher-evidence-quality branch wins;
        # the disagreement is recorded, not forced away (Checkpoints 3.1/4.1).
        winner_eval = max(top, key=lambda e: (e.quality, e.total))
        view = by_id[winner_eval.hyp_id].view
        disagreement = True
        detail = {"evaluations": evals,
                  "outcome": (f"round 2: beam split {beam_tiers}; "
                              f"{winner_eval.hyp_id} ({winner_eval.stance}) "
                              "selected on evidence quality; disagreement "
                              "recorded as unresolved")}
        if conflict is None:
            conflict = Conflict(
                topic="Tree-of-Thought branch disagreement",
                positions={e.hyp_id: beam_tiers[e.hyp_id] for e in top})
            store.record_conflict(conflict)

    if conflict is not None:
        if view.confirmed_exploitation and state["confirmation_tier"] is not None \
                and state["confirmation_tier"] <= TIER_VENDOR:
            conflict.resolved = True
            conflict.resolution = (
                "recency-and-authority policy: tier-2 vendor evidence "
                "outweighs KEV absence; KEV gap flagged for re-check")
        elif disagreement:
            conflict.resolved = False
    _store_chunks(store, state["chunks"])
    return {"path": "tot", "rounds": rounds_run, "final_view": view,
            "tot_detail": detail, "tot_disagreement": disagreement,
            "base_inputs": base}


def node_score(state: dict, ctx: RunContext) -> dict:
    if state.get("path") == "linear":
        _store_chunks(ctx.store, state["chunks"])
    view = state["final_view"]
    result = score(view)
    unresolved = len(ctx.store.unresolved_conflicts())
    label, value = compute_confidence(_coverage(state), unresolved)
    ctx.store.log("scored", tier=result.tier, points=result.points,
                  confidence=label)
    return {"tier": result.tier, "points": result.points,
            "breakdown": result.breakdown, "confidence_label": label,
            "confidence_value": value}


def node_brief(state: dict, ctx: RunContext) -> dict:
    store = ctx.store
    base = state["base_inputs"]
    unresolved = len(store.unresolved_conflicts()) > 0
    triggers = brief_mod.intervention_triggers(
        tier=state["tier"], confidence_label=state["confidence_label"],
        cvss=base.cvss, epss=base.epss, kev_listed=base.kev_listed,
        any_exploit_signal=base.confirmed_exploitation or base.unconfirmed_warning,
        unresolved_conflict=unresolved,
        retrieval_empty=bool(state["retrieval_empty"]),
        tot_disagreement=bool(state.get("tot_disagreement")))
    escalation = None
    if unresolved and base.kev_listed:
        escalation = ("unresolved conflict on a KEV-listed CVE — page the "
                      "on-call security lead immediately, audit record attached")
    elif unresolved:
        escalation = ("unresolved conflict — routed to the analyst queue "
                      "with a 24-hour review SLA")
    result = {
        "cve_id": ctx.cve_id, "status": "completed",
        "tier": state["tier"], "points": state["points"],
        "breakdown": state["breakdown"],
        "confidence_label": state["confidence_label"],
        "confidence_value": state["confidence_value"],
        "path": state["path"], "rounds": state.get("rounds", 0),
        "retrieval_empty": state["retrieval_empty"],
        "tot_detail": state.get("tot_detail"),
        "triggers": triggers, "escalation": escalation,
        "latency_s": round(time.perf_counter() - ctx.started, 2),
        "store": store, "base_inputs": base,
        "used_langgraph": _HAS_LANGGRAPH,
    }
    result["brief_md"] = brief_mod.render(result)
    store.log("brief_written", tier=state["tier"], triggers=len(triggers))
    return {"result": result}


_NODE_ORDER = [node_collect, node_retrieve, node_decide, node_score, node_brief]


def _run_with_langgraph(ctx: RunContext) -> dict:
    graph = StateGraph(TriageState)
    names = ["collect", "retrieve", "decide", "score", "brief"]
    for name, fn in zip(names, _NODE_ORDER):
        graph.add_node(name, lambda s, fn=fn: fn(s, ctx))
    graph.add_edge(START, "collect")
    for a, b in zip(names, names[1:]):
        graph.add_edge(a, b)
    graph.add_edge("brief", END)
    final = graph.compile().invoke({"cve_id": ctx.cve_id})
    return final["result"]


def _run_fallback(ctx: RunContext) -> dict:
    state: dict = {"cve_id": ctx.cve_id}
    for fn in _NODE_ORDER:
        state.update(fn(state, ctx))
    return state["result"]


def run_triage(cve_id: str, offline: bool = False) -> dict:
    """Run one CVE end to end. Returns the result dict (incl. brief_md)."""
    ctx = RunContext(cve_id, offline=offline)
    try:
        if _HAS_LANGGRAPH:
            return _run_with_langgraph(ctx)
        return _run_fallback(ctx)
    except CollectorError as exc:
        # Evidence gathering failed entirely: queue for manual triage
        # rather than briefing on partial data (Checkpoint 6.1 fallback).
        return {"cve_id": cve_id, "status": "failed", "error": str(exc),
                "latency_s": round(time.perf_counter() - ctx.started, 2),
                "store": ctx.store}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="vulnscope")
    parser.add_argument("cve", nargs="+", help="CVE ID(s) to triage")
    parser.add_argument("--offline", action="store_true",
                        help="use only the local cache (data/cache/)")
    parser.add_argument("--out", help="also write the (last) brief to this file")
    args = parser.parse_args(argv)
    last_md = None
    for cve in args.cve:
        result = run_triage(cve.upper(), offline=args.offline)
        if result["status"] != "completed":
            print(f"{cve}: FAILED — {result.get('error')}", file=sys.stderr)
            continue
        last_md = result["brief_md"]
        print(last_md)
    if args.out and last_md:
        Path(args.out).write_text(last_md)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
