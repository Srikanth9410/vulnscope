"""Evaluator (Checkpoints 4.1 / 5.1).

A separate role from the Generator: it scores each hypothesis on evidence
quality, consistency with hard facts, and constraint coverage. It never
sees the Generator's rationale — this module's functions accept hypothesis
*views* and evidence facts only, so self-grading by fluency is structurally
impossible, not just discouraged.

A branch contradicted by a hard fact (KEV status, CVSS, EPSS — values the
Generator may not reinterpret) is pruned immediately. The surviving top two
form the beam (depth 2, beam 2 per Checkpoint 4.1).
"""

from __future__ import annotations

from dataclasses import dataclass

from .generator import STANCE_ENGAGES, Hypothesis
from .scorer import ScoreInputs

W_QUALITY, W_CONSISTENCY, W_COVERAGE = 0.4, 0.4, 0.2
BEAM = 2


@dataclass
class Evaluation:
    hyp_id: str
    stance: str
    quality: float
    consistency: float
    coverage: float
    total: float
    pruned: bool = False


def _consistency(view: ScoreInputs, facts: ScoreInputs) -> float:
    """1.0 = fully consistent with hard facts; 0.0 = contradicted (prune)."""
    if view.kev_listed != facts.kev_listed:
        return 0.0
    if view.cvss != facts.cvss or view.epss != facts.epss:
        return 0.0
    score = 1.0
    if facts.exposure_assets > 0 and view.exposure_assets == 0:
        # Argues against a completed inventory check — allowed as a stance,
        # but it carries the burden of that disagreement.
        score = min(score, 0.4)
    return score


def _quality(view: ScoreInputs, facts: ScoreInputs,
             confirmation_tier: int | None) -> float:
    if view.confirmed_exploitation:
        return {1: 1.0, 2: 0.85}.get(confirmation_tier or 3, 0.7)
    if facts.confirmed_exploitation and confirmation_tier is not None \
            and confirmation_tier <= 2:
        # Discounts authoritative confirmation pending corroboration.
        return 0.4
    if facts.unconfirmed_warning:
        # Correctly refuses to treat a tier-5 signal as fact.
        return 0.65
    return 0.6  # rests on the structured facts alone


def _coverage(stance: str) -> float:
    return len(STANCE_ENGAGES.get(stance, set())) / 3.0


def evaluate(hypotheses: list[Hypothesis], facts: ScoreInputs,
             confirmation_tier: int | None) -> list[Evaluation]:
    """Score and rank hypotheses; pruned branches sort last."""
    evals = []
    for hyp in hypotheses:
        consistency = _consistency(hyp.view, facts)
        quality = _quality(hyp.view, facts, confirmation_tier)
        coverage = _coverage(hyp.stance)
        total = (W_QUALITY * quality + W_CONSISTENCY * consistency
                 + W_COVERAGE * coverage)
        evals.append(Evaluation(
            hyp_id=hyp.hyp_id, stance=hyp.stance, quality=quality,
            consistency=consistency, coverage=round(coverage, 3),
            total=round(total, 4), pruned=consistency == 0.0))
    evals.sort(key=lambda e: (e.pruned, -e.total))
    return evals


def beam(evals: list[Evaluation]) -> list[Evaluation]:
    """The surviving beam: top non-pruned evaluations, at most BEAM wide."""
    return [e for e in evals if not e.pruned][:BEAM]
