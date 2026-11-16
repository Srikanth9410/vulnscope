"""Deterministic Scorer (Checkpoints 2.1 / 5.1).

Tier assignment is a pure function of an evidence view plus fixed weights.
It is deliberately NOT an agent: identical inputs always produce identical
tiers, which is the reproducibility a probabilistic model cannot offer.
LLM agents propose interpretations of the evidence; the Scorer disposes.

Hard rules (checked before any weighting):
    * KEV-listed  =>  "patch now", always.
    * A tier-5 (unconfirmed) signal contributes ZERO points: per Checkpoint
      3.1 it can trigger corroboration, but can never move a tier on its own.

Confidence (Checkpoint 6.1) is computed from evidence coverage and source
agreement — never generated as prose.
"""

from __future__ import annotations

from dataclasses import dataclass

PATCH_NOW = "patch now"
WATCH = "watch"
DEFER = "defer"

# Fixed weights. Changing these is a design change, not a runtime decision.
WEIGHTS = {
    "cvss_critical": 40,   # CVSS >= 9.0
    "cvss_high": 30,       # CVSS 7.0 - 8.9
    "cvss_medium": 15,     # CVSS 4.0 - 6.9
    "cvss_low": 5,         # CVSS 0.1 - 3.9
    "epss_very_high": 25,  # EPSS >= 0.50
    "epss_high": 15,       # EPSS 0.10 - 0.49
    "epss_elevated": 8,    # EPSS 0.01 - 0.09
    "confirmed_exploitation": 25,  # tier 1-2 evidence of exploitation
    "exposure_many": 10,   # >= 3 inventory assets affected
    "exposure_some": 6,    # 1-2 inventory assets affected
}

THRESHOLD_PATCH_NOW = 60
THRESHOLD_WATCH = 30


@dataclass(frozen=True)
class ScoreInputs:
    """The evidence view the Scorer sees. Frozen so a scored view is auditable."""

    cvss: float | None
    epss: float | None
    kev_listed: bool
    exposure_assets: int
    confirmed_exploitation: bool
    unconfirmed_warning: bool = False  # tier-5 signal: recorded, scores 0


@dataclass(frozen=True)
class ScoreResult:
    tier: str
    points: int
    breakdown: tuple  # tuple of (component, points) for the audit trail


def _cvss_points(cvss: float | None) -> int:
    if cvss is None:
        return 0
    if cvss >= 9.0:
        return WEIGHTS["cvss_critical"]
    if cvss >= 7.0:
        return WEIGHTS["cvss_high"]
    if cvss >= 4.0:
        return WEIGHTS["cvss_medium"]
    if cvss > 0:
        return WEIGHTS["cvss_low"]
    return 0


def _epss_points(epss: float | None) -> int:
    if epss is None:
        return 0
    if epss >= 0.50:
        return WEIGHTS["epss_very_high"]
    if epss >= 0.10:
        return WEIGHTS["epss_high"]
    if epss >= 0.01:
        return WEIGHTS["epss_elevated"]
    return 0


def score(inputs: ScoreInputs) -> ScoreResult:
    """Assign a tier. Pure function: same inputs -> same result, always."""
    if inputs.kev_listed:
        return ScoreResult(
            tier=PATCH_NOW,
            points=100,
            breakdown=(("kev_listed_hard_rule", 100),),
        )

    parts = [
        ("cvss", _cvss_points(inputs.cvss)),
        ("epss", _epss_points(inputs.epss)),
        ("confirmed_exploitation",
         WEIGHTS["confirmed_exploitation"] if inputs.confirmed_exploitation else 0),
        ("exposure",
         WEIGHTS["exposure_many"] if inputs.exposure_assets >= 3
         else WEIGHTS["exposure_some"] if inputs.exposure_assets >= 1 else 0),
        # Recorded for audit; deliberately zero (Checkpoint 3.1).
        ("unconfirmed_warning_tier5", 0),
    ]
    total = sum(p for _, p in parts)
    if total >= THRESHOLD_PATCH_NOW:
        tier = PATCH_NOW
    elif total >= THRESHOLD_WATCH:
        tier = WATCH
    else:
        tier = DEFER
    return ScoreResult(tier=tier, points=total, breakdown=tuple(parts))


def compute_confidence(coverage: float, unresolved_conflicts: int) -> tuple[str, float]:
    """Confidence from evidence coverage and source agreement (Checkpoint 6.1).

    coverage: fraction of the expected evidence checks that produced data
    (CVSS known, EPSS known, KEV status known, retrieval performed, exposure
    checked). Agreement: any unresolved conflict halves the score.
    """
    agreement = 0.5 if unresolved_conflicts > 0 else 1.0
    value = round(coverage * agreement, 3)
    if value >= 0.8:
        label = "high"
    elif value >= 0.5:
        label = "medium"
    else:
        label = "low"
    return label, value
