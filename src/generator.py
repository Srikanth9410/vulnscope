"""Generator (Checkpoints 4.1 / 5.1).

At the tier-decision step the Generator proposes up to three competing tier
hypotheses — distinct interpretive stances toward the SAME evidence. Per
Checkpoint 4.1 the strongest contrary stance is always included when it
applies, so the tree cannot collapse into expensive theater.

Default path is a deterministic fallback: stances are derived from the
evidence by fixed rules, so the graph runs end to end with zero secrets.
If OPENROUTER_API_KEY is set, an LLM (free-tier model) may write the
one-sentence rationale for each stance — narrative only. Scores and tiers
never come from the model; the deterministic Evaluator and Scorer decide.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, replace

import requests

from .scorer import ScoreInputs

OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
OPENROUTER_MODEL = "meta-llama/llama-3.3-70b-instruct:free"

# Which of the Evaluator's constraints (severity, exposure, confidence) each
# stance engages (Checkpoint 4.1, branch definitions).
STANCE_ENGAGES = {
    "exploitation_credible": {"severity", "exposure"},
    "signal_unconfirmed": {"confidence"},
    "exposure_fails": {"exposure"},
}


@dataclass
class Hypothesis:
    hyp_id: str
    stance: str
    view: ScoreInputs          # the evidence interpretation this stance implies
    rationale: str = ""        # narrative only — the Evaluator never sees this


def _llm_rationale(stance: str, base: ScoreInputs, cve_id: str) -> str | None:
    """Optional OpenRouter narrative. Returns None on any failure."""
    key = os.environ.get("OPENROUTER_API_KEY")
    if not key:
        return None
    prompt = (
        f"In one sentence, state the '{stance}' reading of the evidence for "
        f"{cve_id} (CVSS {base.cvss}, EPSS {base.epss}, KEV listed: "
        f"{base.kev_listed}, exposed assets: {base.exposure_assets}, "
        f"confirmed exploitation: {base.confirmed_exploitation}, "
        f"unconfirmed warning: {base.unconfirmed_warning}).")
    try:
        resp = requests.post(
            OPENROUTER_URL,
            headers={"Authorization": f"Bearer {key}"},
            json={"model": OPENROUTER_MODEL,
                  "messages": [{"role": "user", "content": prompt}]},
            timeout=30)
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"].strip()
    except Exception:
        return None


_TEMPLATES = {
    "exploitation_credible":
        "Treat the exploitation evidence as credible and proceed on the "
        "collected facts, including the exposure check.",
    "signal_unconfirmed":
        "The exploitation signal is not confirmed by an authoritative source; "
        "hold the interpretation at unconfirmed and seek corroboration.",
    "exposure_fails":
        "Test whether the affected product is actually deployed; if the "
        "exposure check fails, severity alone does not justify urgency.",
}


def generate(base: ScoreInputs, confirmation_tier: int | None,
             cve_id: str) -> list[Hypothesis]:
    """Propose the applicable stances for this evidence set (max 3)."""
    hyps: list[Hypothesis] = []

    def add(stance: str, view: ScoreInputs) -> None:
        rationale = _llm_rationale(stance, base, cve_id) or _TEMPLATES[stance]
        hyps.append(Hypothesis(hyp_id=f"H{len(hyps) + 1}", stance=stance,
                               view=view, rationale=rationale))

    if (base.kev_listed or base.confirmed_exploitation
            or base.unconfirmed_warning or (base.epss or 0) >= 0.10):
        add("exploitation_credible", base)
    if base.unconfirmed_warning or (base.confirmed_exploitation
                                    and confirmation_tier == 2):
        # Contrary stance (required by Checkpoint 4.1 when it applies):
        # discount the not-yet-authoritative confirmation.
        add("signal_unconfirmed", replace(base, confirmed_exploitation=False))
    if base.exposure_assets > 0:
        add("exposure_fails", replace(base, exposure_assets=0))
    if not hyps:
        add("exploitation_credible", base)
    return hyps
