"""Scorer tests: determinism and the hard rules from the checkpoints.

Run:  python -m pytest tests/ -q
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.scorer import (DEFER, PATCH_NOW, WATCH, ScoreInputs,  # noqa: E402
                        compute_confidence, score)


def inputs(**kw) -> ScoreInputs:
    base = dict(cvss=None, epss=None, kev_listed=False, exposure_assets=0,
                confirmed_exploitation=False, unconfirmed_warning=False)
    base.update(kw)
    return ScoreInputs(**base)


def test_determinism_same_inputs_same_tier():
    case = inputs(cvss=9.8, epss=0.42, exposure_assets=2,
                  confirmed_exploitation=True)
    results = {score(case) for _ in range(50)}
    assert len(results) == 1  # identical inputs -> identical result, always


def test_kev_listed_always_patch_now():
    # Even with nothing else known, KEV listing is decisive (hard rule).
    assert score(inputs(kev_listed=True)).tier == PATCH_NOW
    assert score(inputs(kev_listed=True, cvss=2.0, epss=0.0)).tier == PATCH_NOW


def test_low_epss_no_kev_not_patch_now():
    low = inputs(cvss=3.1, epss=0.001, exposure_assets=0)
    assert score(low).tier == DEFER
    moderate = inputs(cvss=5.0, epss=0.005, exposure_assets=1)
    assert score(moderate).tier != PATCH_NOW


def test_tier5_warning_alone_cannot_move_tier():
    # Checkpoint 3.1: an unconfirmed signal scores zero points on its own.
    warned = inputs(cvss=9.8, epss=None, unconfirmed_warning=True)
    plain = inputs(cvss=9.8, epss=None)
    assert score(warned).points == score(plain).points
    assert score(warned).tier == WATCH  # severity alone holds at watch


def test_retrieval_evidence_flips_watch_to_patch_now():
    # The Checkpoint 3.1 trace case: CVSS 9.8, no KEV, no EPSS sits at watch
    # until confirmed exploitation evidence arrives.
    before = inputs(cvss=9.8, epss=None)
    after = inputs(cvss=9.8, epss=None, confirmed_exploitation=True)
    assert score(before).tier == WATCH
    assert score(after).tier == PATCH_NOW


def test_high_epss_and_severity_patch_now_without_kev():
    case = inputs(cvss=9.8, epss=0.91, exposure_assets=1)
    assert score(case).tier == PATCH_NOW


def test_confidence_from_coverage_and_agreement():
    assert compute_confidence(1.0, 0)[0] == "high"
    assert compute_confidence(1.0, 1)[0] == "medium"  # conflict halves it
    assert compute_confidence(0.4, 0)[0] == "low"
