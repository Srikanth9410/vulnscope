# VulnScope — Autonomous CVE Triage with Deterministic Scoring and Human Oversight

A working prototype built for the CMU Agentic AI capstone. VulnScope triages
newly published CVEs for a security team: for each vulnerability it gathers
evidence (severity, known-exploitation status, exploitation probability,
documentary evidence, internal exposure), assigns a patching tier —
**patch now / watch / defer** — and writes a short analyst brief. The system
recommends; it never acts. Every brief carries a human-approval gate.

## Why this design

A single agent doing all of this in one loop has three structural weaknesses:
self-confirmation (the path that forms the first impression also gathers the
evidence), mixed evidence types (hard API facts vs. unstructured advisory
text), and no independent check on the tier verdict. VulnScope answers each
with role separation:

- **Five LLM-era roles, one deterministic service.** Orchestrator, Evidence
  Collector, Retrieval Agent, Generator, Evaluator, Brief Writer — plus a
  **Scorer that is deliberately not an agent**: tier assignment is a pure
  function of the evidence, so identical inputs always produce identical
  tiers.
- **One shared evidence store.** Agents exchange typed state (fact, source,
  date, trust tier), never free chat, so every verdict is auditable.
- **Expensive reasoning is trigger-gated.** A Tree-of-Thought decision node
  (depth 2, beam 2) activates only when sources conflict, confidence is low
  on a high-severity CVE, or an unconfirmed source raises an early warning.
  Most CVEs take the linear path straight to the Scorer.

## Architecture

```
CVE ID
  │
  ▼
Collect ──► Retrieve ──► Decide ──► Score ──► Brief
(NVD/EPSS/   (RAG layer:   (linear, or    (deterministic  (tier, confidence,
 KEV/assets)  pre-filter,   trigger-gated  Scorer —        evidence, conflicts,
              floor, MMR,   ToT node:      final arbiter)  triggers, approval
              trust tiers)  Generator vs                  gate)
                            Evaluator)
        all stages read/write the shared evidence store (src/store.py)
```

| File | Role |
|---|---|
| `src/orchestrator.py` | LangGraph graph; one workflow per CVE; stop conditions; linear fallback if LangGraph/decision node fails |
| `src/collector.py` | Tool layer: NVD, EPSS, CISA KEV, synthetic asset inventory. Facts only, read-only, every response cached |
| `src/retrieval.py` | Documentary retrieval: metadata pre-filter, similarity floor, top-8 → MMR → 4, five trust tiers, empty retrieval = honest gap |
| `src/generator.py` | Up to 3 competing tier hypotheses (stances) at the decision step |
| `src/evaluator.py` | Scores hypotheses on evidence quality / consistency / constraint coverage; never sees Generator rationale |
| `src/scorer.py` | **Deterministic tier function.** KEV-listed ⇒ patch now, always. Tier-5 signals score zero |
| `src/brief.py` | Analyst brief + the six human-intervention triggers (Checkpoint 6.1) |
| `src/store.py` | Shared evidence store: items with (source, date, trust tier), conflicts, audit log |

**Trust tiers** (Checkpoint 3.1): 1 = CISA KEV · 2 = vendor advisories ·
3 = NVD · 4 = MITRE CWE/ATT&CK · 5 = researcher write-ups / PoC repos
(*unconfirmed* — can raise an early warning and trigger corroboration, but
can never move a tier on its own).

**Conflict policy:** disagreements between authoritative sources are
recorded in the store and the brief. After two decision rounds with no tier
change, the workflow stops and marks the conflict **unresolved** — a human
intervention trigger — rather than forcing a verdict. An unresolved
conflict on a KEV-listed CVE escalates to the on-call lead; ordinary ones
go to the analyst queue with a 24-hour SLA.

## Setup

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

No API keys are required. All three data sources are public and keyless.
If `OPENROUTER_API_KEY` happens to be set, the Generator uses a free-tier
OpenRouter model to phrase hypothesis rationales — narrative only; scoring
and tiers are unaffected, and any failure falls back to built-in templates.

## Usage

```bash
# Live run (responses are cached under data/cache/ as they arrive)
.venv/bin/python -m src.orchestrator CVE-2021-44228

# Reproduce exactly, offline, from the cache
.venv/bin/python -m src.orchestrator CVE-2021-44228 --offline

# Several CVEs; also save a brief to a file
.venv/bin/python -m src.orchestrator CVE-2024-3094 CVE-2020-15103 --out brief.md

# Tests (determinism + hard rules)
.venv/bin/python -m pytest tests/ -q

# Prototype evaluation over a fixed 10-CVE set -> eval/results.md
.venv/bin/python eval/run_eval.py
```

## How to review this project

1. **`examples/sample_run.md`** — one CVE (Log4Shell) end to end: audit
   trail, evidence, decision node, scorer breakdown, brief.
2. **`eval/results.md`** — measured metrics over 10 CVEs (completion rate,
   KEV agreement, latency, path split), plus an explicit list of the
   Checkpoint 6.1 metrics a prototype run *cannot* measure.
3. **`src/scorer.py`** — the deterministic core; `tests/test_scorer.py`
   pins its contract (determinism, KEV hard rule, tier-5 zero weight).
4. **`data/cache/`** — the exact API responses every run used, so any
   result can be reproduced offline byte-for-byte at the input level.

## Evaluation summary

See `eval/results.md` for the full table. Headline: 10/10 runs completed,
8/8 KEV-listed CVEs tiered "patch now" (hard rule), the non-KEV XZ backdoor
(CVE-2024-3094, EPSS 0.91) also reached "patch now" on severity + EPSS +
exposure, and the low-signal case (CVE-2020-15103) deferred. The
time-lagged KEV accuracy, false-negative rate, and analyst override rate
from the Checkpoint 6.1 framework need 90 days of outcome maturation and
human reviewers respectively; they are designed and instrumented (every run
writes a full audit record) but not claimed here.

## Limitations and simplifications (stated, not hidden)

- **Retrieval similarity is lexical** (token cosine), not neural embeddings;
  the checkpoint mechanics — pre-filter, floor, MMR, trust tiers — are
  implemented as designed, the similarity function is the stand-in.
- **References are classified from NVD metadata** (tags + source) rather
  than by crawling advisory full text.
- **Exposure matching** uses NVD CPE version ranges where provided and
  token-level product matching against a 15-row *synthetic* inventory.
- **NVD is keyless** here: requests are paced (≥6 s apart) with retries,
  which inflates live latency; cached/offline runs are near-instant.
- The ToT Evaluator's criteria scores are rule-based in the default
  (keyless) configuration — the role separation is structural, and the
  deterministic Scorer remains the final arbiter either way.

## Data and safety

All data is public (NVD, FIRST EPSS, CISA KEV, MITRE CWE) or synthetic
(asset inventory). All tools are read-only — VulnScope cannot patch, scan,
or touch any system. Retrieved documents are treated as untrusted data,
never as instructions.

*CMU Agentic AI program — capstone prototype (Assignment 7.1).*
