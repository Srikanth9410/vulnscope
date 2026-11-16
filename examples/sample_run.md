# Sample run — CVE-2021-44228 (Log4Shell), end to end

Command: `python -m src.orchestrator CVE-2021-44228` (live APIs, responses cached under `data/cache/`; re-run with `--offline` to reproduce from cache).

Outcome: tier **patch now**, confidence high, path tot, latency 4.35s (live, incl. NVD pacing).

## Audit trail (tool calls and decisions, from the evidence store)

- tool_call: tool=nvd, ok=True, detail=live fetch -> CVE-2021-44228_nvd.json
- tool_call: tool=epss, ok=True, detail=live fetch -> CVE-2021-44228_epss.json
- tool_call: tool=kev, ok=True, detail=live fetch -> kev_feed.json
- retrieval: query=exploitation, returned=4, empty=False, confirmed=True, unconfirmed=True
- scored: tier=patch now, points=100, confidence=high
- brief_written: tier=patch now, triggers=1

---

# VulnScope Brief — CVE-2021-44228

**Tier: PATCH NOW** (score 100/100)  |  **Confidence: high** (1.0)  |  **Path: tot**, 1 round(s)  |  **Latency: 4.35s**

## Key evidence

| Fact | Source | Date | Trust tier |
|---|---|---|---|
| CVSS 10.0 (v3.1) | NVD | 2021-12-10 | 3 |
| Weakness: CWE-20, CWE-400, CWE-502, CWE-917 | NVD | 2021-12-10 | 3 |
| EPSS 0.99999 (percentile 1.0) | FIRST EPSS | 2026-11-15 | 3 |
| Listed in CISA KEV since 2021-12-10 | CISA KEV | 2021-12-10 | 1 |
| 1 inventory asset(s) exposed: web-01 (Apache Log4j 2 2.14.1) | asset inventory (synthetic) | — | 3 |

## Retrieved documentary evidence

- [security@apache.org, 2021-12-10, tier 5] [CVE-2021-44228-ref-3] exploit / researcher reference (unconfirmed): http://packetstormsecurity.com/files/165270/Apache-Log4j2-2.14.1-Remote-Code-Execution.html tags: Exploit, Third Party Advisory, VDB Entry
- [security@apache.org, 2021-12-10, tier 5] [CVE-2021-44228-ref-42] exploit / researcher reference (unconfirmed): https://twitter.com/kurtseifried/status/1469345530182455296 tags: Broken Link, Exploit, Third Party Advisory
- [security@apache.org, 2021-12-10, tier 5] [CVE-2021-44228-ref-11] exploit / researcher reference (unconfirmed): http://packetstormsecurity.com/files/165642/VMware-vCenter-Server-Unauthenticated-Log4Shell-JNDI-Injection-Remote-Code-Execution.html tags: Exploit, Third Party Advisory, VDB Entry
- [security@apache.org, 2021-12-10, tier 5] [CVE-2021-44228-ref-12] exploit / researcher reference (unconfirmed): http://packetstormsecurity.com/files/165673/UniFi-Network-Application-Unauthenticated-Log4Shell-Remote-Code-Execution.html tags: Exploit, Third Party Advisory, VDB Entry

## Conflicts

- None recorded.

## Decision node (Tree-of-Thought)

- H1 (exploitation_credible): quality 1.0, consistency 1.0, coverage 0.667, total 0.9333
- H2 (signal_unconfirmed): quality 0.4, consistency 1.0, coverage 0.333, total 0.6267
- H3 (exposure_fails): quality 1.0, consistency 0.4, coverage 0.333, total 0.6267
- Outcome: round 1: beam converged on 'patch now' via H1 (exploitation_credible)

## Scorer breakdown

- kev_listed_hard_rule: 100
- **total: 100** → patch now

## Human oversight

requires_human_approval: true

Intervention triggers fired:
- 6. "patch now" recommendation — explicit human approval required

---
*Prototype brief. All data public (NVD, EPSS, CISA KEV, MITRE CWE) or synthetic (asset inventory). The system recommends; a human analyst owns the decision.*
