# VulnScope prototype evaluation — results

Mode: live APIs + cache  |  Set: 10 CVEs  |  Wall time: 141.5s

| CVE | Tier | KEV-listed | Path | Confidence | Latency (s) |
|---|---|---|---|---|---|
| CVE-2021-44228 | patch now | yes | tot | high | 0.03 |
| CVE-2017-0144 | patch now | yes | tot | high | 14.48 |
| CVE-2019-0708 | patch now | yes | tot | high | 23.28 |
| CVE-2021-34527 | patch now | yes | tot | high | 24.72 |
| CVE-2023-4966 | patch now | yes | linear | high | 18.01 |
| CVE-2017-5638 | patch now | yes | tot | high | 20.42 |
| CVE-2021-41773 | patch now | yes | tot | high | 24.76 |
| CVE-2023-20198 | patch now | yes | linear | high | 15.8 |
| CVE-2024-3094 | patch now | no | linear | high | 0.02 |
| CVE-2020-15103 | defer | no | linear | high | 0.02 |

## Metrics (measurable in a prototype run)

- **Task completion rate:** 10/10 (100%) — target ≥95% (Checkpoint 6.1)
- **KEV agreement:** 8/8 KEV-listed CVEs tiered "patch now" (100%) — 100% expected; KEV listing is a hard rule
- **Median latency:** 18.01s per CVE (linear-path target <120s, Checkpoint 6.1)
- **Path split:** 4 linear, 6 Tree-of-Thought

## Not measured (by design, not omission)

- Time-lagged KEV accuracy and the watch/defer false-negative rate require 90 days of outcome maturation (Checkpoint 6.1).
- Analyst override rate requires analysts reviewing briefs.
