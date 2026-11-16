"""Shared evidence store (Checkpoint 5.1).

All agents communicate through one store of typed state objects — never free
chat. Every fact or chunk carries its source, its date, and its trust tier so
any tier verdict can be traced to the exact evidence set that produced it.

Trust tiers (Checkpoint 3.1):
    1 - CISA KEV (authoritative exploitation listing)
    2 - Vendor advisories
    3 - NVD entry / structured database record
    4 - MITRE CWE / ATT&CK context
    5 - Researcher write-ups and public PoC repositories (UNCONFIRMED:
        can raise an early warning, can never move a tier on its own)
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field, asdict
from typing import Any

TIER_KEV = 1
TIER_VENDOR = 2
TIER_NVD = 3
TIER_MITRE = 4
TIER_UNCONFIRMED = 5


@dataclass
class EvidenceItem:
    """One fact or retrieved chunk in the store."""

    kind: str            # e.g. "cvss", "epss", "kev", "exposure", "chunk"
    fact: str            # human-readable statement of the fact / chunk text
    source: str          # e.g. "NVD", "CISA KEV", "FIRST EPSS", "asset inventory"
    date: str            # source date (publication / listing / score date)
    trust_tier: int      # 1..5 as above
    value: Any = None    # machine-readable payload (score, bool, count, ...)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Conflict:
    """A recorded disagreement between sources on a tier-relevant fact."""

    topic: str
    positions: dict      # source -> position
    resolved: bool = False
    resolution: str = ""  # how the recency-and-authority policy settled it

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class EvidenceStore:
    """Per-CVE evidence store plus the run's audit record (Checkpoint 6.1)."""

    cve_id: str
    items: list = field(default_factory=list)        # list[EvidenceItem]
    conflicts: list = field(default_factory=list)    # list[Conflict]
    audit: list = field(default_factory=list)        # list[dict] tool calls etc.

    # -- evidence ---------------------------------------------------------
    def add(self, item: EvidenceItem) -> EvidenceItem:
        self.items.append(item)
        return item

    def facts(self, kind: str) -> list:
        return [i for i in self.items if i.kind == kind]

    def fact_value(self, kind: str, default=None):
        found = self.facts(kind)
        return found[-1].value if found else default

    # -- conflicts --------------------------------------------------------
    def record_conflict(self, conflict: Conflict) -> Conflict:
        self.conflicts.append(conflict)
        self.log("conflict_recorded", topic=conflict.topic,
                 resolved=conflict.resolved)
        return conflict

    def unresolved_conflicts(self) -> list:
        return [c for c in self.conflicts if not c.resolved]

    # -- audit ------------------------------------------------------------
    def log(self, event: str, **detail) -> None:
        self.audit.append({"t": round(time.time(), 3), "event": event, **detail})

    # -- serialisation ----------------------------------------------------
    def to_dict(self) -> dict:
        return {
            "cve_id": self.cve_id,
            "items": [i.to_dict() for i in self.items],
            "conflicts": [c.to_dict() for c in self.conflicts],
            "audit": self.audit,
        }
