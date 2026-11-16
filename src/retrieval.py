"""Retrieval layer (Checkpoint 3.1).

APIs answer "what are the facts"; retrieval answers "what does the
documentary evidence say, and where does it say it." For each CVE a small
corpus is assembled from public material the Collector already fetched:

    * the NVD description                     -> tier 3 chunk
    * NVD references, classified by NVD's own tags and the source domain
        vendor advisory                       -> tier 2
        exploit / PoC material                -> tier 5 (unconfirmed)
        other third-party references          -> tier 3
    * the CISA KEV entry, when listed         -> tier 1 chunk
    * a bundled MITRE CWE description         -> tier 4 chunk

Mechanics follow the checkpoint design: a metadata pre-filter pins the
CVE/product/CWE space before ranking, a similarity floor returns an honest
empty result instead of a forced match, and top-8 retrieval is re-ranked by
Maximal Marginal Relevance to a final 4 per query.

Simplification (documented in the README): similarity is lexical cosine over
token counts rather than neural embeddings, and references are classified
from NVD metadata rather than by crawling advisory full text. The control
flow — pre-filter, floor, MMR, trust tiers, empty-is-a-result — is the
checkpoint design unchanged.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass

from .store import (TIER_KEV, TIER_MITRE, TIER_NVD, TIER_UNCONFIRMED,
                    TIER_VENDOR)

SIMILARITY_FLOOR = 0.08
TOP_K = 8
FINAL_K = 4
MMR_LAMBDA = 0.7

_TOKEN_RE = re.compile(r"[a-z0-9]+")
_STOPWORDS = {
    "the", "a", "an", "of", "to", "in", "is", "are", "and", "or", "for",
    "on", "with", "by", "an", "be", "this", "that", "it", "as", "at",
}

# Bundled CWE context (tier 4). Subset covering the weakness classes that
# recur in the evaluation set; an unlisted CWE simply yields no tier-4 chunk.
CWE_CONTEXT = {
    "CWE-79": "Improper neutralization of input during web page generation (cross-site scripting); mitigations include context-aware output encoding and input validation.",
    "CWE-78": "Improper neutralization of special elements used in an OS command; mitigations include avoiding shell invocation with untrusted input and allow-list validation.",
    "CWE-89": "Improper neutralization of special elements used in an SQL command; mitigations include parameterized queries and least-privilege database accounts.",
    "CWE-20": "Improper input validation; mitigations include strict allow-list validation of all externally controlled input.",
    "CWE-22": "Improper limitation of a pathname to a restricted directory (path traversal); mitigations include canonicalization and chroot-style containment.",
    "CWE-200": "Exposure of sensitive information to an unauthorized actor; mitigations include access control checks before returning sensitive data.",
    "CWE-287": "Improper authentication; mitigations include strong authentication mechanisms and protection of credentials in transit and at rest.",
    "CWE-352": "Cross-site request forgery; mitigations include unpredictable anti-CSRF tokens tied to the user session.",
    "CWE-400": "Uncontrolled resource consumption; mitigations include rate limiting and resource quotas.",
    "CWE-416": "Use after free; mitigations include memory-safe languages and rigorous lifetime management.",
    "CWE-502": "Deserialization of untrusted data; mitigations include not deserializing untrusted input and using signed, integrity-checked formats.",
    "CWE-787": "Out-of-bounds write; mitigations include bounds checking and memory-safe languages.",
    "CWE-862": "Missing authorization; mitigations include explicit authorization checks on every sensitive operation.",
    "CWE-918": "Server-side request forgery; mitigations include allow-listing outbound destinations and blocking internal address ranges.",
    "CWE-943": "Improper neutralization of special elements in data query logic; mitigations include parameterized queries for the target data store.",
}


def _tokens(text: str) -> list[str]:
    return [t for t in _TOKEN_RE.findall(text.lower()) if t not in _STOPWORDS]


def _cosine(a: Counter, b: Counter) -> float:
    if not a or not b:
        return 0.0
    dot = sum(a[t] * b.get(t, 0) for t in a)
    na = math.sqrt(sum(v * v for v in a.values()))
    nb = math.sqrt(sum(v * v for v in b.values()))
    return dot / (na * nb) if na and nb else 0.0


@dataclass
class Chunk:
    chunk_id: str
    text: str
    source: str
    date: str
    trust_tier: int
    cve_id: str
    products: tuple = ()     # product tokens for the metadata pre-filter
    cwe_id: str = ""
    tags: tuple = ()

    def to_dict(self) -> dict:
        return {
            "chunk_id": self.chunk_id, "text": self.text[:300],
            "source": self.source, "date": self.date,
            "trust_tier": self.trust_tier, "cve_id": self.cve_id,
            "cwe_id": self.cwe_id, "tags": list(self.tags),
        }


_VENDOR_HINTS = ("vendor", "advisory")
_EXPLOIT_HINTS = ("exploit", "poc", "proof-of-concept", "proof of concept")


def _classify_reference(ref: dict) -> int:
    tags = " ".join(ref.get("tags", [])).lower()
    url = ref.get("url", "").lower()
    if any(h in tags for h in _EXPLOIT_HINTS) or "exploit-db" in url:
        return TIER_UNCONFIRMED
    if "vendor advisory" in tags or any(h in url for h in ("security advisory",)):
        return TIER_VENDOR
    return TIER_NVD


def build_corpus(cve_id: str, nvd: dict, kev: dict) -> list[Chunk]:
    """Assemble the per-CVE documentary corpus from collected public data."""
    chunks: list[Chunk] = []
    products = tuple(sorted({
        m.get("criteria", "").split(":")[4].replace("_", " ")
        for m in nvd.get("cpe_matches", [])
        if len(m.get("criteria", "").split(":")) > 4
    }))
    if nvd.get("description"):
        chunks.append(Chunk(
            chunk_id=f"{cve_id}-nvd-desc", text=nvd["description"],
            source="NVD", date=nvd.get("published", ""),
            trust_tier=TIER_NVD, cve_id=cve_id, products=products,
            cwe_id=nvd["cwes"][0] if nvd.get("cwes") else ""))
    if kev.get("listed"):
        chunks.append(Chunk(
            chunk_id=f"{cve_id}-kev", text=(
                f"CISA Known Exploited Vulnerabilities entry: {kev.get('name')}. "
                f"Listed {kev.get('date_added')}. Known ransomware campaign use: "
                f"{kev.get('ransomware')}."),
            source="CISA KEV", date=kev.get("date_added") or "",
            trust_tier=TIER_KEV, cve_id=cve_id, products=products))
    for i, ref in enumerate(nvd.get("references", [])):
        tier = _classify_reference(ref)
        label = {TIER_VENDOR: "vendor advisory reference",
                 TIER_UNCONFIRMED: "exploit / researcher reference (unconfirmed)",
                 TIER_NVD: "third-party reference"}[tier]
        chunks.append(Chunk(
            chunk_id=f"{cve_id}-ref-{i}",
            text=f"{label}: {ref.get('url', '')} tags: {', '.join(ref.get('tags', []))}",
            source=ref.get("source") or "NVD reference",
            date=nvd.get("published", ""), trust_tier=tier,
            cve_id=cve_id, products=products,
            tags=tuple(ref.get("tags", []))))
    for cwe in nvd.get("cwes", []):
        if cwe in CWE_CONTEXT:
            chunks.append(Chunk(
                chunk_id=f"{cve_id}-{cwe.lower()}", text=f"{cwe}: {CWE_CONTEXT[cwe]}",
                source="MITRE CWE", date="", trust_tier=TIER_MITRE,
                cve_id=cve_id, products=products, cwe_id=cwe))
    return chunks


def retrieve(corpus: list[Chunk], query: str, cve_id: str,
             products: tuple = (), cwe_id: str = "") -> tuple[list[Chunk], bool]:
    """Pre-filter -> similarity floor -> top-8 -> MMR -> final 4.

    Returns (chunks, empty). `empty=True` is a first-class result
    (Checkpoint 3.1): no chunk cleared the floor, and the caller must say so.
    """
    wanted_products = {p.lower() for p in products}

    def in_space(chunk: Chunk) -> bool:
        if chunk.cve_id == cve_id:
            return True
        if cwe_id and chunk.cwe_id == cwe_id:
            return True
        return bool(wanted_products & {p.lower() for p in chunk.products})

    pool = [c for c in corpus if in_space(c)]
    q = Counter(_tokens(query))
    scored = [(c, _cosine(q, Counter(_tokens(c.text)))) for c in pool]
    scored = [(c, s) for c, s in scored if s >= SIMILARITY_FLOOR]
    if not scored:
        return [], True
    scored.sort(key=lambda cs: cs[1], reverse=True)
    top = scored[:TOP_K]

    # Maximal Marginal Relevance re-rank for diversity.
    selected: list[Chunk] = []
    remaining = list(top)
    while remaining and len(selected) < FINAL_K:
        best, best_val = None, -1.0
        for cand, sim in remaining:
            redundancy = max(
                (_cosine(Counter(_tokens(cand.text)), Counter(_tokens(s.text)))
                 for s in selected), default=0.0)
            val = MMR_LAMBDA * sim - (1 - MMR_LAMBDA) * redundancy
            if val > best_val:
                best, best_val = (cand, sim), val
        selected.append(best[0])
        remaining.remove(best)
    return selected, False


EXPLOITATION_QUERY = ("evidence of active exploitation in the wild, "
                      "exploit code, attacks using this vulnerability")
MITIGATION_QUERY = ("mitigations, affected versions, weakness class, "
                    "workarounds and fixes for this vulnerability")


def exploitation_signals(chunks: list[Chunk]) -> tuple[bool, bool, int | None]:
    """Derive (confirmed, unconfirmed, confirmation_tier) from chunks.

    Confirmed requires tier 1-2 evidence: a KEV chunk, or a vendor advisory
    reference that NVD tags as exploit-related. Tier-5 material alone only
    raises the unconfirmed warning (Checkpoint 3.1). confirmation_tier is
    the highest (lowest-numbered) tier that supports the confirmation.
    """
    confirmed, unconfirmed, conf_tier = False, False, None
    for ch in chunks:
        tag_text = " ".join(ch.tags).lower()
        text = ch.text.lower()
        looks_exploity = ("exploit" in tag_text or "exploited" in text
                          or "known exploited" in text)
        if not looks_exploity:
            continue
        if ch.trust_tier <= TIER_VENDOR:
            confirmed = True
            if conf_tier is None or ch.trust_tier < conf_tier:
                conf_tier = ch.trust_tier
        elif ch.trust_tier == TIER_UNCONFIRMED:
            unconfirmed = True
    return confirmed, unconfirmed, conf_tier
