"""Lightweight qualitative severity helper (not a full CVSS calculator)."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class SeverityResult:
    rating: str
    score_hint: float
    rationale: list[str]


def suggest_severity(
    *,
    unauthenticated: bool = False,
    exposes_pii: bool = False,
    exposes_financial: bool = False,
    privilege_escalation: bool = False,
    rce: bool = False,
    easy_exploit: bool = True,
    widespread: bool = False,
) -> SeverityResult:
    score = 0.0
    why: list[str] = []

    if rce:
        score += 9.0
        why.append("Remote code execution potential")
    if privilege_escalation:
        score += 3.5
        why.append("Privilege escalation / authz bypass")
    if exposes_financial:
        score += 3.0
        why.append("Financial or payment data exposure")
    if exposes_pii:
        score += 2.5
        why.append("PII exposure")
    if unauthenticated:
        score += 2.0
        why.append("No authentication required")
    if easy_exploit:
        score += 1.0
        why.append("Low complexity exploit path")
    if widespread:
        score += 1.0
        why.append("Likely affects many users/objects")

    score = min(score, 10.0)

    if score >= 9.0:
        rating = "Critical"
    elif score >= 7.0:
        rating = "High"
    elif score >= 4.0:
        rating = "Medium"
    elif score >= 0.1:
        rating = "Low"
    else:
        rating = "Informational"
        why.append("No strong impact signals selected")

    return SeverityResult(rating=rating, score_hint=round(score, 1), rationale=why)
