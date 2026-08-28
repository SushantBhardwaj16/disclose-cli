"""PII / secret redaction helpers for disclosure reports."""

from __future__ import annotations

import re

PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    (
        "phone_in",
        re.compile(r"(?:\+91[-\s]?)?[6-9]\d{9}\b"),
    ),
    (
        "aadhaar_like",
        re.compile(r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}\b"),
    ),
    (
        "pan_like",
        re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b"),
    ),
    (
        "bank_account",
        re.compile(r"\b\d{9,18}\b"),
    ),
    (
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
    ),
    (
        "bearer",
        re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._\-]+"),
    ),
    (
        "aws_key",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    ),
    (
        "private_key_block",
        re.compile(
            r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"
        ),
    ),
]


def redact_text(text: str, mask: str = "[REDACTED]") -> tuple[str, list[str]]:
    """Return redacted text and list of rule names that fired."""
    fired: list[str] = []
    out = text
    for name, cre in PATTERNS:
        if name == "bearer":

            def _bearer_sub(m: re.Match[str]) -> str:
                return f"{m.group(1)}{mask}"

            new_out, n = cre.subn(_bearer_sub, out)
        elif name == "bank_account":
            # only mask long digit runs that look like accounts when near keywords
            def _bank_sub(m: re.Match[str]) -> str:
                # keep short years / ports — bank-like if 11+ digits
                if len(re.sub(r"\D", "", m.group(0))) >= 11:
                    return mask
                return m.group(0)

            new_out, n = cre.subn(_bank_sub, out)
        else:
            new_out, n = cre.subn(mask, out)
        if n:
            fired.append(f"{name}×{n}")
            out = new_out
    return out, fired
