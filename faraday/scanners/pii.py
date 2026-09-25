from __future__ import annotations

import re
from typing import List, Optional

from faraday.scanners.base import ScanFinding, line_of_index

PII_PATTERNS = [
    (
        "email_address",
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        "medium",
        "redact",
    ),
    (
        "phone_number_india",
        r"(?<!\d)(?:\+91[- ]?|0)?[6-9]\d{4}[- ]?\d{5}(?!\d)",
        "medium",
        "redact",
    ),
    (
        "account_identifier",
        r"(?i)\b(account|acct|customer|patient|invoice|order)[ _-]?(id|number|no)?\b\s*[:=]\s*['\"]?[A-Za-z0-9_-]{6,}['\"]?",
        "medium",
        "redact",
    ),
]

SENSITIVE_KEYWORDS = [
    "aadhaar",
    "pan",
    "ssn",
    "social security",
    "salary",
    "medical",
    "diagnosis",
    "patient",
    "confidential",
]


def scan_pii(
    text: str,
    origin: str,
    path: Optional[str] = None,
) -> List[ScanFinding]:
    """MVP PII/sensitive-data scanner using deterministic local rules only."""

    findings: List[ScanFinding] = []

    for rule, pattern, severity, action in PII_PATTERNS:
        for match in re.finditer(pattern, text):
            findings.append(
                ScanFinding(
                    type="pii",
                    severity=severity,
                    scanner="pii",
                    origin=origin,
                    path=path,
                    line=line_of_index(text, match.start()),
                    rule=rule,
                    confidence=1.0,
                    recommended_action=action,
                    details=None,
                    start=match.start(),
                    end=match.end(),
                    matched=match.group(0),
                )
            )

    keyword_pattern = rf"(?i)\b(?:{'|'.join(SENSITIVE_KEYWORDS)})\b"

    for match in re.finditer(keyword_pattern, text):
        findings.append(
            ScanFinding(
                type="pii",
                severity="low",
                scanner="pii",
                origin=origin,
                path=path,
                line=line_of_index(text, match.start()),
                rule="sensitive_keyword",
                confidence=0.7,
                recommended_action="warn",
                details=None,
                start=match.start(),
                end=match.end(),
                matched=match.group(0),
            )
        )

    return findings
