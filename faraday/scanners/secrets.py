from __future__ import annotations

import re
from typing import List, Optional

from faraday.scanners.base import ScanFinding, line_of_index, shannon_entropy

SECRET_PATTERNS = [
    (
        "aws_access_key_id",
        r"\bAKIA[0-9A-Z]{16}\b",
        "critical",
    ),
    (
        "aws_secret_access_key",
        r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{20,}['\"]?",
        "critical",
    ),
    (
        "private_key_block",
        r"-----BEGIN[A-Z ]*PRIVATE KEY-----",
        "critical",
    ),
    (
        "stripe_secret_key",
        r"\bsk_(live|test)_[A-Za-z0-9]{10,}\b",
        "critical",
    ),
    (
        "github_token",
        r"\bgh[pousr]_[A-Za-z0-9]{30,}\b",
        "critical",
    ),
    (
        "slack_token",
        r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b",
        "high",
    ),
    (
        "jwt",
        r"\beyJ[A-Za-z0-9_=-]+\.[A-Za-z0-9_=-]+\.[A-Za-z0-9_=-]+\b",
        "high",
    ),
    (
        "database_url",
        r"\b(postgres|postgresql|mysql|mongodb|redis)://[^\s'\"<>]+",
        "high",
    ),
    (
        "bearer_token",
        r"(?i)\bbearer\s+[A-Za-z0-9_\-\.]{20,}\b",
        "high",
    ),
    (
        "generic_secret_assignment",
        r"(?i)\b(api[_-]?key|apikey|secret|token|password|passwd|pwd)\b\s*[:=]\s*['\"]?[A-Za-z0-9_\-./+=]{12,}['\"]?",
        "high",
    ),
]

SENSITIVE_PATH_TOKENS = (
    ".env",
    ".pem",
    ".key",
    "secret",
    "secrets",
    "credential",
    "credentials",
    "config",
)


def extract_candidate_value(matched: str) -> str:
    """Extract the likely secret value from key=value or key: value text."""

    for separator in ("=", ":"):
        if separator in matched:
            right = matched.split(separator, 1)[1].strip()
            return right.strip("'\"")

    return matched.strip().strip("'\"")


def path_looks_sensitive(path: Optional[str]) -> bool:
    """Increase scrutiny for files that commonly contain secrets."""

    if not path:
        return False

    lowered = str(path).lower()

    return any(token in lowered for token in SENSITIVE_PATH_TOKENS)


def scan_secrets(
    text: str,
    origin: str,
    path: Optional[str] = None,
) -> List[ScanFinding]:
    """Deterministic secret scanner.

    Detection layers:
        - known credential patterns
        - generic secret assignments
        - entropy scoring
        - path awareness
    """

    findings: List[ScanFinding] = []
    effective_path = path or origin

    for rule, pattern, base_severity in SECRET_PATTERNS:
        for match in re.finditer(pattern, text):
            matched = match.group(0)
            severity = base_severity
            details: List[str] = []

            candidate = extract_candidate_value(matched)
            entropy = shannon_entropy(candidate)

            if len(candidate) >= 16 and entropy >= 4.0:
                details.append(f"entropy:{entropy:.2f}")

                if rule == "generic_secret_assignment":
                    severity = "critical"

            if path_looks_sensitive(effective_path):
                details.append("sensitive_path")

                if severity in ("medium", "high"):
                    severity = "critical"

            findings.append(
                ScanFinding(
                    type="secret",
                    severity=severity,
                    scanner="secrets",
                    origin=origin,
                    path=path,
                    line=line_of_index(text, match.start()),
                    rule=rule,
                    confidence=1.0,
                    recommended_action="block",
                    details=";".join(details) if details else None,
                    start=match.start(),
                    end=match.end(),
                    matched=matched,
                )
            )

    return findings
