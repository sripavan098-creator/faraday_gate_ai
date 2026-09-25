from __future__ import annotations

import math
from collections import Counter
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field

from faraday.core.session import DecisionAction, FindingType, Severity


def line_of_index(text: str, index: int) -> int:
    """Convert a character index into a 1-based line number."""

    return text.count("\n", 0, index) + 1


def shannon_entropy(value: str) -> float:
    """Compute Shannon entropy for a string.

    Higher entropy often indicates generated secrets, tokens, or keys.
    This is only a signal; deterministic patterns remain primary.
    """

    if not value:
        return 0.0

    length = len(value)
    counts = Counter(value)

    entropy = 0.0

    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy


def mask_value(value: str) -> str:
    """Mask a value for safe display.

    Raw secret values should not be stored or printed.
    """

    value = value.strip()

    if not value:
        return ""

    if len(value) <= 8:
        return "*" * len(value)

    return value[:3] + "*" * min(12, len(value) - 6) + value[-3:]


class ScanFinding(BaseModel):
    """Internal scanner finding.

    Security rules:
        - `matched` is excluded from serialization by default.
        - `matched` must not be written to audit logs.
        - `matched` exists only so the redactor can replace text.
    """

    type: FindingType
    severity: Severity
    scanner: str
    origin: str
    path: Optional[str] = None
    line: Optional[int] = None
    rule: str
    confidence: float = 1.0
    recommended_action: DecisionAction = "block"
    details: Optional[str] = None

    start: Optional[int] = Field(default=None, exclude=True)
    end: Optional[int] = Field(default=None, exclude=True)
    matched: Optional[str] = Field(default=None, exclude=True)


def finding_to_session_kwargs(finding: ScanFinding) -> Dict[str, Any]:
    """Convert an internal ScanFinding into safe kwargs for Session.add_finding().

    Intentionally excludes start, end, and matched.
    """

    return {
        "type": finding.type,
        "severity": finding.severity,
        "source": finding.origin,
        "path": finding.path,
        "line": finding.line,
        "rule": finding.rule,
        "confidence": finding.confidence,
        "recommended_action": finding.recommended_action,
        "details": finding.details,
    }
