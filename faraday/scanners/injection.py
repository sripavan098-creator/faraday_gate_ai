from __future__ import annotations

import re
from typing import List, Optional

from faraday.scanners.base import ScanFinding, line_of_index

INJECTION_PATTERNS = [
    (
        "ignore_instructions",
        r"(?i)ignore\s+(all\s+|any\s+)?(previous|prior|above)\s+instructions",
        "critical",
    ),
    (
        "disregard_instructions",
        r"(?i)disregard\s+(all\s+|any\s+)?(previous|prior|above)\s+instructions",
        "critical",
    ),
    (
        "read_env",
        r"(?i)\b(read|cat|print|reveal|show|include)\b[^\n]{0,80}\.env\b",
        "critical",
    ),
    (
        "read_ssh",
        r"(?i)\b(read|cat|print|reveal|show|include)\b[^\n]{0,80}\.ssh\b",
        "critical",
    ),
    (
        "reveal_environment_variables",
        r"(?i)\b(reveal|show|print|include)\b[^\n]{0,80}\benvironment variables\b",
        "critical",
    ),
    (
        "network_exfiltration",
        r"(?i)\b(curl|wget)\b\s+https?://",
        "critical",
    ),
    (
        "exfiltration_keywords",
        r"(?i)\b(send|post|upload|exfiltrate)\b[^\n]{0,80}\b(secret|credential|token|key|password|data)\b",
        "high",
    ),
    (
        "override_security_policy",
        r"(?i)\b(override|bypass|disable)\b[^\n]{0,80}\b(safety|security|policy|guard)\b",
        "high",
    ),
]


def scan_injection(
    text: str,
    origin: str,
    path: Optional[str] = None,
) -> List[ScanFinding]:
    """Deterministic prompt-injection scanner.

    This is the first layer of the prompt-injection firewall. Later layers may
    include a local classifier and local LLM reviewer.

    Security rule:
        A later model layer must never override a deterministic deny.
    """

    findings: List[ScanFinding] = []

    for rule, pattern, severity in INJECTION_PATTERNS:
        for match in re.finditer(pattern, text):
            findings.append(
                ScanFinding(
                    type="prompt_injection",
                    severity=severity,
                    scanner="injection",
                    origin=origin,
                    path=path,
                    line=line_of_index(text, match.start()),
                    rule=rule,
                    confidence=1.0,
                    recommended_action="block",
                    details=None,
                    start=match.start(),
                    end=match.end(),
                    matched=match.group(0),
                )
            )

    return findings
