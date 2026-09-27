from __future__ import annotations

import re
from typing import List, Optional, Tuple

from faraday.core.session import Severity
from faraday.scanners.base import ScanFinding, line_of_index

INJECTION_PATTERNS: List[Tuple[str, str, Severity]] = [
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


# Negated security prose is documentation, not an attack. "We never ignore
# previous instructions" is a test assertion; "Ignore previous instructions" is
# an attack. Without this guard the scanner fires on ordinary project docs and
# unit-test fixtures, which trains users to bypass the firewall.
#
# The window is deliberately short (a few words immediately before the match)
# so that an attacker cannot suppress a real payload by prefixing an unrelated
# "never" far earlier in the text.
_NEGATION = re.compile(
    r"(?i)(?:\b(?:never|not|no|don't|doesn't|does\s+not|do\s+not|"
    r"did\s+not|won't|will\s+not|shouldn't|should\s+not|must\s+not|"
    r"avoid|avoiding|prevent|prevents|refuse|refuses)\b\W+){1,3}$"
)

# Rules where a leading negation changes the meaning to documentation. These
# are the natural-language instruction rules. Exfiltration commands are not
# included: "we never curl ..." inside a README is unusual enough that keeping
# the deterministic deny is the safer default.
_NEGATION_SENSITIVE_RULES = {
    "ignore_instructions",
    "disregard_instructions",
    "read_env",
    "read_ssh",
    "reveal_environment_variables",
    "override_security_policy",
}


def _is_negated(text: str, match_start: int, rule: str) -> bool:
    """Return True when the match is preceded by a negating word."""

    if rule not in _NEGATION_SENSITIVE_RULES:
        return False

    prefix = text[max(0, match_start - 40) : match_start]

    return bool(_NEGATION.search(prefix))


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
            if _is_negated(text, match.start(), rule):
                continue

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
