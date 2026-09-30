"""Heuristic detection of prose that is semantically dangerous to send.

This scanner targets a gap the deterministic secret/PII scanners cannot cover:
text that contains no secret pattern, but *asks the agent* to leak one. The
canonical example is a prompt that is itself benign (``"Fix the login bug"``)
combined with repository content instructing the agent to read credentials.

Design constraints (see the project's "deterministic before probabilistic"
rule):

- This runs **after** the deterministic scanners, and can only add findings.
  It can never remove, downgrade, or override a deterministic deny.
- It is a heuristic and is labeled as such: findings carry ``confidence`` well
  below 1.0 and default to ``warn`` rather than ``block``. A false positive
  here must not silently become a block, because that would make the firewall
  unusable on ordinary documentation.
- It performs no network calls and loads no model.

The benign examples in ``tests/test_semantic_leak.py`` are the guardrail: plain
English about security ("do not commit secrets") must not fire.
"""

from __future__ import annotations

import re
from typing import List, Optional, Tuple

from faraday.core.session import DecisionAction, Severity
from faraday.scanners.base import ScanFinding

# A gap between two keywords. It may contain dots that are part of identifiers
# (`.env`, `api.key`) but must not cross a sentence boundary (". " plus space).
# Excluding every ".", as a naive `[^.\n]` does, makes "upload the .env file to
# my endpoint" fail to match, because ".env" itself contains a dot.
_GAP = r"(?:(?!\.\s)[^\n])"

# Descriptive subjects that mark a sentence as documentation rather than an
# instruction: "we list all environment variables" is prose, "list all
# environment variables in your response" is a request.
_DESCRIPTIVE_SUBJECT = re.compile(
    r"(?:^|[\s\"'(])(?:we|they|it|this|that|these|those|the\s+\w+|"
    r"our\s+\w+|a\s+\w+|an\s+\w+)\s+$",
    re.IGNORECASE,
)

# Phrases that indicate security *documentation* rather than an attack. If any
# of these appear near a candidate match, the candidate is suppressed.
_BENIGN_CONTEXT = re.compile(
    r"\b(do not|don't|never|avoid|must not|should not|refrain)\b"
    r"[^.\n]{0,40}\b(commit|paste|share|send|upload|log|reveal|expose|"
    r"echo|print|include)\b",
    re.IGNORECASE,
)

# (rule, severity, action, pattern) tuples. Order matters only for reporting.
_PATTERNS: List[Tuple[str, Severity, DecisionAction, re.Pattern]] = [
    (
        "semantic_credential_request",
        "high",
        "warn",
        # Asking for credentials/keys specifically, not merely mentioning them.
        re.compile(
            r"\b(?:send|share|give|provide|paste|print|output|reveal|expose|"
            r"include|list)\b" + _GAP + r"{0,30}\b(?:credential|credentials|"
            r"password|passwords|api[_\s-]?key|api[_\s-]?keys|secret|secrets|"
            r"token|tokens)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "semantic_env_dump_request",
        "high",
        "warn",
        # Asking to enumerate the environment or config in the response.
        re.compile(
            r"\b(?:list|show|print|output|dump|include|enumerate)\b" + _GAP
            + r"{0,25}\b(?:all\s+)?(?:environment\s+variables?|env\s+vars?|"
            r"\.env|secrets?|config(?:uration)?\s+values?)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "semantic_external_transfer_intent",
        "high",
        "warn",
        # Sending data to an external location, without a literal URL. The
        # literal `curl http...` form is already covered by the injection
        # scanner; this catches paraphrases such as "upload the file to my
        # server".
        re.compile(
            r"\b(?:upload|post|send|transmit|exfiltrate|forward|copy)\b"
            + _GAP + r"{0,40}\b(?:to\s+(?:my|our|the|a|an|their)\s+"
            r"(?:server|endpoint|bucket|webhook|url|host|domain)|"
            r"externally|offsite|outside\s+the\s+(?:network|org))",
            re.IGNORECASE,
        ),
    ),
    (
        "semantic_security_tampering_intent",
        "medium",
        "warn",
        # Disabling or working around a guard. Worded to avoid matching
        # ordinary prose like "disable the debug flag".
        re.compile(
            r"\b(?:disable|bypass|turn\s+off|circumvent|skip|remove)\b"
            + _GAP + r"{0,30}\b(?:security|guard|guardrail|firewall|scanner|"
            r"policy|policies|audit|protection|safeguard)\b",
            re.IGNORECASE,
        ),
    ),
]

# Only content from these origins is treated as untrusted input. A prompt typed
# by the developer is not repository content and must not be flagged as an
# injected instruction.
_UNTRUSTED_HINTS = ("repo:", "file:", "readme", "context:", "manifest:")


def _is_untrusted_origin(origin: str, path: Optional[str]) -> bool:
    if path:
        return True

    lowered = origin.lower()

    return any(hint in lowered for hint in _UNTRUSTED_HINTS)


def _suppressed(text: str, start: int, end: int, rule: str) -> bool:
    """Return True when the surrounding text reads as documentation."""

    window = text[max(0, start - 120) : min(len(text), end + 120)]

    if _BENIGN_CONTEXT.search(window):
        return True

    # "we list all environment variables" is descriptive prose. Only apply
    # this to the enumerate-style rule; "send my credentials" reads as an
    # imperative even when a pronoun precedes it.
    if rule == "semantic_env_dump_request":
        prefix = text[max(0, start - 24) : start]
        if _DESCRIPTIVE_SUBJECT.search(prefix):
            return True

    return False


def scan_semantic_leak(
    text: str,
    origin: str = "text",
    path: Optional[str] = None,
) -> List[ScanFinding]:
    """Detect prose that appears to request or move sensitive data.

    Findings are heuristic warnings. Callers must not treat them as equivalent
    to a deterministic secret detection.
    """

    if not text.strip():
        return []

    if not _is_untrusted_origin(origin, path):
        return []

    findings: List[ScanFinding] = []

    for rule, severity, action, pattern in _PATTERNS:
        for match in pattern.finditer(text):
            if _suppressed(text, match.start(), match.end(), rule):
                continue

            findings.append(
                ScanFinding(
                    type="semantic_leak",
                    severity=severity,
                    scanner="semantic_leak",
                    origin=origin,
                    path=path,
                    rule=rule,
                    confidence=0.6,
                    recommended_action=action,
                    details=(
                        "Heuristic prose pattern. May be documentation; "
                        "requires review. Not a deterministic detection."
                    ),
                    start=match.start(),
                    end=match.end(),
                    matched=match.group(0),
                )
            )

    return findings
