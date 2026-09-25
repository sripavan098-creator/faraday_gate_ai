from __future__ import annotations

import re
from typing import List

from faraday.scanners.base import ScanFinding

COMMAND_GUARD_PATTERNS = [
    ("curl", r"\bcurl\b", "high"),
    ("wget", r"\bwget\b", "high"),
    ("netcat", r"\bnc\b", "high"),
    ("scp", r"\bscp\b", "high"),
    ("ssh", r"\bssh\b", "medium"),
    ("git_push", r"\bgit\s+push\b", "high"),
    ("aws_cli", r"\baws\b", "high"),
    ("gcloud_cli", r"\bgcloud\b", "high"),
    ("azure_cli", r"\baz\b", "high"),
    ("kubectl", r"\bkubectl\b", "high"),
    ("cat_env", r"(?i)\bcat\b[^\n]{0,80}\.env\b", "critical"),
    ("cat_ssh", r"(?i)\bcat\b[^\n]{0,80}\.ssh\b", "critical"),
    ("rm_rf", r"\brm\s+-rf\b", "critical"),
    ("chmod_777", r"\bchmod\s+777\b", "medium"),
    ("shutdown", r"\bshutdown\b", "high"),
]


def scan_command_guard(
    command_text: str,
    origin: str = "command",
) -> List[ScanFinding]:
    """Inspect proposed shell commands.

    This scanner treats commands as another security boundary. Policy may later
    allow, warn, ask, or block depending on mode.
    """

    findings: List[ScanFinding] = []

    for rule, pattern, severity in COMMAND_GUARD_PATTERNS:
        for match in re.finditer(pattern, command_text):
            findings.append(
                ScanFinding(
                    type="command_guard",
                    severity=severity,
                    scanner="command_guard",
                    origin=origin,
                    path=None,
                    line=1,
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
