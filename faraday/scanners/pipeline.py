from __future__ import annotations

from typing import List, Optional

from faraday.core.policy import Policy
from faraday.scanners.base import ScanFinding, line_of_index
from faraday.scanners.command_guard import scan_command_guard
from faraday.scanners.injection import scan_injection
from faraday.scanners.pii import scan_pii
from faraday.scanners.secrets import scan_secrets


def sort_findings(findings: List[ScanFinding]) -> List[ScanFinding]:
    """Sort findings by span location.

    Findings without spans are placed after span-based findings.
    """

    return sorted(
        findings,
        key=lambda finding: (
            finding.start is None,
            finding.start or 0,
            finding.end or 0,
        ),
    )


def assign_line_numbers(text: str, findings: List[ScanFinding]) -> None:
    """Assign line numbers where missing but span information exists."""

    for finding in findings:
        if finding.line is None and finding.start is not None:
            finding.line = line_of_index(text, finding.start)


def scan_text(
    text: str,
    origin: str,
    path: Optional[str] = None,
    policy: Optional[Policy] = None,
) -> List[ScanFinding]:
    """Run deterministic text scanners.

    Scanners included: secrets, PII / sensitive data, prompt injection.

    The policy argument is accepted for future use, but MVP scanners are
    deterministic and do not require model inference.
    """

    findings: List[ScanFinding] = []

    findings.extend(scan_secrets(text, origin=origin, path=path))
    findings.extend(scan_pii(text, origin=origin, path=path))
    findings.extend(scan_injection(text, origin=origin, path=path))

    assign_line_numbers(text, findings)

    return sort_findings(findings)


def scan_command(
    command_text: str,
    origin: str = "command",
    policy: Optional[Policy] = None,
) -> List[ScanFinding]:
    """Run command guard on proposed command text."""

    findings = scan_command_guard(command_text, origin=origin)

    for finding in findings:
        if finding.line is None:
            finding.line = 1

    return sort_findings(findings)
