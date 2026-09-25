from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from faraday.scanners.base import ScanFinding

SEVERITY_RANK = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}

NON_REDACTABLE_TYPES = {
    "prompt_injection",
    "command_guard",
    "path",
}

QUOTE_CHARS = ("'", '"')


@dataclass
class PlaceholderState:
    """Session-scoped placeholder manager.

    Keeps placeholder numbering stable within a session.

    Security note:
        The fingerprint is a local SHA-256 hash used only to map repeated
        values to the same placeholder. It is not intended for export or
        audit storage.
    """

    counters: Dict[str, int] = field(default_factory=dict)
    fingerprint_to_placeholder: Dict[str, str] = field(default_factory=dict)

    def next_placeholder(self, prefix: str, fingerprint: str) -> str:
        existing = self.fingerprint_to_placeholder.get(fingerprint)

        if existing:
            return existing

        count = self.counters.get(prefix, 0) + 1
        self.counters[prefix] = count

        placeholder = f"[{prefix}_{count}]"
        self.fingerprint_to_placeholder[fingerprint] = placeholder

        return placeholder


@dataclass
class RedactionRecord:
    """Safe record of a redaction.

    This must not contain the original sensitive value.
    """

    placeholder: str
    finding_type: str
    rule: str
    origin: str
    path: Optional[str]
    line: Optional[int]


@dataclass
class Replacement:
    """Internal replacement span."""

    start: int
    end: int
    text: str
    placeholder: str
    finding: ScanFinding


@dataclass
class RedactionResult:
    """Result of a redaction operation."""

    redacted_text: str
    records: List[RedactionRecord]
    blocked: List[ScanFinding]
    replacements_count: int
    state: PlaceholderState


def fingerprint_text(value: str) -> str:
    """Create a local fingerprint for placeholder stability.

    This is not stored in audit metadata.
    """

    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def placeholder_prefix(finding: ScanFinding) -> str:
    """Choose placeholder prefix based on finding type/rule."""

    if finding.type == "pii":
        if "email" in finding.rule:
            return "EMAIL"

        if "phone" in finding.rule:
            return "PHONE"

        if "account" in finding.rule:
            return "ACCOUNT"

        return "SENSITIVE"

    if finding.type == "secret":
        return "SECRET"

    if finding.type == "semantic_leak":
        return "LEAK"

    return "REDACTED"


def is_redactable(finding: ScanFinding, mode: str) -> bool:
    """Decide whether a finding may be redacted by this engine.

    Modes:
        default: redact findings whose recommended_action is "redact".
        sensitive: redact secret and PII findings even if recommended_action
            is block. Useful for `faraday redact`.
        all: redact all technically redactable findings.
    """

    if finding.type in NON_REDACTABLE_TYPES:
        return False

    if finding.start is None or finding.end is None or not finding.matched:
        return False

    if mode == "all":
        return True

    if mode == "sensitive":
        return finding.type in {"secret", "pii"}

    if mode == "default":
        return finding.recommended_action == "redact"

    raise ValueError(f"Unknown redaction mode: {mode}")


def find_value_span(
    finding: ScanFinding,
    text: str,
) -> Optional[Tuple[int, int, str, bool]]:
    """Attempt to find the narrow sensitive value span inside a finding.

    Returns:
        start, end, value, was_quoted

    This helps preserve syntax by replacing only the value instead of the
    whole assignment line.
    """

    if finding.start is None or finding.end is None or finding.matched is None:
        return None

    matched = finding.matched
    base_start = finding.start

    # Bearer tokens: replace only the token, not the word "Bearer".
    if finding.rule == "bearer_token":
        parts = matched.split(None, 1)

        if len(parts) == 2:
            token = parts[1]
            offset = matched.find(token, len(parts[0]))

            return (
                base_start + offset,
                base_start + offset + len(token),
                token,
                False,
            )

    # Build the candidate value spans first. Narrowing to just the value is
    # what preserves an assignment's key, and it is safe for spans that already
    # point at the value. A URL scheme such as `postgres://` is rejected by the
    # `//` guard below, so `postgres` is never mistaken for a key.
    #
    # Assignment-style secrets: key=value, key: value, key = "value".
    if finding.type == "secret":
        for separator in (":", "="):
            separator_index = matched.find(separator)

            if separator_index == -1:
                continue

            key_part = matched[:separator_index].strip()

            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_\-\.]*", key_part):
                continue

            rest = matched[separator_index + 1 :]

            match = re.search(r"(\s*)(['\"]?)([^'\"\s]+)\2", rest)

            if match and not match.group(3).startswith("//"):
                was_quoted = bool(match.group(2))
                value = match.group(3)
                value_start = base_start + separator_index + 1 + match.start(3)

                return (
                    value_start,
                    value_start + len(value),
                    value,
                    was_quoted,
                )

            stripped = rest.strip()

            if stripped:
                value = stripped.strip("'\"")

                if value and not value.startswith("//"):
                    value_index = rest.find(value[0])

                    if value_index != -1:
                        value_start = base_start + separator_index + 1 + value_index

                        return (
                            value_start,
                            value_start + len(value),
                            value,
                            False,
                        )

    return (
        base_start,
        finding.end,
        matched,
        False,
    )


def span_is_quoted(text: str, start: int, end: int) -> bool:
    """Return True if the span appears to be surrounded by matching quotes."""

    if start <= 0 or end >= len(text):
        return False

    before = text[start - 1]
    after = text[end]

    return before == after and before in QUOTE_CHARS


ASSIGNMENT_KEY_RE = r"[A-Za-z0-9_\-\.]+"
ASSIGNMENT_OP = r"(?:[:=])"


def context_is_assignment(text: str, start: int) -> bool:
    """Return True if the current line before the span looks like an assignment.

    Only the current line is considered. Looking further back would cross
    newlines and treat an unrelated `=` or `:` at the end of a previous line as
    an assignment operator for this span.
    """

    line_start = text.rfind("\n", 0, start) + 1
    prefix = text[line_start:start]

    return (
        re.search(
            rf"(?i){ASSIGNMENT_KEY_RE}\s*{ASSIGNMENT_OP}\s*['\"]?$",
            prefix,
        )
        is not None
    )


def build_replacements(
    text: str,
    findings: List[ScanFinding],
    state: PlaceholderState,
    mode: str,
) -> List[Replacement]:
    """Convert redactable findings into replacement candidates."""

    replacements: List[Replacement] = []

    for finding in findings:
        if not is_redactable(finding, mode):
            continue

        span = find_value_span(finding, text)

        if span is None:
            continue

        start, end, value, was_quoted = span

        if start < 0 or end > len(text) or start >= end:
            continue

        if span_is_quoted(text, start, end):
            was_quoted = True

        prefix = placeholder_prefix(finding)
        fingerprint = fingerprint_text(value)
        placeholder = state.next_placeholder(prefix, fingerprint)

        replacement_text = placeholder

        # Syntax preservation: unquoted secret assignments get quoted
        # placeholders so the surrounding code stays parseable.
        if (
            finding.type == "secret"
            and not was_quoted
            and context_is_assignment(text, start)
        ):
            replacement_text = f'"{placeholder}"'

        replacements.append(
            Replacement(
                start=start,
                end=end,
                text=replacement_text,
                placeholder=placeholder,
                finding=finding,
            )
        )

    return replacements


def select_non_overlapping(
    replacements: List[Replacement],
) -> List[Replacement]:
    """Choose non-overlapping replacements.

    Preference order: higher severity, then longer span.
    """

    candidates = sorted(
        replacements,
        key=lambda replacement: (
            SEVERITY_RANK.get(replacement.finding.severity, 0),
            replacement.end - replacement.start,
        ),
        reverse=True,
    )

    selected: List[Replacement] = []

    for candidate in candidates:
        overlaps = False

        for existing in selected:
            if not (candidate.end <= existing.start or candidate.start >= existing.end):
                overlaps = True
                break

        if not overlaps:
            selected.append(candidate)

    return sorted(selected, key=lambda replacement: replacement.start)


def redact_text(
    text: str,
    findings: List[ScanFinding],
    mode: str = "default",
    state: Optional[PlaceholderState] = None,
) -> RedactionResult:
    """Redact sensitive findings from text.

    Modes:
        default: redact findings whose recommended_action is "redact".
        sensitive: redact secret and PII findings even if recommended_action
            is block. Useful for standalone redaction commands.
        all: redact all technically redactable findings.
    """

    if state is None:
        state = PlaceholderState()

    replacements = build_replacements(text, findings, state, mode)
    selected = select_non_overlapping(replacements)

    redacted_text = text

    for replacement in sorted(selected, key=lambda r: r.start, reverse=True):
        redacted_text = (
            redacted_text[: replacement.start]
            + replacement.text
            + redacted_text[replacement.end :]
        )

    records = [
        RedactionRecord(
            placeholder=replacement.placeholder,
            finding_type=replacement.finding.type,
            rule=replacement.finding.rule,
            origin=replacement.finding.origin,
            path=replacement.finding.path,
            line=replacement.finding.line,
        )
        for replacement in selected
    ]

    selected_ids = {id(replacement.finding) for replacement in selected}

    blocked = [
        finding
        for finding in findings
        if id(finding) not in selected_ids and finding.recommended_action == "block"
    ]

    return RedactionResult(
        redacted_text=redacted_text,
        records=records,
        blocked=blocked,
        replacements_count=len(selected),
        state=state,
    )
