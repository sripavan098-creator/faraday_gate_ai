"""AST-aware redaction.

The text redactor rewrites characters using heuristics. That is fine for
`.env` files and prose, but it corrupts structured code: a finding that spans a
whole string literal can swallow quotes, prefix characters, and interpolation
holes.

This module uses tree-sitter to locate the *string content* node and replaces
only that, so quoting, string prefixes (`f`, `r`, `b`), and interpolations such
as `{user}` survive. After editing, the result is re-parsed; if the new parse
contains an error, `RedactionValidationError` is raised rather than emitting
silently broken code (fail-closed).

If tree-sitter or the requested grammar is unavailable, the caller should fall
back to `redact_text`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from faraday.redactor.text_redactor import (
    PlaceholderState,
    RedactionRecord,
    RedactionResult,
    fingerprint_text,
    is_redactable,
    placeholder_prefix,
)
from faraday.scanners.base import ScanFinding


class RedactionValidationError(Exception):
    """Raised when redaction would produce syntactically invalid output."""


_LANGUAGE_LOADERS: Dict[str, str] = {
    "python": "tree_sitter_python",
    "javascript": "tree_sitter_javascript",
    "typescript": "tree_sitter_typescript",
}

_EXTENSION_LANGUAGES: Dict[str, str] = {
    ".py": "python",
    ".pyi": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
}


def language_for_path(path: str) -> Optional[str]:
    """Return the grammar name for a file path, or None if unsupported."""

    lower = path.lower()

    for extension, language in _EXTENSION_LANGUAGES.items():
        if lower.endswith(extension):
            return language

    return None


def _load_language(name: str):
    """Load a tree-sitter grammar, or return None if it is not installed."""

    module_name = _LANGUAGE_LOADERS.get(name)

    if module_name is None:
        return None

    try:
        import importlib

        from tree_sitter import Language

        module = importlib.import_module(module_name)

        return Language(module.language())
    except Exception:
        return None


@dataclass
class _Edit:
    start: int  # character offset
    end: int  # character offset
    text: str


class ASTRedactor:
    """Structure-aware redactor for source code."""

    def __init__(self, language: str = "python") -> None:
        self.language_name = language
        self._language = _load_language(language)

    @property
    def available(self) -> bool:
        return self._language is not None

    def _parse(self, source: bytes):
        from tree_sitter import Parser

        parser = Parser(self._language)

        return parser.parse(source)

    def _string_node_for(self, root, byte_start: int, byte_end: int):
        """Find the innermost `string` node containing the byte range."""

        best = None

        stack = [root]

        while stack:
            node = stack.pop()

            if node.start_byte <= byte_start and node.end_byte >= byte_end:
                if node.type == "string":
                    best = node

                stack.extend(node.children)

        return best

    def _content_edits(self, node, source: bytes) -> List[Tuple[int, int]]:
        """Return byte ranges of literal string content to replace.

        Interpolation children (`{expr}`) are never included, so they survive.
        """

        ranges: List[Tuple[int, int]] = []

        current: Optional[Tuple[int, int]] = None

        for child in node.children:
            if child.type == "string_content":
                if current is None:
                    current = (child.start_byte, child.end_byte)
                else:
                    current = (current[0], child.end_byte)
            else:
                if current is not None:
                    ranges.append(current)
                    current = None

        if current is not None:
            ranges.append(current)

        return ranges

    def redact(
        self,
        text: str,
        findings: List[ScanFinding],
        mode: str = "sensitive",
        state: Optional[PlaceholderState] = None,
    ) -> RedactionResult:
        """Redact code using AST node boundaries.

        Falls back to whole-literal replacement when a finding lies outside any
        string node.
        """

        if not self.available:
            raise RedactionValidationError(
                f"tree-sitter grammar for {self.language_name!r} is not available"
            )

        state = state or PlaceholderState()

        source = text.encode("utf-8")
        tree = self._parse(source)

        if tree.root_node.has_error:
            raise RedactionValidationError(
                "input does not parse; AST redaction is not applicable"
            )

        def to_bytes(char_offset: int) -> int:
            return len(text[:char_offset].encode("utf-8"))

        edits: List[_Edit] = []
        records: List[RedactionRecord] = []
        blocked: List[ScanFinding] = []

        for finding in findings:
            if not is_redactable(finding, mode):
                continue

            # A finding without a span cannot be located in the syntax tree,
            # so AST redaction cannot place a placeholder for it. Treat it as
            # unredactable here and let the caller fall back to text redaction
            # rather than crashing on a None offset.
            if finding.start is None or finding.end is None:
                blocked.append(finding)
                continue

            prefix = placeholder_prefix(finding)
            fingerprint = fingerprint_text(finding.matched or "")
            placeholder = state.next_placeholder(prefix, fingerprint)

            byte_start = to_bytes(finding.start)
            byte_end = to_bytes(finding.end)

            node = self._string_node_for(tree.root_node, byte_start, byte_end)

            if node is None:
                blocked.append(finding)
                continue

            emitted = False

            for start_byte, end_byte in self._content_edits(node, source):
                # Only touch literal runs that overlap the finding.
                if end_byte <= byte_start or start_byte >= byte_end:
                    continue

                start_char = len(source[:start_byte].decode("utf-8"))
                end_char = len(source[:end_byte].decode("utf-8"))

                # A finding may span several literal runs separated by
                # interpolations. Emit the placeholder once and blank the rest,
                # so the number of holes in the string is not exposed.
                replacement = "" if emitted else placeholder
                emitted = True

                edits.append(_Edit(start=start_char, end=end_char, text=replacement))

                records.append(
                    RedactionRecord(
                        placeholder=placeholder,
                        finding_type=finding.type,
                        rule=finding.rule,
                        origin=finding.origin,
                        path=finding.path,
                        line=finding.line,
                    )
                )

        for edit in sorted(edits, key=lambda e: e.start, reverse=True):
            text = text[: edit.start] + edit.text + text[edit.end :]

        try:
            reparsed = self._parse(text.encode("utf-8"))
        except Exception as exc:  # pragma: no cover - defensive
            raise RedactionValidationError(f"re-parse failed: {exc}") from exc

        if reparsed.root_node.has_error:
            raise RedactionValidationError(
                "redaction produced syntactically invalid output"
            )

        replacements_count = len(edits)

        deduped: List[RedactionRecord] = []

        for record in records:
            if record not in deduped:
                deduped.append(record)

        return RedactionResult(
            redacted_text=text,
            records=deduped,
            blocked=blocked,
            replacements_count=replacements_count,
            state=state,
        )
