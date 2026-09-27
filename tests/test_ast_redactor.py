"""Tests for AST-aware redaction.

The AST redactor exists because the heuristic text redactor corrupts
structured code. These tests pin the properties that motivated it:

- interpolations inside f-strings survive
- string prefixes (`f`, `r`) survive
- quoting survives and the output re-parses
- a finding spanning multiple literal runs emits one placeholder
- non-secret string literals are left alone
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from faraday.redactor.ast_redactor import (
    ASTRedactor,
    RedactionValidationError,
    language_for_path,
)
from faraday.redactor.text_redactor import PlaceholderState
from faraday.scanners.pipeline import scan_text

FIXTURES = Path(__file__).parent / "fixtures" / "ast"

FAKE_STRIPE = "sk_test_fake1234567890"


def _redact(text: str, language: str = "python", mode: str = "sensitive"):
    findings = scan_text(text, origin="t.py")
    redactor = ASTRedactor(language)

    if not redactor.available:
        pytest.skip(f"tree-sitter grammar {language!r} not installed")

    return redactor.redact(text, findings, mode=mode)


def test_language_detection():
    assert language_for_path("a/b/c.py") == "python"
    assert language_for_path("x.ts") == "typescript"
    assert language_for_path("x.jsx") == "javascript"
    assert language_for_path("config.yaml") is None
    assert language_for_path("README.md") is None


def test_grammar_loads():
    assert ASTRedactor("python").available


def test_plain_assignment_keeps_key_and_quotes():
    result = _redact(f'STRIPE_KEY = "{FAKE_STRIPE}"\n')

    assert result.redacted_text == 'STRIPE_KEY = "[SECRET_1]"\n'
    ast.parse(result.redacted_text)


def test_fstring_interpolations_survive():
    result = _redact('db_url = f"postgres://{user}:{SECRET}@localhost/db"\n')

    # This is the regression the AST redactor was built for. The text redactor
    # produced `db_url = f"[SECRET_1]"`, destroying both interpolations.
    assert "{user}" in result.redacted_text
    assert "{SECRET}" in result.redacted_text
    assert "postgres://" not in result.redacted_text
    ast.parse(result.redacted_text)


def test_finding_spanning_multiple_literal_runs_emits_one_placeholder():
    text = f'u = f"a{{var}}{FAKE_STRIPE}b{{tail}}"\n'

    result = _redact(text)

    assert result.redacted_text.count("[SECRET_") == 1
    assert result.replacements_count >= 1
    ast.parse(result.redacted_text)


def test_raw_string_prefix_survives():
    result = _redact(f'k = r"{FAKE_STRIPE}"\n')

    assert result.redacted_text.startswith("k = r")
    ast.parse(result.redacted_text)


def test_non_secret_literal_is_untouched():
    result = _redact('password = "hunter2"\n')

    assert result.redacted_text == 'password = "hunter2"\n'


def test_output_is_valid_python_for_multiple_secrets():
    text = f'a = "{FAKE_STRIPE}"\nb = "{FAKE_STRIPE}"\n'

    result = _redact(text)

    ast.parse(result.redacted_text)

    # Same value in one session must reuse the same placeholder.
    assert result.redacted_text.count("[SECRET_1]") == 2


def test_unparseable_input_is_rejected():
    redactor = ASTRedactor("python")

    with pytest.raises(RedactionValidationError):
        redactor.redact("def broken(:\n", [], mode="sensitive")


def test_unavailable_grammar_raises():
    redactor = ASTRedactor("cobol")

    assert not redactor.available

    with pytest.raises(RedactionValidationError):
        redactor.redact("x = 1\n", [], mode="sensitive")


def test_placeholder_state_is_shared():
    state = PlaceholderState()
    redactor = ASTRedactor("python")

    text = f'a = "{FAKE_STRIPE}"\n'
    findings = scan_text(text, origin="t.py")

    redactor.redact(text, findings, mode="sensitive", state=state)

    assert state.counters


def test_golden_fixture_matches_expected_output():
    source = (FIXTURES / "input.py").read_text()
    expected = (FIXTURES / "expected.py").read_text()

    findings = scan_text(source, origin=str(FIXTURES / "input.py"))

    result = ASTRedactor("python").redact(source, findings, mode="sensitive")

    assert result.redacted_text == expected
    ast.parse(result.redacted_text)
