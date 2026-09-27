"""Tests for the policy engine and config loader.

The governing rule is fail-closed: a missing, unreadable, or schema-invalid
policy must raise rather than silently falling back to something permissive.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from faraday.config import (
    ConfigError,
    ensure_faraday_structure,
    load_policy,
    save_policy,
)
from faraday.core.policy import Policy, default_policy


def test_default_policy_is_strict_local():
    policy = default_policy()

    assert policy.mode == "strict-local"
    assert policy.network.egress == "deny"


def test_default_policy_actions_match_security_requirements():
    policy = default_policy()

    assert policy.secrets.action == "block"
    assert policy.pii.action == "redact"
    assert policy.prompt_injection.action == "block"
    assert policy.commands.action == "block"


def test_default_policy_denies_sensitive_paths():
    deny = default_policy().paths.deny

    assert ".env" in deny
    assert ".env.*" in deny
    assert "**/*.pem" in deny
    assert "**/*.key" in deny
    assert "~/.ssh/**" in deny
    assert "~/.aws/**" in deny


def test_default_policy_enables_audit_chain():
    audit = default_policy().audit

    assert audit.hash_chain is True
    assert audit.jsonl_export is True


def test_policy_roundtrip(tmp_path):
    path = tmp_path / "policy.yaml"
    policy = default_policy()
    policy.mode = "observe-only"

    save_policy(policy, path)
    loaded = load_policy(path)

    assert loaded.mode == "observe-only"
    assert loaded.policy_version == policy.policy_version
    assert loaded.paths.deny == policy.paths.deny


def test_load_policy_missing_file_raises_config_error(tmp_path):
    with pytest.raises(ConfigError):
        load_policy(tmp_path / "does-not-exist.yaml")


def test_load_policy_invalid_yaml_raises_config_error(tmp_path):
    path = tmp_path / "policy.yaml"
    path.write_text("mode: strict-local\n  bad: [indent\n")

    with pytest.raises(ConfigError):
        load_policy(path)


def test_load_policy_invalid_schema_raises_config_error(tmp_path):
    path = tmp_path / "policy.yaml"
    # `mode` is not in the Mode literal.
    path.write_text("policy_version: v1\nmode: totally-open\n")

    with pytest.raises(ConfigError):
        load_policy(path)


def test_load_policy_invalid_action_raises_config_error(tmp_path):
    path = tmp_path / "policy.yaml"
    path.write_text(
        "policy_version: v1\n"
        "mode: strict-local\n"
        "secrets:\n"
        "  action: ignore-everything\n"
    )

    with pytest.raises(ConfigError):
        load_policy(path)


def test_invalid_mode_literal_raises_validation_error():
    with pytest.raises(ValidationError):
        Policy(policy_version="v1", mode="not-a-mode")


def test_ensure_faraday_structure_creates_directories(tmp_path):
    base = ensure_faraday_structure(tmp_path)

    assert (base / "audit").is_dir()
    assert (base / "policies").is_dir()
    assert (base / "cache").is_dir()
    assert (base / "reports").is_dir()


def test_ensure_faraday_structure_is_idempotent(tmp_path):
    first = ensure_faraday_structure(tmp_path)
    second = ensure_faraday_structure(tmp_path)

    assert first == second
    assert (second / "audit").is_dir()


def test_reversible_redaction_defaults_off():
    # Reversible redaction would require storing the original value, which
    # contradicts the "never store raw secrets" rule.
    assert default_policy().redaction.reversible is False
