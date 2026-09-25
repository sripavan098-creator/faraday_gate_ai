from __future__ import annotations

from pathlib import Path
from typing import Optional

import yaml
from pydantic import ValidationError

from faraday.core.policy import Policy, default_policy


class ConfigError(Exception):
    """Raised when Faraday Gate configuration is missing, malformed, or invalid.

    Security principle:
    Configuration errors should fail closed for protected operations.
    """


def faraday_dir() -> Path:
    """Return the local `.faraday` directory for the current working directory."""

    return Path.cwd() / ".faraday"


def config_path() -> Path:
    """Return the primary config file path (`.faraday/config.yaml`)."""

    return faraday_dir() / "config.yaml"


def default_policy_path() -> Path:
    """Return the default policy path (`.faraday/policies/default.yaml`)."""

    return faraday_dir() / "policies" / "default.yaml"


def ensure_faraday_structure(base: Optional[Path] = None) -> Path:
    """Create the `.faraday` directory structure required by PRD FR-01."""

    root = base or faraday_dir()

    for subdir in ("policies", "audit", "cache", "reports"):
        (root / subdir).mkdir(parents=True, exist_ok=True)

    return root


def save_policy(policy: Policy, path: Optional[Path] = None) -> Path:
    """Save a Policy model to YAML, defaulting to `.faraday/config.yaml`."""

    target = path or config_path()
    target.parent.mkdir(parents=True, exist_ok=True)

    yaml_text = yaml.safe_dump(
        policy.model_dump(),
        sort_keys=False,
        allow_unicode=True,
    )

    target.write_text(yaml_text, encoding="utf-8")
    return target


def load_policy(path: Optional[Path] = None) -> Policy:
    """Load and validate a Policy model from YAML.

    Raises:
        ConfigError if the file is missing, YAML is invalid,
        or Pydantic validation fails.

    Security principle:
        Invalid strict policies must prevent protected execution.
    """

    target = path or config_path()

    if not target.exists():
        raise ConfigError(
            f"Missing Faraday config: {target}. Run 'faraday init' first."
        )

    try:
        raw_text = target.read_text(encoding="utf-8")
        data = yaml.safe_load(raw_text) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"Invalid YAML in {target}: {exc}") from exc
    except OSError as exc:
        raise ConfigError(f"Could not read {target}: {exc}") from exc

    if not isinstance(data, dict):
        raise ConfigError(
            f"Policy root must be a mapping in {target}, got {type(data).__name__}."
        )

    try:
        return Policy(**data)
    except ValidationError as exc:
        raise ConfigError(f"Policy validation failed for {target}: {exc}") from exc


def write_default_project_policy(force: bool = False) -> Path:
    """Write the default policy to `.faraday/policies/default.yaml`."""

    ensure_faraday_structure()

    target = default_policy_path()

    if target.exists() and not force:
        return target

    return save_policy(default_policy(), target)
