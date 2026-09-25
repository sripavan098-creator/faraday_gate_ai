from __future__ import annotations

from typing import List, Literal

from pydantic import BaseModel, Field

Mode = Literal[
    "strict-local",
    "sanitize-external",
    "observe-only",
]

PolicyAction = Literal[
    "allow",
    "warn",
    "redact",
    "ask",
    "block",
    "quarantine",
]

RedactionLevel = Literal[
    "low",
    "medium",
    "high",
]

EgressMode = Literal[
    "deny",
    "allow",
]

DEFAULT_DENY_PATHS = [
    ".env",
    ".env.*",
    "**/*.pem",
    "**/*.key",
    "**/secrets/**",
    "~/.ssh/**",
    "~/.aws/**",
]


class PathsPolicy(BaseModel):
    """Path inclusion/exclusion policy.

    MVP behavior:
    - deny list is enforced first
    - allow list is reserved for future least-context workflows
    """

    allow: List[str] = Field(default_factory=list)
    deny: List[str] = Field(default_factory=lambda: list(DEFAULT_DENY_PATHS))


class RedactionPolicy(BaseModel):
    """Redaction behavior.

    preserve_syntax:
        If true, redaction should attempt to keep code/text syntactically valid.

    reversible:
        If true, a local encrypted vault may be used in hard mode.
        Default must remain false for safety.
    """

    level: RedactionLevel = "high"
    reversible: bool = False
    preserve_syntax: bool = True


class ActionPolicy(BaseModel):
    """A simple policy action for a scanner category."""

    action: PolicyAction = "block"


class NetworkPolicy(BaseModel):
    """Egress policy.

    In strict-local mode this should be deny.
    In sanitize-external mode it may be allow, but sensitive content
    must still pass through policy/scanners.
    """

    egress: EgressMode = "deny"


class AuditPolicy(BaseModel):
    """Audit behavior.

    hash_chain:
        Append-only SHA-256 hash-chained events.

    sqlite:
        Store indexed metadata in SQLite.

    jsonl_export:
        Export portable JSONL audit events.
    """

    hash_chain: bool = True
    sqlite: bool = True
    jsonl_export: bool = True


class Policy(BaseModel):
    """Root Faraday Gate policy.

    This is the typed representation of `.faraday/config.yaml`.
    """

    policy_version: str = "default-v1"
    mode: Mode = "strict-local"

    paths: PathsPolicy = Field(default_factory=PathsPolicy)
    redaction: RedactionPolicy = Field(default_factory=RedactionPolicy)

    secrets: ActionPolicy = Field(default_factory=lambda: ActionPolicy(action="block"))
    pii: ActionPolicy = Field(default_factory=lambda: ActionPolicy(action="redact"))
    prompt_injection: ActionPolicy = Field(
        default_factory=lambda: ActionPolicy(action="block")
    )
    commands: ActionPolicy = Field(default_factory=lambda: ActionPolicy(action="block"))

    network: NetworkPolicy = Field(default_factory=NetworkPolicy)
    audit: AuditPolicy = Field(default_factory=AuditPolicy)


def default_policy() -> Policy:
    """Return the default strict-local competition policy."""

    return Policy(
        policy_version="default-v1",
        mode="strict-local",
        paths=PathsPolicy(allow=[], deny=list(DEFAULT_DENY_PATHS)),
        redaction=RedactionPolicy(level="high", reversible=False, preserve_syntax=True),
        secrets=ActionPolicy(action="block"),
        pii=ActionPolicy(action="redact"),
        prompt_injection=ActionPolicy(action="block"),
        commands=ActionPolicy(action="block"),
        network=NetworkPolicy(egress="deny"),
        audit=AuditPolicy(hash_chain=True, sqlite=True, jsonl_export=True),
    )
