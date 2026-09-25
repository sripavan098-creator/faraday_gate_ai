from __future__ import annotations

from typing import Sequence

from faraday.adapters.base import AgentAdapter


class GenericAdapter(AgentAdapter):
    """Fallback adapter for unknown CLI tools.

    It treats everything after the executable as likely prompt/context.
    """

    name = "generic"

    def matches(self, command: Sequence[str]) -> bool:
        return True

    def extract_prompt(self, command: Sequence[str]) -> str:
        if not command:
            return ""

        if len(command) == 1:
            return command[0]

        return " ".join(command[1:]).strip()
