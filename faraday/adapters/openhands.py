from __future__ import annotations

from pathlib import Path
from typing import Sequence

from faraday.adapters.base import AgentAdapter, extract_option, join_positional_args


class OpenHandsAdapter(AgentAdapter):
    """Adapter for OpenHands-style CLIs.

    Examples:
        openhands run --task "Fix failing tests"
        openhands --task "Fix failing tests"
    """

    name = "openhands"

    def matches(self, command: Sequence[str]) -> bool:
        if not command:
            return False

        executable = Path(command[0]).name.lower()

        return "openhands" in executable or "hands" in executable

    def extract_prompt(self, command: Sequence[str]) -> str:
        args = list(command[1:])

        option_value = extract_option(args, ("--task", "-t"))

        if option_value:
            return option_value.strip()

        return join_positional_args(args, skip_words=("run",))
