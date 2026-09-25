from __future__ import annotations

from pathlib import Path
from typing import Sequence

from faraday.adapters.base import AgentAdapter, extract_option, join_positional_args


class QwenCoderAdapter(AgentAdapter):
    """Adapter for Qwen Coder-style CLIs.

    Examples:
        qwen-coder "Fix login bug"
        qwen-coder --prompt "Fix login bug"
        qwen-coder --prompt="Fix login bug"
    """

    name = "qwen-coder"

    def matches(self, command: Sequence[str]) -> bool:
        if not command:
            return False

        executable = Path(command[0]).name.lower()

        return "qwen" in executable or "coder" in executable

    def extract_prompt(self, command: Sequence[str]) -> str:
        args = list(command[1:])

        option_value = extract_option(args, ("--prompt", "-p"))

        if option_value:
            return option_value.strip()

        return join_positional_args(args)
