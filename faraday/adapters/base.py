from __future__ import annotations

from abc import ABC, abstractmethod
from typing import List, Optional, Sequence


class AgentAdapter(ABC):
    """Generic agent adapter interface.

    Adapters do not need to modify the target agent. The MVP uses the
    subprocess wrapper pattern.
    """

    name: str = "generic"

    @abstractmethod
    def matches(self, command: Sequence[str]) -> bool:
        """Return True if this adapter should handle the command."""

    @abstractmethod
    def extract_prompt(self, command: Sequence[str]) -> str:
        """Extract likely prompt/task text from the command.

        Security note:
            This returns text for scanning. It must not be stored raw in
            audit metadata.
        """


def extract_option(args: Sequence[str], option_names: Sequence[str]) -> Optional[str]:
    """Extract an option value.

    Supports:
        --option value
        --option=value
    """

    for index, arg in enumerate(args):
        for name in option_names:
            if arg == name and index + 1 < len(args):
                return args[index + 1]

            if arg.startswith(f"{name}="):
                return arg.split("=", 1)[1]

    return None


def join_positional_args(
    args: Sequence[str],
    skip_words: Sequence[str] = (),
) -> str:
    """Join positional arguments while skipping obvious options.

    This is heuristic only. Agent CLIs vary.
    """

    values: List[str] = []
    index = 0

    while index < len(args):
        arg = args[index]

        if arg in ("--prompt", "--task", "-p", "-t"):
            index += 2
            continue

        if arg.startswith("-"):
            index += 1
            continue

        if arg in skip_words:
            index += 1
            continue

        values.append(arg)
        index += 1

    return " ".join(values).strip()
