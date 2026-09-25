from __future__ import annotations

from typing import List, Sequence

from faraday.adapters.base import AgentAdapter
from faraday.adapters.generic import GenericAdapter
from faraday.adapters.openhands import OpenHandsAdapter
from faraday.adapters.qwen_coder import QwenCoderAdapter

ADAPTERS: List[AgentAdapter] = [
    QwenCoderAdapter(),
    OpenHandsAdapter(),
    GenericAdapter(),
]


def get_adapter(command: Sequence[str]) -> AgentAdapter:
    """Return the first adapter that matches the command.

    The generic adapter is last and always matches.
    """

    for adapter in ADAPTERS:
        if adapter.matches(command):
            return adapter

    return GenericAdapter()
