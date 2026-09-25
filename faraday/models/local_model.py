from __future__ import annotations

from typing import Optional


class MockLocalCoder:
    """Simulated local coder backend.

    Used for the competition MVP so the wrap flow can demonstrate a
    local-response path without claiming real model inference or NPU
    acceleration.

    Replace with a real ModelBackend implementation later.
    """

    name = "faraday-mock-coder"
    backend_name = "mock-local"
    device_name = "local"

    def generate(self, prompt: str, context: Optional[str] = None) -> str:
        prompt = (prompt or "").strip().replace("\n", " ")

        if len(prompt) > 160:
            prompt = prompt[:157] + "..."

        return (
            f"[{self.name}] Simulated local safe response generated. "
            f"No external egress. Task: {prompt or 'empty prompt'}"
        )

    def generate_blocked(self, blocked_count: int) -> str:
        return (
            f"[{self.name}] Operation blocked by Faraday Gate. "
            f"{blocked_count} blocking finding(s) detected. "
            f"No sensitive context was passed to an agent."
        )
