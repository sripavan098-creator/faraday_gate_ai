from __future__ import annotations

import math
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List

from faraday.core.policy import Policy
from faraday.scanners.pipeline import scan_text


@dataclass
class BenchmarkResult:
    iterations: int
    payload_bytes: int
    payload_mb: float
    findings_last: int
    total_seconds: float
    mean_ms: float
    p50_ms: float
    p95_ms: float
    mb_per_second: float
    notes: List[str] = field(default_factory=list)


def percentile(sorted_values: List[float], percent: float) -> float:
    """Linear interpolated percentile."""

    if not sorted_values:
        return 0.0

    k = (len(sorted_values) - 1) * percent
    floor_index = int(math.floor(k))
    ceil_index = int(math.ceil(k))

    if floor_index == ceil_index:
        return sorted_values[floor_index]

    return (
        sorted_values[floor_index] * (ceil_index - k)
        + sorted_values[ceil_index] * (k - floor_index)
    )


def generate_payload(target_bytes: int) -> str:
    """Generate a synthetic benchmark payload.

    The payload contains fake sensitive patterns so scanners are exercised.
    All values are fake and safe.
    """

    chunk = (
        "Benchmark sample text for Faraday Gate scanner throughput.\n"
        "Contact benchmark@example.com for fake details.\n"
        'BENCHMARK_KEY = "sk_test_fake1234567890"\n'
        "Normal code line: value = compute(42)\n"
        "Another harmless line for performance measurement.\n"
    )

    payload = ""

    while len(payload.encode("utf-8")) < max(target_bytes, 1):
        payload += chunk

    return payload


def run_scanner_benchmark(
    policy: Policy,
    iterations: int = 20,
    payload_bytes: int = 50_000,
) -> BenchmarkResult:
    """Benchmark deterministic scanner throughput.

    This benchmark does not claim NPU acceleration. It measures the local
    deterministic scanner pipeline only.
    """

    if iterations < 1:
        raise ValueError("iterations must be >= 1")

    payload = generate_payload(payload_bytes)
    actual_payload_bytes = len(payload.encode("utf-8"))

    latencies_ms: List[float] = []
    findings_last = 0

    for _ in range(iterations):
        start = time.perf_counter()

        findings = scan_text(
            payload,
            origin="benchmark",
            policy=policy,
        )

        elapsed_ms = (time.perf_counter() - start) * 1000.0

        latencies_ms.append(elapsed_ms)
        findings_last = len(findings)

    total_seconds = sum(latencies_ms) / 1000.0
    mean_ms = total_seconds * 1000.0 / iterations if iterations else 0.0

    sorted_latencies = sorted(latencies_ms)

    p50_ms = percentile(sorted_latencies, 0.50)
    p95_ms = percentile(sorted_latencies, 0.95)

    payload_mb = actual_payload_bytes / 1_000_000.0
    mb_per_second = (payload_mb * iterations) / total_seconds if total_seconds else 0.0

    notes = [
        "Deterministic scanner pipeline only.",
        "Local model inference not measured.",
        "NPU acceleration not claimed unless verified.",
        "Payload contains fake sensitive patterns for scanner exercise.",
    ]

    return BenchmarkResult(
        iterations=iterations,
        payload_bytes=actual_payload_bytes,
        payload_mb=payload_mb,
        findings_last=findings_last,
        total_seconds=total_seconds,
        mean_ms=mean_ms,
        p50_ms=p50_ms,
        p95_ms=p95_ms,
        mb_per_second=mb_per_second,
        notes=notes,
    )


def benchmark_to_dict(result: BenchmarkResult) -> Dict[str, Any]:
    """JSON-safe benchmark representation."""

    return asdict(result)
