"""Process-visible network egress measurement.

The MVP previously labeled egress as `not-measured` whenever `--execute` ran a
real subprocess, because Faraday did not observe the process's sockets. This
module turns that into a real measurement.

Measurement method
------------------
A background thread samples `psutil.net_connections(kind="inet")` before,
during, and after the wrapped command, and records remote endpoints that were
not present in the baseline snapshot. That gives a `measured-process` label
when the sampler is available.

Honest limitations (recorded in the result, not hidden)
-------------------------------------------------------
- Sampling is **polling**, so a connection that opens and closes entirely
  between two samples can be missed. This is detection, not interception.
- `psutil.net_connections` may require elevated privileges on some platforms;
  the sampler reports `unavailable` rather than silently reporting zero.
- Connections are attributed by *appearance during the window*, not by process
  ownership, so unrelated system traffic can appear if it starts at the same
  time. Faraday does not create such traffic itself.
- This does **not** block egress. Policy denial is enforced separately by the
  command guard; this module only measures.

Because of the first point, a result of "no new connections" means
"none observed", never "none happened".
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import List, Optional, Set, Tuple

from faraday.core.session import EgressMethod

_SAMPLE_INTERVAL_SECONDS = 0.05

# Endpoints that are always noise: loopback and unspecified addresses.
_IGNORED_IPS = {"127.0.0.1", "::1", "0.0.0.0", "::"}


@dataclass
class EgressResult:
    """Outcome of monitoring one wrapped command."""

    method: str  # "measured-process" | "unavailable"
    available: bool
    new_connections: List[Tuple[int, str, int]] = field(default_factory=list)
    baseline_count: int = 0
    samples: int = 0
    reason: Optional[str] = None

    @property
    def observed_egress(self) -> bool:
        return bool(self.new_connections)

    def describe(self) -> str:
        """Return a human-readable egress summary for terminal output.

        This is a display string only. It is not the audit `method` value,
        which stays within the `EgressMethod` vocabulary.
        """

        if not self.available:
            return "not-measured"

        if self.new_connections:
            return "egress-observed"

        return "no-egress-observed"

    @property
    def audit_method(self) -> EgressMethod:
        """Return the `EgressMethod` literal describing how this was obtained."""

        return "measured-process" if self.available else "not-measured"


def _remote_endpoints() -> Set[Tuple[int, str, int]]:
    """Return connections keyed by (local_port, remote_ip, remote_port).

    The local port is part of the identity on purpose. Keying on the remote
    endpoint alone would hide a *repeat* connection to an endpoint that was
    already present before the command ran, which is the common case for
    chatty tools.

    Connections in `TIME_WAIT` are included: they are short-lived connections
    that already closed, and counting them is what lets a final snapshot catch
    egress that our polling interval missed.
    """

    import psutil

    connections: Set[Tuple[int, str, int]] = set()

    for conn in psutil.net_connections(kind="inet"):
        if not conn.raddr or not conn.laddr:
            continue

        ip = conn.raddr.ip

        if ip in _IGNORED_IPS:
            continue

        connections.add((conn.laddr.port, ip, conn.raddr.port))

    return connections


def probe_available() -> Tuple[bool, Optional[str]]:
    """Check whether socket sampling works in this environment."""

    try:
        import psutil  # noqa: F401

        _remote_endpoints()

        return True, None
    except ImportError:
        return False, "psutil is not installed (install the 'egress' extra)"
    except Exception as exc:
        return False, f"socket sampling unavailable: {type(exc).__name__}: {exc}"


class EgressMonitor:
    """Samples socket state around a wrapped command."""

    def __init__(self, interval: float = _SAMPLE_INTERVAL_SECONDS) -> None:
        self.interval = interval
        self._baseline: Set[Tuple[int, str, int]] = set()
        self._observed: Set[Tuple[int, str, int]] = set()
        self._samples = 0
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._available = False
        self._reason: Optional[str] = None

    def __enter__(self) -> "EgressMonitor":
        self._available, self._reason = probe_available()

        if not self._available:
            return self

        try:
            self._baseline = _remote_endpoints()
        except Exception as exc:  # pragma: no cover - platform dependent
            self._available = False
            self._reason = f"baseline snapshot failed: {exc}"
            return self

        self._thread = threading.Thread(target=self._sample_loop, daemon=True)
        self._thread.start()

        return self

    def _sample_loop(self) -> None:
        while not self._stop.is_set():
            try:
                self._observed |= _remote_endpoints()
                self._samples += 1
            except Exception:
                # A transient sampling error must not abort the measurement.
                pass

            self._stop.wait(self.interval)

    def __exit__(self, exc_type, exc, tb) -> None:
        self._stop.set()

        if self._thread is not None:
            self._thread.join(timeout=2.0)

        if self._available:
            try:
                self._observed |= _remote_endpoints()
            except Exception:
                pass

    @property
    def result(self) -> EgressResult:
        if not self._available:
            return EgressResult(
                method="unavailable",
                available=False,
                reason=self._reason,
            )

        new = sorted(self._observed - self._baseline)

        return EgressResult(
            method="measured-process",
            available=True,
            new_connections=new,
            baseline_count=len(self._baseline),
            samples=self._samples,
        )


def measure_egress(command_runner) -> Tuple[object, EgressResult]:
    """Run `command_runner()` while sampling sockets.

    Returns the runner's return value and the egress result. The runner is
    invoked exactly once.
    """

    with EgressMonitor() as monitor:
        outcome = command_runner()

    return outcome, monitor.result


def format_endpoints(
    endpoints: List[Tuple[int, str, int]], limit: int = 5
) -> str:
    """Render endpoints for terminal output, truncating for readability."""

    if not endpoints:
        return "none observed"

    shown = ", ".join(
        f"{ip}:{port}" for _local_port, ip, port in endpoints[:limit]
    )

    if len(endpoints) > limit:
        shown += f" (+{len(endpoints) - limit} more)"

    return shown


def sleep_for_measurement(seconds: float = 0.001) -> None:
    """Small helper used by tests to give the sampler a chance to run."""

    time.sleep(seconds)
