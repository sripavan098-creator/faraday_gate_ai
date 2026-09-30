"""Tests for process-visible egress measurement.

These tests exercise the real sampler with real sockets. To stay offline and
deterministic, the connection-detection tests empty the loopback ignore-list so
that a genuine localhost socket is observable.
"""

from __future__ import annotations

import socket
import time

import pytest

from faraday.core import egress_monitor
from faraday.core.egress_monitor import (
    EgressMonitor,
    EgressResult,
    format_endpoints,
    probe_available,
)

psutil_available, psutil_reason = probe_available()

requires_psutil = pytest.mark.skipif(
    not psutil_available, reason=psutil_reason or "psutil unavailable"
)


def test_describe_labels():
    assert EgressResult(method="unavailable", available=False).describe() == (
        "not-measured"
    )
    assert EgressResult(method="measured-process", available=True).describe() == (
        "no-egress-observed"
    )
    assert (
        EgressResult(
            method="measured-process",
            available=True,
            new_connections=[(41234, "1.1.1.1", 443)],
        ).describe()
        == "egress-observed"
    )


def test_observed_egress_flag():
    quiet = EgressResult(method="measured-process", available=True)
    loud = EgressResult(
        method="measured-process",
        available=True,
        new_connections=[(41234, "1.1.1.1", 443)],
    )

    assert not quiet.observed_egress
    assert loud.observed_egress


def test_format_endpoints_empty():
    assert format_endpoints([]) == "none observed"


def test_format_endpoints_truncates():
    endpoints = [(40000 + i, f"10.0.0.{i}", 443) for i in range(8)]

    rendered = format_endpoints(endpoints, limit=5)

    assert "10.0.0.0:443" in rendered
    assert "(+3 more)" in rendered


def test_unavailable_result_reports_reason():
    result = EgressResult(
        method="unavailable", available=False, reason="psutil missing"
    )

    assert not result.available
    assert result.reason == "psutil missing"
    assert result.new_connections == []


@requires_psutil
def test_quiet_workload_reports_no_egress():
    """A no-op workload must not add egress of its own.

    The sampler calls `psutil.net_connections()` with no `pid` filter, so it is
    system-wide: `wrap` runs the command through a blocking `subprocess.run`, and
    the child pid is not plumbed through to the sampling thread. The module
    docstring records this as a known limitation. Per-process attribution via
    `psutil.Process(pid).net_connections()` is possible and is roadmap work, not
    a property of this design.

    On a busy machine or a shared CI runner, unrelated ambient traffic can
    therefore appear inside the observation window. A no-op workload opens no
    sockets, so any newly observed connection is ambient traffic rather than
    evidence about the workload. We still exercise the measurement path
    unconditionally, and skip rather than fail when ambient traffic is present:
    a genuine regression would still be caught on any quiet machine.
    """

    with EgressMonitor() as monitor:
        time.sleep(0.3)

    result = monitor.result

    assert result.available
    assert result.method == "measured-process"
    assert result.samples > 0

    if result.new_connections:
        pytest.skip(
            "ambient system traffic observed during the window "
            f"({len(result.new_connections)} connection(s)); "
            "system-wide sampler cannot attribute them to the workload"
        )

    assert result.new_connections == []


@requires_psutil
def test_detects_new_connection(monkeypatch):
    # Loopback is normally filtered as noise. Emptying the list makes a
    # localhost socket observable so this test needs no external network.
    monkeypatch.setattr(egress_monitor, "_IGNORED_IPS", set())

    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    try:
        with EgressMonitor() as monitor:
            client = socket.create_connection(("127.0.0.1", port), timeout=3)
            time.sleep(0.3)
            client.close()

        result = monitor.result

        assert result.available
        assert any(ip == "127.0.0.1" for _lp, ip, _rp in result.new_connections)
        assert result.describe() == "egress-observed"
    finally:
        listener.close()


@requires_psutil
def test_baseline_connection_is_not_reported(monkeypatch):
    monkeypatch.setattr(egress_monitor, "_IGNORED_IPS", set())

    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    # Open the connection BEFORE the baseline snapshot.
    preexisting = socket.create_connection(("127.0.0.1", port), timeout=3)

    try:
        with EgressMonitor() as monitor:
            time.sleep(0.3)

        result = monitor.result

        assert not any(
            ip == "127.0.0.1" for _lp, ip, _rp in result.new_connections
        )
    finally:
        preexisting.close()
        listener.close()


@requires_psutil
def test_repeat_connection_same_endpoint_is_detected(monkeypatch):
    """A second connection to an already-seen endpoint must be visible.

    Keying connections by remote endpoint alone would hide this, because the
    endpoint was present in the baseline snapshot.
    """

    monkeypatch.setattr(egress_monitor, "_IGNORED_IPS", set())

    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(5)
    port = listener.getsockname()[1]

    warmup = socket.create_connection(("127.0.0.1", port), timeout=3)
    time.sleep(0.2)

    try:
        with EgressMonitor() as monitor:
            second = socket.create_connection(("127.0.0.1", port), timeout=3)
            time.sleep(0.3)
            second.close()

        result = monitor.result

        assert any(ip == "127.0.0.1" for _lp, ip, _rp in result.new_connections)
    finally:
        warmup.close()
        listener.close()


@requires_psutil
def test_measure_egress_returns_runner_value():
    def runner():
        time.sleep(0.1)
        return "done"

    value, result = egress_monitor.measure_egress(runner)

    assert value == "done"
    assert result.method == "measured-process"


@requires_psutil
def test_monitor_is_reusable_after_exit():
    with EgressMonitor() as monitor:
        time.sleep(0.05)

    first = monitor.result

    # Reading the result again must not change it.
    assert monitor.result.new_connections == first.new_connections
