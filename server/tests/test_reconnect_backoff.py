"""Redis streams and wake subscribers share the same bounded retry schedule."""

import pytest

from aweb.reconnect import ReconnectBackoff


def test_first_failure_waits_initial_delay_and_doubles_next_failure():
    backoff = ReconnectBackoff(initial_delay=0.1, maximum_delay=5.0)
    assert backoff.due(0)
    assert backoff.schedule(10) == 0.1
    assert not backoff.due(10.09)
    assert backoff.due(10.1)
    assert backoff.schedule(11) == 0.2
    assert not backoff.due(11.19)
    assert backoff.due(11.2)


@pytest.mark.parametrize("initial,maximum", [(0.1, 5.0), (0.5, 10.0)])
def test_failures_cap_and_success_resets_each_stream_independently(initial, maximum):
    backoff = ReconnectBackoff(initial_delay=initial, maximum_delay=maximum)
    untouched = ReconnectBackoff(initial_delay=initial, maximum_delay=maximum)
    delays = [backoff.schedule(float(now)) for now in range(20)]
    assert delays[0] == initial
    assert delays[-1] == maximum
    assert all(delay <= maximum for delay in delays)
    assert untouched.due(0)
    backoff.reset()
    assert backoff.due(0)
    assert backoff.schedule(100) == initial
