"""The bounded freshness cache shared by remote authority reads.

The cache is driven by a test clock for its freshness window and by the real
event loop for refresh timeouts and concurrency. Each fetch below is an
explicit answer the authority gives, so the assertions are about what the
cache serves, never about the fetch.
"""

from __future__ import annotations

import asyncio

import pytest

from aweb_naapp.runtime.freshness import FRESHNESS_CEILING_SECONDS, FreshnessCache, RefreshTimedOut


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


class Authority:
    """Answers in order; each call records that the authority was asked."""

    def __init__(self, *answers) -> None:
        self.answers = list(answers)
        self.calls = 0

    async def __call__(self):
        self.calls += 1
        answer = self.answers.pop(0)
        if isinstance(answer, BaseException):
            raise answer
        if callable(answer):
            return await answer()
        return answer


def _cache(clock: Clock, *, refresh_timeout: float = 5.0) -> FreshnessCache:
    return FreshnessCache(refresh_timeout=refresh_timeout, monotonic=clock)


async def test_an_answer_is_reused_inside_its_window():
    clock = Clock()
    cache = _cache(clock)
    authority = Authority(("granted", 30))

    first = await cache.get("team-a", authority)
    clock.now += 29.9
    second = await cache.get("team-a", authority)

    assert (first.value, second.value) == ("granted", "granted")
    assert authority.calls == 1


@pytest.mark.parametrize(("max_age", "window"), [(30, 30), (60, 60), (61, 60), (3600, 60)])
async def test_the_window_is_the_answers_max_age_capped_at_sixty_seconds(max_age, window):
    clock = Clock()
    cache = _cache(clock)
    authority = Authority(("old", max_age), ("new", max_age))

    fresh = await cache.get("team-a", authority)
    clock.now += window - 0.001
    inside = await cache.get("team-a", authority)
    clock.now += 0.001
    at_expiry = await cache.get("team-a", authority)

    assert fresh.fresh_until == 1000.0 + window
    assert (inside.value, at_expiry.value) == ("old", "new")
    assert FRESHNESS_CEILING_SECONDS == 60


async def test_the_window_counts_from_the_request_not_from_receipt():
    clock = Clock()
    cache = _cache(clock)

    async def slow_answer():
        clock.now += 4
        return ("granted", 60)

    fresh = await cache.get("team-a", Authority(slow_answer))

    assert fresh.fresh_until == 1000.0 + 60


async def test_a_late_joiner_gets_the_deadline_of_the_refresh_it_joined():
    clock = Clock()
    cache = _cache(clock)
    answered = asyncio.Event()

    async def held_answer():
        await answered.wait()
        return ("granted", 60)

    authority = Authority(held_answer)
    first = asyncio.create_task(cache.get("team-a", authority))
    await asyncio.sleep(0)
    clock.now += 3
    late = asyncio.create_task(cache.get("team-a", authority))
    await asyncio.sleep(0)
    answered.set()

    assert {(await first).fresh_until, (await late).fresh_until} == {1000.0 + 60}
    assert authority.calls == 1


async def test_an_expired_entry_is_never_served_when_the_refresh_fails():
    clock = Clock()
    cache = _cache(clock)
    outage = ConnectionError("authority down")
    authority = Authority(("granted", 60), outage)

    await cache.get("team-a", authority)
    clock.now += 60
    with pytest.raises(ConnectionError) as raised:
        await cache.get("team-a", authority)

    assert raised.value is outage


async def test_a_failure_is_not_cached():
    clock = Clock()
    cache = _cache(clock)
    authority = Authority(ConnectionError("authority down"), ("granted", 60))

    with pytest.raises(ConnectionError):
        await cache.get("team-a", authority)
    recovered = await cache.get("team-a", authority)

    assert recovered.value == "granted"
    assert authority.calls == 2


async def test_a_definitive_negative_answer_is_cached_for_its_window():
    clock = Clock()
    cache = _cache(clock)
    authority = Authority((None, 60), ("granted", 60))

    first = await cache.get("team-a", authority)
    clock.now += 59
    second = await cache.get("team-a", authority)

    assert (first.value, second.value) == (None, None)
    assert authority.calls == 1


async def test_concurrent_misses_share_one_refresh():
    clock = Clock()
    cache = _cache(clock)
    release = asyncio.Event()

    async def answer_when_released():
        await release.wait()
        return ("granted", 60)

    authority = Authority(answer_when_released)
    waiters = [asyncio.create_task(cache.get("team-a", authority)) for _ in range(5)]
    await asyncio.sleep(0)
    release.set()
    results = await asyncio.gather(*waiters)

    assert [result.value for result in results] == ["granted"] * 5
    assert authority.calls == 1


async def test_a_shared_refresh_failure_reaches_every_waiter():
    clock = Clock()
    cache = _cache(clock)
    release = asyncio.Event()

    async def fail_when_released():
        await release.wait()
        raise ConnectionError("authority down")

    authority = Authority(fail_when_released)
    waiters = [asyncio.create_task(cache.get("team-a", authority)) for _ in range(3)]
    await asyncio.sleep(0)
    release.set()
    results = await asyncio.gather(*waiters, return_exceptions=True)

    assert all(isinstance(result, ConnectionError) for result in results)
    assert authority.calls == 1


async def test_callers_wait_for_the_refresh_of_an_expired_entry_instead_of_reading_it():
    clock = Clock()
    cache = _cache(clock)
    release = asyncio.Event()

    async def new_answer_when_released():
        await release.wait()
        return ("new", 60)

    authority = Authority(("old", 60), new_answer_when_released)
    await cache.get("team-a", authority)
    clock.now += 60
    refreshing = asyncio.create_task(cache.get("team-a", authority))
    await asyncio.sleep(0)
    joining = asyncio.create_task(cache.get("team-a", authority))
    await asyncio.sleep(0)

    assert not refreshing.done() and not joining.done()
    release.set()
    assert ((await refreshing).value, (await joining).value) == ("new", "new")
    assert authority.calls == 2


async def test_a_refresh_that_outlasts_its_timeout_fails_closed_and_is_not_cached():
    clock = Clock()
    cache = _cache(clock, refresh_timeout=0.05)
    never = asyncio.Event()

    async def hang():
        await never.wait()

    authority = Authority(hang, ("granted", 60))
    waiters = [asyncio.create_task(cache.get("team-a", authority)) for _ in range(3)]
    results = await asyncio.wait_for(asyncio.gather(*waiters, return_exceptions=True), timeout=1)
    recovered = await asyncio.wait_for(cache.get("team-a", authority), timeout=1)

    assert all(isinstance(result, RefreshTimedOut) for result in results)
    assert recovered.value == "granted"
    assert authority.calls == 2


async def test_a_waiter_that_joins_late_is_bounded_by_the_shared_refresh_deadline():
    clock = Clock()
    cache = _cache(clock, refresh_timeout=0.2)
    never = asyncio.Event()

    async def hang():
        await never.wait()

    authority = Authority(hang)
    first = asyncio.create_task(cache.get("team-a", authority))
    await asyncio.sleep(0.15)
    loop = asyncio.get_running_loop()
    joined_at = loop.time()
    with pytest.raises(RefreshTimedOut):
        await asyncio.wait_for(cache.get("team-a", authority), timeout=1)

    assert loop.time() - joined_at < 0.15
    with pytest.raises(RefreshTimedOut):
        await asyncio.wait_for(first, timeout=1)


async def test_a_cancelled_waiter_does_not_cancel_the_shared_refresh():
    clock = Clock()
    cache = _cache(clock)
    release = asyncio.Event()

    async def answer_when_released():
        await release.wait()
        return ("granted", 60)

    authority = Authority(answer_when_released)
    cancelled = asyncio.create_task(cache.get("team-a", authority))
    remaining = asyncio.create_task(cache.get("team-a", authority))
    await asyncio.sleep(0)
    cancelled.cancel()
    await asyncio.sleep(0)
    release.set()

    assert (await remaining).value == "granted"
    with pytest.raises(asyncio.CancelledError):
        await cancelled
    assert authority.calls == 1


async def test_keys_are_cached_independently():
    clock = Clock()
    cache = _cache(clock)
    authority = Authority(("a", 60), ("b", 60))

    a = await cache.get("team-a", authority)
    b = await cache.get("team-b", authority)
    again = await cache.get("team-a", authority)

    assert (a.value, b.value, again.value) == ("a", "b", "a")
    assert authority.calls == 2


@pytest.mark.parametrize("max_age", [0, -1, 1.5, True, "60", None])
async def test_an_answer_without_a_positive_whole_max_age_is_refused_and_not_cached(max_age):
    clock = Clock()
    cache = _cache(clock)
    authority = Authority(("granted", max_age), ("granted", 60))

    with pytest.raises(ValueError):
        await cache.get("team-a", authority)
    recovered = await cache.get("team-a", authority)

    assert recovered.value == "granted"
    assert authority.calls == 2


@pytest.mark.parametrize("refresh_timeout", [0, -1, float("inf"), float("nan")])
def test_the_refresh_timeout_must_be_a_positive_finite_number(refresh_timeout):
    with pytest.raises(ValueError):
        FreshnessCache(refresh_timeout=refresh_timeout)
