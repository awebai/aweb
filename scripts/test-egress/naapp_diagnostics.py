"""Live pytest evidence for the isolated naapp unit suites."""

import asyncio
import gc
import os
import sys
import threading
import time
import traceback
from contextlib import suppress
from datetime import UTC, datetime

import pytest_asyncio

# PYTEST_PLUGINS loads this module before pytest redirects stderr for capture.
# Keep a line-buffered copy so the runner retains evidence even if pytest stalls.
try:
    _evidence = os.fdopen(os.dup(sys.stderr.fileno()), "w", buffering=1)
except (OSError, ValueError):
    _evidence = None


@pytest_asyncio.fixture(autouse=True, loop_scope="function")
async def isolated_test_diagnostics(request):
    if _evidence is None:
        yield
        return

    def record(message):
        timestamp = datetime.now(UTC).isoformat(timespec="milliseconds")
        with suppress(OSError):
            print(f"[naapp-test {timestamp} pid={os.getpid()}] {request.node.nodeid} {message}",
                  file=_evidence, flush=True)

    collection_started = None

    def record_gc(phase, info):
        nonlocal collection_started
        if phase == "start":
            collection_started = time.monotonic()
        elif phase == "stop" and collection_started is not None:
            elapsed = time.monotonic() - collection_started
            collection_started = None
            if elapsed > 0.5:
                record(f"gc generation={info['generation']} elapsed={elapsed:.3f}s")

    loop = asyncio.get_running_loop()
    done = threading.Event()
    last_tick = time.monotonic()
    tick_handle = None
    watchdog = None

    def tick():
        nonlocal last_tick, tick_handle
        last_tick = time.monotonic()
        tick_handle = loop.call_later(0.25, tick)

    def watch_loop():
        reported_tick = None
        idle_at = last_tick
        while not done.wait(0.25):
            now = time.monotonic()
            if not loop.is_running():
                idle_at = now
                continue
            observed_tick = last_tick
            elapsed = now - max(observed_tick, idle_at)
            if elapsed >= 2 and observed_tick != reported_tick:
                reported_tick = observed_tick
                try:
                    frame = sys._current_frames().get(threading.main_thread().ident)
                    stack = "".join(traceback.format_stack(frame)) if frame is not None else ""
                    record(f"event loop stalled for {elapsed:.3f}s; main thread stack\n{stack}")
                except Exception as error:
                    record(f"watchdog stack capture failed: {error}")

    record("start")
    gc.callbacks.append(record_gc)
    try:
        if pytest_asyncio.is_async_test(request.node):
            tick()
            thread = threading.Thread(target=watch_loop, daemon=True)
            try:
                thread.start()
                watchdog = thread
            except RuntimeError as error:
                record(f"watchdog unavailable: {error}")
        yield
    finally:
        done.set()
        if tick_handle is not None:
            tick_handle.cancel()
        with suppress(ValueError):
            gc.callbacks.remove(record_gc)
        if watchdog is not None:
            watchdog.join(timeout=0.25)
