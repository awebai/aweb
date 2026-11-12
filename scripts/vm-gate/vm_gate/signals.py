"""A first termination unwinds work; later signals cannot interrupt teardown."""
from contextlib import contextmanager
import signal
import threading


@contextmanager
def handling(cleanup=False):
    if threading.current_thread() is not threading.main_thread():
        yield;return
    previous={sig:signal.getsignal(sig) for sig in (signal.SIGINT,signal.SIGTERM)}
    def interrupted(*args):raise KeyboardInterrupt
    try:
        for sig in previous:signal.signal(sig,signal.SIG_IGN if cleanup else interrupted)
        yield
    finally:
        for sig,handler in previous.items():signal.signal(sig,handler)
