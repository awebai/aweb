"""One bounded reconnect schedule for native Redis subscriptions."""

from dataclasses import dataclass, field


@dataclass
class ReconnectBackoff:
    """Track retry eligibility using the caller's existing monotonic clock."""

    initial_delay: float
    maximum_delay: float
    delay: float = field(init=False)
    next_attempt_at: float | None = field(default=None, init=False)

    def __post_init__(self) -> None:
        self.reset()

    def reset(self) -> None:
        """A successful subscription restores the initial retry interval."""
        self.delay = self.initial_delay
        self.next_attempt_at = None

    def due(self, now: float) -> bool:
        """Whether a caller may attempt a connection at this clock reading."""
        return self.next_attempt_at is None or now >= self.next_attempt_at

    def schedule(self, now: float) -> float:
        """Schedule one failure, returning its wait before advancing the delay."""
        wait = self.delay
        self.next_attempt_at = now + wait
        self.delay = min(self.maximum_delay, wait * 2)
        return wait
