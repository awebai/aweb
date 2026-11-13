"""A resource expiry bounds completion, including evidence and teardown."""

import math
from .errors import Infrastructure, Refused


class CompletionBudget:
    def __init__(
        self,
        created,
        timeout,
        *,
        setup=900,
        pull=600,
        cleanup=300,
        margin=300,
        grace=150,
    ):
        self.steps = {
            "setup": setup,
            "gate": timeout,
            "grace": grace,
            "pull": pull,
            "cleanup": cleanup,
            "margin": margin,
        }
        if any(
            not isinstance(x, (int, float)) or not math.isfinite(x) or x <= 0
            for x in [created, *self.steps.values()]
        ):
            raise Refused(
                "completion durations and creation time must be positive and finite"
            )
        self.expires = math.ceil(created + sum(self.steps.values()))

    def require(self, step, *, now):
        names = list(self.steps)
        remaining = sum(self.steps[name] for name in names[names.index(step) :])
        if step in {"setup", "grace"} and math.isfinite(now):
            available = self.expires - (remaining - self.steps[step]) - now
            if available > 0:
                return min(self.steps[step], available)
        if not math.isfinite(now) or now + remaining > self.expires:
            raise Infrastructure(
                f"{step} cannot finish before completion expiry {self.expires}"
            )
        return self.steps[step]
