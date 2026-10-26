"""The S13 service boundary consumed by the runner HTTP adapter.

These immutable transport objects grant no authority. The service verifies
scope, exact bytes, current keys and nonces in its own transactions. The
header-only limit read ends before the adapter streams the result body.
"""

from dataclasses import dataclass, field
from typing import Literal, Protocol


@dataclass(frozen=True, repr=False)
class RunnerSubmission:
    header: str
    method: str
    raw_target: str
    body: bytes


@dataclass(frozen=True)
class RunnerReply:
    status: Literal[200, 204]
    body: bytes | None = field(default=None, repr=False)


class RunDispatchAPI(Protocol):
    """Framing adapters receive only these calls, never a registry or opener."""

    async def claim(self, submission: RunnerSubmission) -> RunnerReply: ...

    async def started(self, dispatch_ref: str, submission: RunnerSubmission) -> RunnerReply: ...

    async def result_body_limit(
        self, *, dispatch_ref: str, header: str, method: str, raw_target: str
    ) -> int: ...

    async def result(self, dispatch_ref: str, submission: RunnerSubmission) -> RunnerReply: ...
