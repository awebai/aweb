"""Durable outbound worker: observation/retry only, never new release authority."""

import asyncio
import signal
from datetime import UTC, datetime
from pathlib import Path

from .errors import Refused
from .execution import execute
from .http import RunnerHTTP
from .jobs import CredentialInput, RunnerConfig
from .journal import Journal
from .protocol import canonical, timestamp, verify_assignment
from .state import Identity, IdentityStore


class Worker:
    """One sequential worker under the operator command's private process lock."""

    def __init__(
        self, identity: Identity, config: RunnerConfig, journal: Journal, client: RunnerHTTP
    ):
        if identity.runner_id is None or identity.service_kid is None:
            raise Refused("runner_unregistered")
        self._identity = identity
        self._runner_id = identity.runner_id
        self._service_kid = identity.service_kid
        self._config = config
        self._journal = journal
        self._client = client

    async def _flush(self) -> None:
        for result in self._journal.pending_results():
            await self._client.result(result.dispatch_id, result.body)
            self._journal.ack_result(result.dispatch_id)

    async def step(self) -> bool:
        """Flush reports, claim once, execute once, then durably report.

        Failure retains pending bytes for the next attempt/restart. An accepted
        assignment whose execution failed or was interrupted stays accepted:
        never fabricate an exit report, re-open, or run it again. The service's
        existing timeout/reconciliation path resolves that uncertainty.
        """
        await self._flush()
        raw = await self._client.claim()
        if raw is None:
            return False
        verified = verify_assignment(
            raw,
            origin=self._identity.origin,
            runner_id=self._runner_id,
            service_kid=self._service_kid,
            now=datetime.now(UTC),  # Fresh after the long-poll wait.
            journal=self._journal,
        )
        document = verified.document
        assignment = document["assignment"]
        dispatch_id = verified.dispatch_id
        credentials = [
            CredentialInput(
                item["secret_ref"], item["sealed"], self._identity.encryption_key, dispatch_id
            )
            for item in document["credentials"]
        ]

        async def started(pid: int) -> None:
            await self._client.started(dispatch_id)

        report = await execute(
            self._config,
            job_id=assignment["job_id"],
            digest=assignment["job_digest"],
            runner_id=self._runner_id,
            params=document["params"],
            credentials=credentials,
            expires_at=timestamp(assignment["expires_at"]).timestamp(),
            started=started,
        )
        # Only sanitized output is durable. Canonicalize exactly once, before
        # the first send; subsequent attempts use the saved bytes unchanged.
        self._journal.save_result(dispatch_id, canonical(report))
        await self._flush()
        return True

    async def serve(self) -> None:
        backoff = 1
        while True:
            try:
                ran = await self.step()
            except Refused as refused:
                if refused.code != "runner_unavailable":
                    raise
                await asyncio.sleep(backoff)
                backoff = min(30, backoff * 2)
            else:
                backoff = 1
                if not ran:
                    # Idle 204s may arrive early; do not busy-spin if they do.
                    await asyncio.sleep(1)


async def run(config_file: Path, state_dir: Path, *, ca_file: Path | None = None) -> int:
    store = IdentityStore(state_dir)
    with store.worker_lock():
        identity = store.load()
        if identity.runner_id is None or identity.service_kid is None:
            raise Refused("runner_unregistered")
        config = RunnerConfig.load(config_file)
        config.doctor(identity.runner_id)
        journal = Journal(state_dir / "journal.sqlite3")
        loop = asyncio.get_running_loop()
        task = asyncio.current_task()
        assert task is not None
        terminated = False

        def terminate() -> None:
            nonlocal terminated
            terminated = True
            task.cancel()

        loop.add_signal_handler(signal.SIGTERM, terminate)
        try:
            async with RunnerHTTP(identity, ca_file=ca_file) as client:
                await Worker(identity, config, journal, client).serve()
        except asyncio.CancelledError:
            if terminated:
                return 143
            raise
        finally:
            loop.remove_signal_handler(signal.SIGTERM)
    return 0
