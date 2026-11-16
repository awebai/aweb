#!/usr/bin/env python3
"""First self-custody add-human journey; real runtime adapters plug into these steps.

The browser smoke check exercises only CDP/virtual-authenticator wiring. It is
not an approval-service, key-holder or completed-journey acceptance result.
"""

from __future__ import annotations

import argparse
import asyncio
import importlib
import json
import os
import tempfile
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import quote

STEPS = (
    "controller_bootstrap_first",
    "enroll_first_person",
    "publish_first_identity",
    "verify_first_evidence",
    "request_second_person",
    "first_person_approves_second",
    "holder_issues_second",
    "enroll_second_person",
    "publish_second_identity",
    "verify_second_evidence",
)


@dataclass
class BrowserActor:
    page: Any
    cdp: Any
    authenticator_id: str

    async def register(self, origin: str, locator: str) -> None:
        """Use awsign's real page and its create ceremony; keep its CSRF state."""
        from playwright.async_api import expect

        await self.page.goto(origin + "/enroll#" + quote(locator, safe=""))
        await self.page.get_by_role("button", name="Register a key", exact=True).click()
        await expect(self.page.get_by_role("status")).to_contain_text("Key registered.")

    async def confirm_enrollment(self) -> None:
        """Call after the issuer prepares B and the separate confirmation R."""
        from playwright.async_api import expect

        await self.page.get_by_role(
            "button", name="Confirm this enrollment", exact=True
        ).click()
        await self.page.get_by_role(
            "button", name="Confirm with your key", exact=True
        ).click()
        await expect(self.page.get_by_role("status")).to_contain_text(
            "Enrollment confirmed."
        )

    async def sign_in(self, origin: str, person: str) -> None:
        from playwright.async_api import expect

        await self.page.goto(origin + "/")
        await self.page.get_by_role(
            "button", name="Sign in with an approval key", exact=True
        ).click()
        await expect(self.page.get_by_role("status")).to_have_text(
            "Signed in as " + person
        )

    async def approve(self, request_digest: str) -> None:
        """Choose the displayed exact request, never just the first pending row."""
        from playwright.async_api import expect

        row = self.page.locator("article").filter(
            has=self.page.get_by_text(request_digest, exact=True)
        )
        await expect(row).to_have_count(1)
        await row.get_by_role("button", name="Approve", exact=True).click()
        await expect(row).to_have_count(0)


@asynccontextmanager
async def browser_actors():
    from playwright.async_api import async_playwright

    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch()
        contexts = []
        try:
            actors = {}
            for name in ("first", "second"):
                context = await browser.new_context()
                contexts.append(context)
                page = await context.new_page()
                cdp = await context.new_cdp_session(page)
                await cdp.send("WebAuthn.enable")
                added = await cdp.send(
                    "WebAuthn.addVirtualAuthenticator",
                    {
                        "options": {
                            "protocol": "ctap2",
                            "transport": "internal",
                            "hasResidentKey": True,
                            "hasUserVerification": True,
                            "isUserVerified": True,
                            "automaticPresenceSimulation": True,
                        }
                    },
                )
                actors[name] = BrowserActor(page, cdp, added["authenticatorId"])
            yield actors
        finally:
            for context in contexts:
                await context.close()
            await browser.close()


@dataclass
class JourneyContext:
    work_dir: Path
    actors: dict[str, BrowserActor]
    values: dict[str, Any] = field(default_factory=dict)


class Runtime(Protocol):
    async def execute(self, step: str, context: JourneyContext) -> None:
        """Perform the named step through the real service/holder/aw interfaces.

        Store artifacts in the private work_dir and cross-step values in context.
        Verification steps must consume aw verify's actual JSON/exit status.
        """
        ...


def write_report(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with tempfile.NamedTemporaryFile(mode="w", dir=path.parent, delete=False) as stream:
        temporary = Path(stream.name)
        try:
            json.dump(report, stream, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)


async def run(runtime: Runtime, work_dir: Path) -> None:
    work_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    report: dict[str, Any] = {
        "journey": "adcl6-self-custody-add-human",
        "completed": False,
        "steps": [],
    }
    try:
        async with browser_actors() as actors:
            context = JourneyContext(work_dir, actors)
            for step in STEPS:
                started = time.monotonic()
                row = {"step": step, "outcome": "running"}
                report["steps"].append(row)
                try:
                    await runtime.execute(step, context)
                except BaseException as error:
                    row.update(outcome="failed", error_type=type(error).__name__)
                    raise
                else:
                    row["outcome"] = "passed"
                finally:
                    row["seconds"] = time.monotonic() - started
            report["completed"] = True
    finally:
        write_report(work_dir / "journey.json", report)


async def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--adapter",
        help="Real runtime adapter as module:factory; factory takes no arguments",
    )
    parser.add_argument("--work-dir", type=Path)
    parser.add_argument(
        "--check-browser",
        action="store_true",
        help="Check only real browser/CDP wiring, without running the journey",
    )
    args = parser.parse_args()
    if args.check_browser:
        async with browser_actors() as actors:
            for actor in actors.values():
                await actor.cdp.send(
                    "WebAuthn.getCredentials",
                    {"authenticatorId": actor.authenticator_id},
                )
        print(json.dumps({"browser_wiring": "passed", "journey_executed": False}))
        return
    if not args.adapter or not args.work_dir:
        parser.error("--adapter and --work-dir are required for the real journey")
    module, separator, factory = args.adapter.partition(":")
    if not separator:
        parser.error("--adapter must be module:factory")
    runtime = getattr(importlib.import_module(module), factory)()
    await run(runtime, args.work_dir)


if __name__ == "__main__":
    asyncio.run(main())
