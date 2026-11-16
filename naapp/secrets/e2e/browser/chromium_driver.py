"""The ordinary app credential handoff in Chromium, with real WebAuthn UV."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import time
from pathlib import Path
from typing import Any

from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import sync_playwright

# App handoffs finish or refuse; the loopback return navigates away.
TERMINAL = ("complete", "refused")


def trust(ca: str) -> None:
    nssdb = Path.home() / ".pki" / "nssdb"
    nssdb.mkdir(parents=True, exist_ok=True)
    if not (nssdb / "cert9.db").exists():
        subprocess.run(["certutil", "-d", f"sql:{nssdb}", "-N", "--empty-password"], check=True)
    # certutil -A reads one certificate from a file: each authority the file
    # holds is added under its own name.
    end = "-----END CERTIFICATE-----"
    for number, block in enumerate(Path(ca).read_text().split(end)[:-1]):
        one = nssdb / f"lane-ca-{number}.pem"
        one.write_text(block.strip() + "\n" + end + "\n")
        subprocess.run(
            ["certutil", "-d", f"sql:{nssdb}", "-A", "-t", "C,,", "-n", f"lane-ca-{number}", "-i", str(one)],
            check=True,
        )


def authenticator(page, user_verified: bool):
    cdp = page.context.new_cdp_session(page)
    cdp.send("WebAuthn.enable")
    found = cdp.send(
        "WebAuthn.addVirtualAuthenticator",
        {
            "options": {
                "protocol": "ctap2",
                "transport": "internal",
                "hasResidentKey": True,
                "hasUserVerification": True,
                "isUserVerified": user_verified,
                "automaticPresenceSimulation": True,
            }
        },
    )
    return cdp, found["authenticatorId"]




def wait_state(page, states: tuple[str, ...], timeout: int = 60000) -> str:
    """The page's handoff state once it is one of states, or "navigated" once the
    page has left its https origin (the loopback hand-back to aw).

    Waits with selectors and page.url rather than an evaluated predicate: the
    page's CSP refuses eval, and the lane keeps that CSP."""
    selector = ", ".join(f'body[data-handoff-state="{state}"]' for state in states)
    deadline = time.monotonic() + timeout / 1000
    while time.monotonic() < deadline:
        if not page.url.startswith("https"):
            return "navigated"
        try:
            page.wait_for_selector(selector, timeout=500)
            return page.get_attribute("body", "data-handoff-state")
        except PlaywrightError:
            continue  # not yet in a wanted state, or the document is navigating
    raise TimeoutError(f"page never reached {states}; at {page.url}")




def credential(args, browser) -> None:
    """A holder's credential handoff on an app's human origin: the page shows
    the scope, the passkey is created on the action, and the page hands back to
    aw's loopback. The new credential is written to --device."""
    page = browser.new_context().new_page()
    cdp, authenticator_id = authenticator(page, True)
    report: dict[str, Any] = {"states": []}
    page.goto(args.url)
    report["states"].append(wait_state(page, ("ready", "refused")))
    if report["states"][-1] == "ready":
        report["principal"] = page.text_content("#handoff-principal")
        report["role"] = page.text_content("#handoff-role")
        page.click("#handoff-action")
        report["states"].append(wait_state(page, TERMINAL + ("ready",)))
    credentials = cdp.send("WebAuthn.getCredentials", {"authenticatorId": authenticator_id})["credentials"]
    device = Path(args.device)
    device.write_text(json.dumps(credentials))
    device.chmod(0o600)
    report["credentials"] = len(credentials)
    if report["states"][-1] != "navigated":
        report["status"] = page.text_content("#handoff-status")
    print(json.dumps(report))


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    commands = parser.add_subparsers(dest="command", required=True)
    c = commands.add_parser("credential")
    for name in ("--url", "--device", "--ca"):
        c.add_argument(name, required=True)
    args = parser.parse_args()
    trust(args.ca)
    # Playwright's own requests (route.fetch) run in its Node driver, which
    # does not read the browser's NSS store: give it the same authority.
    os.environ["NODE_EXTRA_CA_CERTS"] = args.ca
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        try:
            credential(args, browser)
        finally:
            browser.close()


if __name__ == "__main__":
    os.umask(0o077)
    main()
