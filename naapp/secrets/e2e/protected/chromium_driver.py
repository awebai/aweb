"""The approving human's Chromium in the protected round trip.

  enrol   --origin O --options F --attestation OUT --device D --ca CA
          On a page of the human origin, create the passkey from B3's
          enrolment options with a CDP virtual authenticator (user verified),
          write the browser's attestation JSON, and keep the credential in D.
  approve --url PAGE --device D --ca CA [--login-uv yes|no] [--approve-uv yes|no]
          Open the governance page in a fresh context (no cookie, no token),
          click through its real LOGIN and its separate approval, and print the
          states the page reached, the digest and fingerprint it showed, and
          the URL it ended on.

The credential's private key lives only in D, a file of the lane's runtime
directory. The page's own script does every request; this driver only clicks.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
from pathlib import Path

from playwright.sync_api import sync_playwright

TERMINAL = ("complete", "refused", "unconfirmed", "pending")


def trust(ca: str) -> None:
    nssdb = Path.home() / ".pki" / "nssdb"
    nssdb.mkdir(parents=True, exist_ok=True)
    if not (nssdb / "cert9.db").exists():
        subprocess.run(["certutil", "-d", f"sql:{nssdb}", "-N", "--empty-password"], check=True)
    subprocess.run(["certutil", "-d", f"sql:{nssdb}", "-A", "-t", "C,,", "-n", "lane-ca", "-i", ca], check=True)


def authenticator(page, user_verified: bool):
    cdp = page.context.new_cdp_session(page)
    cdp.send("WebAuthn.enable")
    found = cdp.send("WebAuthn.addVirtualAuthenticator", {"options": {
        "protocol": "ctap2", "transport": "internal", "hasResidentKey": True,
        "hasUserVerification": True, "isUserVerified": user_verified,
        "automaticPresenceSimulation": True}})
    return cdp, found["authenticatorId"]


def enrol(args, browser) -> None:
    page = browser.new_context().new_page()
    page.goto(args.origin + "/handoff/enrolment-host")  # any document of the human origin
    cdp, authenticator_id = authenticator(page, True)
    options = json.loads(Path(args.options).read_text())
    attestation = page.evaluate(
        "async (o) => (await navigator.credentials.create({publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(o)})).toJSON()",
        options)
    Path(args.attestation).write_text(json.dumps(attestation))
    credentials = cdp.send("WebAuthn.getCredentials", {"authenticatorId": authenticator_id})["credentials"]
    device = Path(args.device)
    device.write_text(json.dumps(credentials))
    device.chmod(0o600)


def wait_state(page, states: tuple[str, ...], timeout: int = 60000) -> str:
    page.wait_for_function(
        "(states) => states.includes(document.body.dataset.handoffState) || !location.protocol.startsWith('https')",
        arg=list(states), timeout=timeout)
    if not page.url.startswith("https"):
        return "navigated"
    return page.evaluate("document.body.dataset.handoffState")


def approve(args, browser) -> None:
    page = browser.new_context().new_page()
    cdp, authenticator_id = authenticator(page, args.login_uv == "yes")
    for credential in json.loads(Path(args.device).read_text()):
        cdp.send("WebAuthn.addCredential", {"authenticatorId": authenticator_id, "credential": credential})
    report = {"states": []}
    page.goto(args.url)
    report["states"].append(wait_state(page, ("login-required", "refused")))
    if report["states"][-1] == "login-required":
        page.click("#handoff-action")
        report["states"].append(wait_state(page, ("ready", "refused", "login-required")))
    if report["states"][-1] == "ready":
        report["digest"] = page.text_content("#handoff-digest")
        report["fingerprint"] = page.text_content("#handoff-fingerprint")
        report["act"] = page.text_content("#handoff-act")
        cdp.send("WebAuthn.setUserVerified", {"authenticatorId": authenticator_id, "isUserVerified": args.approve_uv == "yes"})
        page.click("#handoff-action")
        report["states"].append(wait_state(page, TERMINAL + ("ready",)))
    report["url"] = page.url
    print(json.dumps(report))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    e = commands.add_parser("enrol")
    for name in ("--origin", "--options", "--attestation", "--device", "--ca"):
        e.add_argument(name, required=True)
    a = commands.add_parser("approve")
    for name in ("--url", "--device", "--ca"):
        a.add_argument(name, required=True)
    a.add_argument("--login-uv", choices=["yes", "no"], default="yes")
    a.add_argument("--approve-uv", choices=["yes", "no"], default="yes")
    args = parser.parse_args()
    trust(args.ca)
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        try:
            {"enrol": enrol, "approve": approve}[args.command](args, browser)
        finally:
            browser.close()


if __name__ == "__main__":
    os.umask(0o077)
    main()
