"""The approving human's Chromium in the protected round trip.

  enrol-page --url LINK --device D --ca CA
          Open the enrolment link the signer delivered, on its human origin,
          and complete the page's own registration with a CDP virtual
          authenticator (user verified); keep the credential in D.
  approve --url PAGE --device D --ca CA [--approve-uv yes|no]
          [--login-cancel | --login-without-uv]
          Open the governance page in a fresh context (no cookie, no token),
          click through its real LOGIN and its separate approval, and print the
          states the page reached, the digest and fingerprint it showed, the
          page's own status text and the URL it ended on, and keeps the
          credential (with its advanced signature counter) in D.
          --login-cancel lets the browser itself reject the LOGIN prompt: the
          authenticator gets no user presence and the options' timeout hint is
          shortened, so navigator.credentials.get rejects with no assertion
          sent; the exceptions the page caught are reported by name.
          --login-without-uv injects a correctly signed assertion without user
          verification: the browser's own LOGIN assertion, with only its UV
          flag cleared and signed again by the enrolled credential (verified
          under its public key before it is sent). It tests the signer's
          refusal and the page's answer, not Chromium's own behaviour.

The credential's private key lives only in D, a file of the lane's runtime
directory. The page's own script does every request; this driver only clicks.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import struct
import subprocess
import time
from pathlib import Path
from typing import Any

from aweb_naapp_testing.webauthn import UV, from_b64url, without_user_verification
from awid.signing import VerifyResult, verify_signature_with_public_key
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_der_private_key,
)
from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import sync_playwright

TERMINAL = ("complete", "refused", "unconfirmed", "pending")


def trust(ca: str) -> None:
    nssdb = Path.home() / ".pki" / "nssdb"
    nssdb.mkdir(parents=True, exist_ok=True)
    if not (nssdb / "cert9.db").exists():
        subprocess.run(["certutil", "-d", f"sql:{nssdb}", "-N", "--empty-password"], check=True)
    subprocess.run(
        ["certutil", "-d", f"sql:{nssdb}", "-A", "-t", "C,,", "-n", "lane-ca", "-i", ca], check=True
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


def enrol_page(args, browser) -> None:
    page = browser.new_context().new_page()
    cdp, authenticator_id = authenticator(page, True)
    page.goto(args.url)
    page.wait_for_selector("#complete:not([disabled])", timeout=30000)
    page.click("#complete")
    # The page shows the way on to sign in once B3 has registered the passkey;
    # on a refusal it enables the button again and shows no such link.
    page.wait_for_selector("#continue:not([hidden])", timeout=60000)
    credentials = cdp.send("WebAuthn.getCredentials", {"authenticatorId": authenticator_id})[
        "credentials"
    ]
    device = Path(args.device)
    device.write_text(json.dumps(credentials))
    device.chmod(0o600)
    print(json.dumps({"enrolled": len(credentials)}))


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


def approve(args, browser) -> None:
    page = browser.new_context().new_page()
    cdp, authenticator_id = authenticator(page, True)
    device = json.loads(Path(args.device).read_text())
    for credential in device:
        cdp.send(
            "WebAuthn.addCredential",
            {"authenticatorId": authenticator_id, "credential": credential},
        )
    exceptions: list[str] = []
    if args.login_without_uv:
        keys = {
            base64.b64decode(c["credentialId"]): load_der_private_key(base64.b64decode(c["privateKey"]), None)
            for c in device
        }
        stored = {base64.b64decode(c["credentialId"]): c["signCount"] for c in device}

        def without_uv(route):
            if route.request.method != "POST":
                route.continue_()
                return
            body = route.request.post_data_json
            assertion = body["assertion"]
            key = keys[from_b64url(assertion["rawId"])]
            changed = without_user_verification(assertion, key)
            before = from_b64url(assertion["response"]["authenticatorData"])
            after = from_b64url(changed["response"]["authenticatorData"])
            # Same credential, client data (challenge, origin), RP hash, other
            # flags and counter; only UV differs, and the new signature is
            # the enrolled credential's.
            assert changed["rawId"] == assertion["rawId"]
            assert changed["response"]["clientDataJSON"] == assertion["response"]["clientDataJSON"]
            assert before[32] & UV and after == before[:32] + bytes([before[32] & ~UV & 0xFF]) + before[33:]
            # The counter has moved past the credential's last persisted one.
            assert struct.unpack(">I", before[33:37])[0] > stored[from_b64url(assertion["rawId"])]
            public, signature = key.public_key(), changed["response"]["signature"]
            signed = after + hashlib.sha256(from_b64url(changed["response"]["clientDataJSON"])).digest()
            if isinstance(public, ec.EllipticCurvePublicKey):
                public.verify(from_b64url(signature), signed, ec.ECDSA(hashes.SHA256()))
            else:
                # EdDSA, through AWID's shared Ed25519 verifier.
                raw = public.public_bytes(Encoding.Raw, PublicFormat.Raw)
                assert verify_signature_with_public_key(raw, signed, signature) is VerifyResult.VERIFIED
            report["login_assertion"] = "injected-uv-cleared-signature-verified"
            route.continue_(post_data=json.dumps({**body, "assertion": changed}))

        page.route("**/login", without_uv)
    if args.login_cancel:
        # The caught exception's name, read by the debugger as the page
        # handles it; the page's own code runs unchanged.
        def paused(event):
            try:
                object_id = (event.get("data") or {}).get("objectId")
                if object_id:
                    named = cdp.send(
                        "Runtime.callFunctionOn",
                        {
                            "objectId": object_id,
                            "functionDeclaration": "function() { return this.name; }",
                            "returnByValue": True,
                            "silent": True,
                        },
                    )
                    exceptions.append(named["result"].get("value"))
            finally:
                cdp.send("Debugger.resume")

        cdp.send("Debugger.enable")
        cdp.on("Debugger.paused", paused)
        cdp.send("Debugger.setPauseOnExceptions", {"state": "all"})
        # No presence, and the real options' client timeout hint shortened:
        # the browser rejects the prompt itself. Nothing else is changed.
        cdp.send(
            "WebAuthn.setAutomaticPresenceSimulation",
            {"authenticatorId": authenticator_id, "enabled": False},
        )

        def shorten(route):
            response = route.fetch()
            options = response.json()
            options["timeout"] = 1000
            route.fulfill(response=response, json=options)

        page.route("**/login/options", shorten)
    report: dict[str, Any] = {"states": []}
    page.goto(args.url)
    report["states"].append(wait_state(page, ("login-required", "refused")))
    if report["states"][-1] == "login-required":
        clicked = time.monotonic()
        page.click("#handoff-action")
        report["states"].append(wait_state(page, ("ready", "refused", "login-required")))
        report["login_seconds"] = round(time.monotonic() - clicked, 1)
        if args.login_cancel:
            cdp.send("Debugger.setPauseOnExceptions", {"state": "none"})
            report["exception_names"] = exceptions
    if report["states"][-1] == "ready":
        report["digest"] = page.text_content("#handoff-digest")
        report["fingerprint"] = page.text_content("#handoff-fingerprint")
        report["act"] = page.text_content("#handoff-act")
        cdp.send(
            "WebAuthn.setUserVerified",
            {"authenticatorId": authenticator_id, "isUserVerified": args.approve_uv == "yes"},
        )
        page.click("#handoff-action")
        report["states"].append(wait_state(page, TERMINAL + ("ready",)))
    # The credential's counter has moved on: the next browser starts from it.
    credentials = cdp.send("WebAuthn.getCredentials", {"authenticatorId": authenticator_id})["credentials"]
    Path(args.device).write_text(json.dumps(credentials))
    # Once the page has handed back to aw's loopback there is no status to read.
    if report["states"][-1] != "navigated":
        report["status"] = page.text_content("#handoff-status")
    report["url"] = page.url
    print(json.dumps(report))


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    commands = parser.add_subparsers(dest="command", required=True)
    p = commands.add_parser("enrol-page")
    for name in ("--url", "--device", "--ca"):
        p.add_argument(name, required=True)
    a = commands.add_parser("approve")
    for name in ("--url", "--device", "--ca"):
        a.add_argument(name, required=True)
    a.add_argument("--approve-uv", choices=["yes", "no"], default="yes")
    login = a.add_mutually_exclusive_group()
    login.add_argument("--login-cancel", action="store_true")
    login.add_argument("--login-without-uv", action="store_true")
    args = parser.parse_args()
    trust(args.ca)
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        try:
            {"enrol-page": enrol_page, "approve": approve}[args.command](args, browser)
        finally:
            browser.close()


if __name__ == "__main__":
    os.umask(0o077)
    main()
