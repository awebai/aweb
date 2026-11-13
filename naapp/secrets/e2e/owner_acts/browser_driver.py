"""The holder's browser in the H owner-acts journey.

It runs in the holder's network namespace (docker --network container:<holder>),
so its last request, the redirect to aw's 127.0.0.1 callback, reaches the aw
that started the handoff. It plays a person at the shared handoff page: it
loads the page, then completes the ceremony through the page's JSON routes with
a software authenticator whose keys persist in --device between runs.

It never relaxes a check: TLS is verified against --ca, the browser Origin is
the human origin, and it follows only the redirect the app returned.
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
from pathlib import Path
from urllib.parse import urlsplit

import httpx
from cryptography.hazmat.primitives import serialization

# The shared software authenticator, copied beside this script in the browser
# image as soft_webauthn (browser.Dockerfile), so it never shadows py_webauthn.
from soft_webauthn import SoftAuthenticator, SoftCredential  # type: ignore[import-not-found]


def load_device(path: Path, origin: str) -> SoftAuthenticator:
    device = SoftAuthenticator(origin)
    if path.exists():
        for item in json.loads(path.read_text()):
            key = serialization.load_pem_private_key(item["key"].encode(), password=None)
            cid = base64.b64decode(item["credential_id"])
            device.credentials[cid] = SoftCredential(
                credential_id=cid, key=key, rp_id=item["rp_id"],
                user_handle=base64.b64decode(item["user_handle"]), sign_count=item["sign_count"],
            )
    return device


def save_device(path: Path, device: SoftAuthenticator) -> None:
    items = [
        {
            "credential_id": base64.b64encode(c.credential_id).decode(),
            "key": c.key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ).decode(),
            "rp_id": c.rp_id,
            "user_handle": base64.b64encode(c.user_handle).decode(),
            "sign_count": c.sign_count,
        }
        for c in device.credentials.values()
    ]
    path.write_text(json.dumps(items))
    path.chmod(0o600)


def expect(response: httpx.Response, status: int = 200) -> httpx.Response:
    if response.status_code != status:
        sys.exit(f"{response.request.method} {response.request.url.path}: {response.status_code} {response.text[:300]}")
    return response


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--page", required=True, help="the URL aw printed")
    parser.add_argument("--purpose", required=True, choices=("credential", "session"))
    parser.add_argument("--device", required=True, type=Path)
    parser.add_argument("--ca", required=True)
    parser.add_argument("--no-page", action="store_true", help="skip the HTML check until the page lands")
    args = parser.parse_args()

    page = urlsplit(args.page)
    origin = f"{page.scheme}://{page.netloc}"
    handoff_id = page.path.rsplit("/", 1)[-1]
    device = load_device(args.device, origin)
    with httpx.Client(base_url=origin, verify=args.ca, follow_redirects=False, timeout=30) as browser:
        if not args.no_page:
            shown = expect(browser.get(page.path))
            if not shown.headers.get("content-type", "").startswith("text/html"):
                sys.exit(f"the handoff page is not HTML: {shown.headers.get('content-type')}")
        prefix = f"/handoff/{handoff_id}/{args.purpose}"
        state = expect(browser.get(prefix)).json()
        headers = {"Origin": origin, "X-CSRF-Token": state["csrf_token"], "Content-Type": "application/json"}
        options = expect(browser.post(prefix + "/options", json={}, headers=headers)).json()
        if args.purpose == "credential":
            done = expect(browser.post(prefix + "/complete", json={"credential": device.create(options)}, headers=headers))
        else:
            expect(browser.post(prefix + "/login", json={"assertion": device.get(options)}, headers=headers))
            done = expect(browser.post(prefix + "/allow", json={"allow": True}, headers=headers))
        save_device(args.device, device)
        redirect = done.json()["redirect_uri"]
    # The browser follows the stored redirect to aw's loopback on this machine.
    with httpx.Client(follow_redirects=False, timeout=30) as loopback:
        expect(loopback.get(redirect))
    print("browser: completed", args.purpose, file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
