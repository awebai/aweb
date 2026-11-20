"""A local stand-in for the Microsoft Graph app-folder calls the publisher makes.

It exercises failure handling only. It cannot qualify real provider access,
scope or account support; those are demonstrated against the real provider.
"""

import base64
import hashlib
import json
import uuid
from collections.abc import Callable
from urllib.parse import parse_qs, unquote, urlsplit

import httpx
import quickxorhash

GRAPH = "https://graph.standin.invalid/v1.0"
UPLOAD_HOST = "upload.standin.invalid"
DOWNLOAD_HOST = "download.standin.invalid"
TOKEN = "standin-access-token"
APPROOT_PREFIX = "/v1.0/me/drive/special/approot"


def reference_quick_xor(data: bytes) -> str:
    hasher = quickxorhash.quickxorhash()
    hasher.update(data)
    return base64.b64encode(hasher.digest()).decode("ascii")


class OneDriveStandIn:
    """In-memory app folder with Graph-shaped requests, responses and faults."""

    PAGE_SIZE = 2

    def __init__(self):
        self.items: dict[str, dict] = {}
        self.sessions: dict[str, dict] = {}
        self.committed_uploads = 0
        self.lose_next_commit_response = False
        self.deny_all = False
        self.insert_before_next_commit: tuple[str, bytes] | None = None
        self.foreign_next_link: str | None = None
        self.before_commit: Callable[[], None] | None = None
        self.before_session: Callable[[], None] | None = None
        self.malformed_next: str | None = None
        self.fail_next_list = False
        self.misreport_next_commit = False
        self.approot = {
            "id": "STANDIN-APPROOT",
            "name": "Fictional Publisher",
            "parentReference": {"driveId": "standin-drive"},
            "folder": {"childCount": 0},
        }

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handle)

    def add_item(self, name: str, content: bytes, description: str | None = None) -> dict:
        item_id = uuid.uuid4().hex.upper()
        item = {
            "id": item_id,
            "name": name,
            "size": len(content),
            "content": content,
            "file": {
                "hashes": {
                    "quickXorHash": reference_quick_xor(content),
                    "sha1Hash": hashlib.sha1(content).hexdigest().upper(),
                }
            },
        }
        if description is not None:
            item["description"] = description
        self.items[item_id] = item
        return item

    def snapshot(self) -> dict[str, tuple[str, bytes, str | None]]:
        return {
            item_id: (item["name"], item["content"], item.get("description"))
            for item_id, item in self.items.items()
        }

    def handle(self, request: httpx.Request) -> httpx.Response:
        url = urlsplit(str(request.url))
        if url.hostname == UPLOAD_HOST:
            return self._upload_range(request, url)
        if url.hostname == DOWNLOAD_HOST:
            return self._download(request, url)
        if request.headers.get("Authorization") != f"Bearer {TOKEN}":
            return _error(401, "InvalidAuthenticationToken")
        if self.deny_all:
            return _error(403, "accessDenied")
        path = unquote(url.path)
        if request.method == "GET" and path == APPROOT_PREFIX:
            if self._take_malformed("approot"):
                return _malformed()
            return httpx.Response(200, json=self.approot)
        if request.method == "GET" and path == f"{APPROOT_PREFIX}/children":
            if self.fail_next_list:
                self.fail_next_list = False
                return _error(503, "serviceNotAvailable")
            if self._take_malformed("list"):
                return _malformed()
            return self._list(url)
        if request.method == "POST" and path.startswith(f"{APPROOT_PREFIX}:/"):
            if path.endswith(":/createUploadSession"):
                name = path[len(f"{APPROOT_PREFIX}:/") : -len(":/createUploadSession")]
                return self._create_session(request, name)
        if request.method == "GET" and path.startswith("/v1.0/me/drive/items/"):
            if path.endswith("/content"):
                item_id = path[len("/v1.0/me/drive/items/") : -len("/content")]
                return self._content_redirect(item_id)
        return _error(403, "accessDenied")

    def _list(self, url) -> httpx.Response:
        start = int(parse_qs(url.query).get("skiptoken", ["0"])[0])
        ordered = sorted(self.items.values(), key=lambda item: item["name"])
        page = ordered[start : start + self.PAGE_SIZE]
        body: dict[str, object] = {"value": [_public(item) for item in page]}
        if start + self.PAGE_SIZE < len(ordered):
            body["@odata.nextLink"] = self.foreign_next_link or (
                f"{GRAPH}/me/drive/special/approot/children?skiptoken={start + self.PAGE_SIZE}"
            )
        return httpx.Response(200, json=body)

    def _take_malformed(self, endpoint: str) -> bool:
        if self.malformed_next != endpoint:
            return False
        self.malformed_next = None
        return True

    def _name_taken(self, name: str) -> bool:
        return any(item["name"].casefold() == name.casefold() for item in self.items.values())

    def _create_session(self, request: httpx.Request, name: str) -> httpx.Response:
        if self.before_session is not None:
            self.before_session()
        if self._take_malformed("session"):
            return _malformed()
        item = json.loads(request.content)["item"]
        if item.get("@microsoft.graph.conflictBehavior") != "fail":
            return _error(400, "invalidRequest")
        if self._name_taken(name):
            return _error(409, "nameAlreadyExists")
        session_id = uuid.uuid4().hex
        self.sessions[session_id] = {"name": name, "description": item.get("description")}
        return httpx.Response(
            200, json={"uploadUrl": f"https://{UPLOAD_HOST}/session/{session_id}"}
        )

    def _upload_range(self, request: httpx.Request, url) -> httpx.Response:
        if "Authorization" in request.headers:
            return _error(400, "authorizationSentToUploadUrl")
        session = self.sessions.pop(url.path.rsplit("/", 1)[-1], None)
        if session is None:
            return _error(404, "itemNotFound")
        content = request.content
        if request.headers.get("Content-Range") != f"bytes 0-{len(content) - 1}/{len(content)}":
            return _error(400, "invalidRange")
        if self.before_commit is not None:
            self.before_commit()
        if self.insert_before_next_commit is not None:
            foreign_name, foreign_content = self.insert_before_next_commit
            self.insert_before_next_commit = None
            self.add_item(foreign_name, foreign_content)
        if self._name_taken(session["name"]):
            return _error(409, "nameAlreadyExists")
        item = self.add_item(session["name"], content, session["description"])
        self.committed_uploads += 1
        if self.lose_next_commit_response:
            self.lose_next_commit_response = False
            raise httpx.ReadTimeout("response lost after commit", request=request)
        if self._take_malformed("commit"):
            return _malformed()
        if self.misreport_next_commit:
            self.misreport_next_commit = False
            reported = _public(item)
            reported["file"] = {"hashes": {"quickXorHash": reference_quick_xor(b"other")}}
            return httpx.Response(201, json=reported)
        return httpx.Response(201, json=_public(item))

    def _content_redirect(self, item_id: str) -> httpx.Response:
        if item_id not in self.items:
            return _error(404, "itemNotFound")
        return httpx.Response(302, headers={"Location": f"https://{DOWNLOAD_HOST}/{item_id}"})

    def _download(self, request: httpx.Request, url) -> httpx.Response:
        if "Authorization" in request.headers:
            return _error(400, "authorizationSentToDownloadUrl")
        item = self.items.get(url.path.lstrip("/"))
        if item is None:
            return _error(404, "itemNotFound")
        return httpx.Response(200, content=item["content"])


def _public(item: dict) -> dict:
    return {key: value for key, value in item.items() if key != "content"}


def _malformed() -> httpx.Response:
    return httpx.Response(200, json={"value": "not a list", "id": 7})


def _error(status: int, code: str) -> httpx.Response:
    return httpx.Response(status, json={"error": {"code": code, "message": code}})
