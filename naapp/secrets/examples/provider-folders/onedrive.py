"""The Microsoft Graph calls the publisher makes, confined to the app's own folder.

The access token comes from the caller through `token`; this module never
obtains, refreshes or stores one.
"""

from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import quote, urlsplit

import httpx

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
LIST_FIELDS = "id,name,size,description,file"
TIMEOUT_SECONDS = 30.0


class ProviderDenied(Exception):
    """The provider refused the token or the operation (401 or 403)."""


class NameTaken(Exception):
    """The target name already exists and conflictBehavior=fail held (409)."""


class ProviderRejected(Exception):
    """The provider refused the request itself; nothing was written."""


class ProviderUnavailable(Exception):
    """The outcome is unknown or transient; reconcile before any retry."""


@dataclass(frozen=True)
class Destination:
    drive_id: str
    folder_id: str


@dataclass(frozen=True)
class RemoteItem:
    id: str
    name: str
    size: int
    quick_xor_hash: str | None
    description: str | None


class GraphAppFolder:
    def __init__(
        self,
        client: httpx.Client,
        *,
        token: Callable[[], str],
        base: str = GRAPH_BASE,
    ):
        self.client = client
        self.token = token
        self.base = base.rstrip("/")
        self._origin = _origin(self.base)

    def destination(self) -> Destination:
        body = _object(self._call("GET", f"{self.base}/me/drive/special/approot"))
        parent = body.get("parentReference")
        return Destination(
            drive_id=_string(parent.get("driveId") if isinstance(parent, dict) else None),
            folder_id=_string(body.get("id")),
        )

    def list_items(self) -> list[RemoteItem]:
        items = []
        url = f"{self.base}/me/drive/special/approot/children?$select={LIST_FIELDS}"
        while url:
            body = _object(self._call("GET", url))
            entries = body.get("value")
            if not isinstance(entries, list):
                raise ProviderUnavailable("malformed_response")
            items.extend(_remote_item(entry) for entry in entries)
            url = _optional_string(body.get("@odata.nextLink"))
            if url is not None and _origin(url) != self._origin:
                raise ProviderUnavailable("next_link_origin")
        return items

    def upload_new(self, name: str, content: bytes, description: str) -> RemoteItem:
        """Create one new item, never replacing an existing one."""
        session = _object(
            self._call(
                "POST",
                f"{self.base}/me/drive/special/approot:/{quote(name, safe='')}:/createUploadSession",
                json={
                    "item": {
                        "@microsoft.graph.conflictBehavior": "fail",
                        "description": description,
                    }
                },
            )
        )
        upload_url = _string(session.get("uploadUrl"))
        if urlsplit(upload_url).scheme != "https":
            raise ProviderRejected("upload_url_not_https")
        # The upload URL is pre-authenticated; the bearer token is never sent to it.
        response = self._send(
            "PUT",
            upload_url,
            content=content,
            headers={"Content-Range": f"bytes 0-{len(content) - 1}/{len(content)}"},
        )
        return _remote_item(_object(response))

    def download(self, item_id: str) -> bytes:
        """Read one item's bytes by ID; the redirect to the content host carries no token."""
        return self._call(
            "GET",
            f"{self.base}/me/drive/items/{quote(item_id, safe='')}/content",
            follow_redirects=True,
        ).content

    def _call(self, method: str, url: str, **kwargs) -> httpx.Response:
        headers = {"Authorization": f"Bearer {self.token()}"}
        return self._send(method, url, headers=headers, **kwargs)

    def _send(self, method: str, url: str, **kwargs) -> httpx.Response:
        try:
            response = self.client.request(method, url, timeout=TIMEOUT_SECONDS, **kwargs)
        except httpx.TransportError as error:
            raise ProviderUnavailable(type(error).__name__) from error
        if response.is_success:
            return response
        code = _error_code(response)
        if response.status_code in (401, 403):
            raise ProviderDenied(code)
        if response.status_code == 409:
            raise NameTaken(code)
        if response.status_code == 429 or response.status_code >= 500:
            raise ProviderUnavailable(code)
        raise ProviderRejected(code)


def _remote_item(entry: object) -> RemoteItem:
    """Validate one driveItem; a malformed one makes the outcome unknown."""
    if not isinstance(entry, dict):
        raise ProviderUnavailable("malformed_response")
    size = entry.get("size")
    if type(size) is not int:
        raise ProviderUnavailable("malformed_response")
    file = entry.get("file")
    hashes = file.get("hashes") if isinstance(file, dict) else None
    quick_xor = hashes.get("quickXorHash") if isinstance(hashes, dict) else None
    return RemoteItem(
        id=_string(entry.get("id")),
        name=_string(entry.get("name")),
        size=size,
        quick_xor_hash=_optional_string(quick_xor),
        description=_optional_string(entry.get("description")),
    )


def _object(response: httpx.Response) -> dict:
    try:
        body = response.json()
    except ValueError:
        raise ProviderUnavailable("malformed_response") from None
    if not isinstance(body, dict):
        raise ProviderUnavailable("malformed_response")
    return body


def _string(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise ProviderUnavailable("malformed_response")
    return value


def _optional_string(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ProviderUnavailable("malformed_response")
    return value


def _origin(url: str) -> tuple[str, str, int | None]:
    parts = urlsplit(url)
    return parts.scheme, parts.hostname or "", parts.port


def _error_code(response: httpx.Response) -> str:
    try:
        return str(response.json()["error"]["code"])
    except (ValueError, KeyError, TypeError):
        return f"http_{response.status_code}"
