"""Deployment-selected client address for request budgets."""

from dataclasses import dataclass

from starlette.requests import Request


@dataclass(frozen=True)
class ClientIdentity:
    """How the deployment identifies the client behind a request.

    By default it is the peer address, and any forwarded header is ignored,
    because a client can set one. Behind a proxy, the deployment names the
    header that proxy sets as ``trusted_header``; its last comma-separated
    entry is the address the proxy saw. A request without the header is keyed
    on its peer.
    """

    trusted_header: str | None = None

    def of(self, request: Request) -> str:
        if self.trusted_header is not None:
            value = request.headers.get(self.trusted_header, "")
            last = value.rsplit(",", 1)[-1].strip()
            if last:
                return last
        return request.client.host if request.client is not None else ""
