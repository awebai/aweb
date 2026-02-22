from __future__ import annotations

from dataclasses import dataclass

import httpx
from fastapi import HTTPException


@dataclass(frozen=True)
class AwebClient:
    """Minimal aweb HTTP client for external callers (and future aweb-* SDKs)."""

    base_url: str
    timeout_seconds: float = 5.0
    transport: httpx.AsyncBaseTransport | None = None

    async def _request_json(
        self,
        method: str,
        path: str,
        *,
        headers: dict[str, str] | None = None,
        params: dict[str, str] | None = None,
        json: dict | None = None,
    ) -> dict:
        async with httpx.AsyncClient(
            base_url=self.base_url,
            timeout=self.timeout_seconds,
            transport=self.transport,
        ) as client:
            resp = await client.request(method, path, headers=headers, params=params, json=json)
        if resp.status_code != 200:
            detail = None
            try:
                detail = resp.json().get("detail")
            except Exception:
                detail = None
            raise HTTPException(status_code=resp.status_code, detail=detail or resp.text)
        return resp.json()

    async def introspect(self, *, authorization: str) -> dict:
        return await self._request_json(
            "GET", "/v1/auth/introspect", headers={"Authorization": authorization}
        )

    async def introspect_project_id(self, *, authorization: str) -> str:
        data = await self.introspect(authorization=authorization)
        project_id = (data.get("project_id") or "").strip()
        if not project_id:
            raise HTTPException(status_code=502, detail="aweb introspection missing project_id")
        return project_id

    async def current_project(self, *, authorization: str) -> dict:
        return await self._request_json(
            "GET", "/v1/projects/current", headers={"Authorization": authorization}
        )

    async def send_message(
        self,
        *,
        authorization: str,
        to_agent_id: str | None = None,
        to_alias: str | None = None,
        subject: str = "",
        body: str,
        priority: str = "normal",
        thread_id: str | None = None,
        message_id: str | None = None,
        timestamp: str | None = None,
        from_did: str | None = None,
        to_did: str | None = None,
        signature: str | None = None,
        signing_key_id: str | None = None,
        # Backward-compat: ignored (server infers sender from bearer token)
        from_agent_id: str | None = None,
        from_alias: str | None = None,
    ) -> dict:
        payload: dict = {
            "to_agent_id": to_agent_id,
            "to_alias": to_alias,
            "subject": subject,
            "body": body,
            "priority": priority,
            "thread_id": thread_id,
            "message_id": message_id,
            "timestamp": timestamp,
            "from_did": from_did,
            "to_did": to_did,
            "signature": signature,
            "signing_key_id": signing_key_id,
        }
        if to_agent_id is None and to_alias is None:
            raise HTTPException(status_code=422, detail="Must provide to_agent_id or to_alias")
        payload = {k: v for k, v in payload.items() if v is not None}
        return await self._request_json(
            "POST",
            "/v1/messages",
            headers={"Authorization": authorization},
            json=payload,
        )
