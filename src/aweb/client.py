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
        return await self._request_json("GET", "/v1/auth/introspect", headers={"Authorization": authorization})

    async def introspect_project_id(self, *, authorization: str) -> str:
        data = await self.introspect(authorization=authorization)
        project_id = (data.get("project_id") or "").strip()
        if not project_id:
            raise HTTPException(status_code=502, detail="aweb introspection missing project_id")
        return project_id

    async def current_project(self, *, authorization: str) -> dict:
        return await self._request_json("GET", "/v1/projects/current", headers={"Authorization": authorization})

    async def send_message(
        self,
        *,
        authorization: str,
        from_agent_id: str,
        from_alias: str,
        to_agent_id: str,
        subject: str = "",
        body: str,
        priority: str = "normal",
        thread_id: str | None = None,
    ) -> dict:
        payload: dict = {
            "from_agent_id": from_agent_id,
            "from_alias": from_alias,
            "to_agent_id": to_agent_id,
            "subject": subject,
            "body": body,
            "priority": priority,
            "thread_id": thread_id,
        }
        payload = {k: v for k, v in payload.items() if v is not None}
        return await self._request_json(
            "POST",
            "/v1/messages",
            headers={"Authorization": authorization},
            json=payload,
        )
