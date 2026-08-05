#!/usr/bin/env python3
"""Disposable request-schema control for the 2026-07-26 mark-read break.

This does not mutate or stand in for candidate bytes.  It submits the same
legacy request to the shipped dual-shape request model and to a disposable
model with ``message_ids`` made required.  FastAPI maps the latter validation
failure to HTTP 422; the result is control-only evidence.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "server/src"), str(ROOT / "awid/src")]

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from pydantic import BaseModel, Field  # noqa: E402
from aweb.routes.chat import MarkReadRequest  # noqa: E402


class DisposableRequiredFieldRequest(BaseModel):
    message_ids: list[str] = Field(min_length=1)


def request_status(model, payload: dict) -> int:
    app = FastAPI()

    async def mark_read(request):
        return {"messages_marked": 1}

    mark_read.__annotations__["request"] = model
    app.post("/v1/chat/sessions/control/read")(mark_read)

    with TestClient(app) as client:
        return client.post(
            "/v1/chat/sessions/control/read", json=payload
        ).status_code


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--message-id", required=True)
    args = parser.parse_args(argv)
    request = {"up_to_message_id": args.message_id}
    report = {
        "request": request,
        "unmutated_status": request_status(MarkReadRequest, request),
        "mutated_status": request_status(
            DisposableRequiredFieldRequest, request
        ),
        "mutation_subject": "disposable required-field server",
    }
    print(json.dumps(report, sort_keys=True))
    return 0 if (
        report["unmutated_status"] == 200
        and report["mutated_status"] == 422
    ) else 1


if __name__ == "__main__":
    raise SystemExit(main())
