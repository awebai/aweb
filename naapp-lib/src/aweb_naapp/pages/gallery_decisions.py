"""Disposable loopback adapter fixtures; never production approval authority."""

from __future__ import annotations

import copy
import json
import re
from datetime import UTC, datetime, timedelta
from typing import Any

from aweb_naapp.pages import bundle_sha256, proposal_sha256

# Separate trusted task fixture: never derive labels or membership from page props.
TASK_OPTIONS = [{"value": "approve", "label": "Approve"}, {"value": "reject", "label": "Reject"}]
TASK_FIELDS = [
    {"field": "start", "label": "From", "format": "date"},
    {"field": "end", "label": "Until", "format": "date"},
    {"field": "price_minor", "label": "Nightly price", "format": "money_minor"},
    {"field": "reason", "label": "Reason", "format": "text"},
]
EXPIRES = (datetime.now(UTC) + timedelta(hours=2)).isoformat()


def proposal_digest(collection: str, record: dict) -> str:
    return proposal_sha256(collection, record["id"], record["value"])


def additions(page: dict, case: str = "") -> None:
    records: list[dict[str, Any]] = [
        {
            "id": "price-1",
            "rev": 1,
            "value": {
                "start": "2026-10-24",
                "end": "2026-10-30",
                "price_minor": 12000,
                "currency": "EUR",
                "reason": "Available dates at the proposed nightly price.",
            },
        },
        {
            "id": "price-2",
            "rev": 2,
            "value": {
                "start": "2026-10-31",
                "end": "2026-11-06",
                "price_minor": 13500,
                "currency": "EUR",
                "reason": "A second week, reviewed together.",
            },
        },
    ]
    if case == "decision-missing-field":
        del records[0]["value"]["reason"]
    if case == "decision-missing-currency":
        del records[0]["value"]["currency"]
    if case == "decision-jpy":
        for record in records:
            record["value"]["currency"] = "JPY"
    items = [
        {
            "record_id": r["id"],
            "record_rev": r["rev"],
            "proposal_sha256": proposal_digest("review-proposals", r),
        }
        for r in records
    ]
    page["collections"].extend(
        [
            {
                "id": "review-proposals",
                "mode": "owned",
                "schema_version": 1,
                "schema": {
                    "type": "object",
                    "properties": {
                        "start": {"type": "string", "format": "date", "title": "From"},
                        "end": {"type": "string", "format": "date", "title": "Until"},
                        "price_minor": {
                            "type": "integer",
                            "title": "Nightly price in minor currency units",
                        },
                        "currency": {"type": "string", "title": "Currency"},
                        "reason": {"type": "string", "title": "Reason"},
                    },
                    "additionalProperties": False,
                },
                "records": records,
            },
            {
                "id": "review-bundles",
                "mode": "owned",
                "schema_version": 1,
                "schema": {
                    "type": "object",
                    "properties": {
                        "items": {
                            "type": "array",
                            "maxItems": 64,
                            "items": {
                                "type": "object",
                                "properties": {
                                    "record_id": {"type": "string"},
                                    "record_rev": {"type": "integer"},
                                    "proposal_sha256": {"type": "string"},
                                },
                                "additionalProperties": False,
                            },
                        }
                    },
                    "additionalProperties": False,
                },
                "records": [{"id": "two-weeks", "rev": 1, "value": {"items": items}}],
            },
        ]
    )
    for kind in ("price", "bundle"):
        page["actions"].append(
            {
                "id": f"answer-{kind}",
                "kind": "answer",
                "label": "Record decision",
                "policy_ref": "fixture-decision",
                "input_schema": {"type": "object", "additionalProperties": False},
            }
        )
        props: dict[str, Any] = {
            "task_id": f"task-{kind}",
            "task_rev": 1,
            "collection": "review-proposals" if kind == "price" else "review-bundles",
            "record_id": "price-1" if kind == "price" else "two-weeks",
            "record_rev": 1,
            "options": copy.deepcopy(TASK_OPTIONS),
            "recommendation": "approve",
            "answer_action": f"answer-{kind}",
            "proposal_sha256": items[0]["proposal_sha256"]
            if kind == "price"
            else bundle_sha256(items),
            "operation": {
                "kind": "fixture.internal.review",
                "destination": "Internal fixture record",
                "summary": "Review the proposed nightly price"
                if kind == "price"
                else "Review both weeks together",
            },
            "source_version": "fixture-source-v1",
            "expires_at": EXPIRES,
        }
        if kind == "bundle":
            props.update(bundle=True, items_collection="review-proposals")
        if case == "decision-options":
            props["options"][0]["label"], props["options"][1]["label"] = "Reject", "Approve"
        if case == "decision-reopened":
            props["task_rev"] = 3
        if case == "decision-expired":
            props["expires_at"] = "2020-01-01T00:00:00Z"
        page["layout"].append({"id": f"{kind}-decision", "type": "decision_card", "props": props})
    if case == "decision-display":
        records[0]["value"]["price_minor"] = 99999
    if case == "decision-input":
        action = next(a for a in page["actions"] if a["id"] == "answer-price")
        action["input_schema"].update(
            properties={"explanation": {"type": "string"}}, required=["explanation"]
        )
    if case == "decision-denied":
        page["widget_state"]["price-decision"] = {
            "message": "Approved by page data",
            "progress": 100,
            "busy": True,
        }


def evidence(page: dict, task_id: str, state: dict, case: str = "") -> dict:
    card = next(
        w
        for w in page["layout"]
        if w["type"] == "decision_card" and w["props"]["task_id"] == task_id
    )
    p = card["props"]
    record = next(
        r
        for c in page["collections"]
        if c["id"] == p["collection"]
        for r in c["records"]
        if r["id"] == p["record_id"]
    )
    result: dict[str, Any] = {
        key: copy.deepcopy(p[key])
        for key in (
            "task_id",
            "task_rev",
            "collection",
            "record_id",
            "record_rev",
            "operation",
            "source_version",
            "expires_at",
        )
    }
    result.update(
        question_rev=1,
        options=copy.deepcopy(TASK_OPTIONS),
        fields=copy.deepcopy(TASK_FIELDS),
        allowed=case != "decision-denied",
        authenticator="member_session",
        status="open",
    )
    if p.get("bundle"):
        items = copy.deepcopy(record["value"]["items"])
        for item in items:
            current = next(
                r
                for c in page["collections"]
                if c["id"] == p["items_collection"]
                for r in c["records"]
                if r["id"] == item["record_id"]
            )
            item.update(
                record_rev=current["rev"],
                proposal_sha256=proposal_digest(p["items_collection"], current),
            )
        result.update(items=items, proposal_sha256=bundle_sha256(items))
    else:
        result["proposal_sha256"] = proposal_digest(p["collection"], record)
    if task_id in state.get("answers", {}):
        result.update(
            status="answered",
            application_state=state["answers"][task_id][1].get("application_state", "pending"),
            answer=state["answers"][task_id][1],
            task_rev=state["answers"][task_id][1]["task_rev"],
            question_rev=state["answers"][task_id][1]["question_rev"],
        )
    if case == "decision-task":
        result["task_rev"] += 1
    if case == "decision-record":
        result["record_rev"] += 1
    if case == "decision-digest":
        result["proposal_sha256"] = "sha256:" + "0" * 64
    if case == "decision-operation":
        result["operation"]["destination"] = "Changed destination"
    if case == "decision-source":
        result["source_version"] = "new-source-version"
    if case == "decision-item" and "items" in result:
        result["items"][0]["record_rev"] += 1
    if task_id not in state.get("answers", {}) and case in {
        "decision-superseded",
        "decision-reopened",
        "decision-approved",
        "decision-rejected",
        "decision-applied",
        "decision-apply-failed",
    }:
        receipt = {
            "current": case
            in {
                "decision-approved",
                "decision-rejected",
                "decision-applied",
                "decision-apply-failed",
            },
            "task_id": task_id,
            "task_rev": 2,
            "question_rev": 1,
            "proposal_rev": p["record_rev"],
            "proposal_sha256": result["proposal_sha256"],
            "choice": "reject" if case == "decision-rejected" else "approve",
            "task_answer_ref": "fixture-read-only-answer",
            "approval_state": "rejected" if case == "decision-rejected" else "approved",
        }
        if receipt["current"]:
            result.update(
                status="answered",
                task_rev=2,
                answer=receipt,
                application_state="applied"
                if case == "decision-applied"
                else "failed"
                if case == "decision-apply-failed"
                else "pending",
            )
        else:
            result.update(status="open", task_rev=3, question_rev=2, answer=receipt)
    if case == "decision-passkey-pending":
        result.update(authenticator="passkey", status="pending")
    if case == "decision-closed":
        result.update(status="closed")
    return result


def answer(page: dict, request: dict, state: dict, case: str = "") -> tuple[dict, int]:
    try:
        current = evidence(page, request["task_id"], state, case)
        card = next(
            w
            for w in page["layout"]
            if w["type"] == "decision_card" and w["props"]["task_id"] == request["task_id"]
        )
        stage = request["stage"]
        if set(stage) != {
            "expected_task_rev",
            "choice",
            "input",
            "proposal_rev",
            "proposal_sha256",
            "answer_key",
        }:
            raise ValueError()
        if type(stage["expected_task_rev"]) is not int or type(stage["proposal_rev"]) is not int:
            raise ValueError()
        if not isinstance(stage["answer_key"], str) or not re.fullmatch(
            r"[A-Za-z0-9._-]{1,128}", stage["answer_key"]
        ):
            raise ValueError()
        canonical = json.dumps(stage, sort_keys=True)
        prior = state.setdefault("answers", {}).get(request["task_id"])
        if prior:
            return (prior[1], 200) if prior[0] == canonical else ({"code": "already_answered"}, 409)
        if (
            stage["expected_task_rev"] != current["task_rev"]
            or stage["proposal_rev"] != current["record_rev"]
            or stage["proposal_sha256"] != current["proposal_sha256"]
            or stage["choice"] not in [o["value"] for o in current["options"]]
            or stage["input"] != {}
            or request["action_id"] != card["props"]["answer_action"]
        ):
            return {"code": "revision_conflict"}, 409
        if datetime.fromisoformat(current["expires_at"]) <= datetime.now(UTC):
            return {"code": "expired"}, 409
        if case == "decision-unknown" and not state.get("unknown_answer_seen"):
            state["unknown_answer_seen"] = True
            return {"code": "unavailable"}, 503
        receipt = {
            "current": True,
            "task_id": request["task_id"],
            "task_rev": current["task_rev"] + 1,
            "question_rev": current["question_rev"],
            "proposal_rev": stage["proposal_rev"],
            "proposal_sha256": stage["proposal_sha256"],
            "choice": stage["choice"],
            "task_answer_ref": "fixture-answer-" + stage["answer_key"],
            "approval_state": "rejected" if stage["choice"] == "reject" else "approved",
        }
        state["answers"][request["task_id"]] = (canonical, receipt)
        return receipt, 200
    except (KeyError, StopIteration, TypeError, ValueError):
        return {"code": "schema_invalid"}, 422
