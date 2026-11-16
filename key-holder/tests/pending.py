"""Authentically signed expired intent fixtures; no clock/verifier replacement."""

import json
import time

from approval_service.canonical import canonical


def expire_pending(holder, person):
    with holder.store._connection() as db, db:
        db.execute("BEGIN IMMEDIATE")
        row = holder._row(db, person)
        old = json.loads(row["intent"])
        body = {
            **old["intent"],
            "not_before": int(time.time()) - 86401,
            "deadline": int(time.time()) - 1,
        }
        expired = {
            "intent": body,
            "signature": holder._protocol(
                db,
                holder.store._descriptor(db),
                "enrollment_intent",
                body,
                actor=body["requester"]["key"],
            ),
        }
        db.execute(
            "UPDATE enrollments SET intent=? WHERE person=?",
            (canonical(expired).decode(), person),
        )
        return expired
