#!/usr/bin/env python3
"""Run shared event vectors against the pinned Cloud validator, offline.

The function below is the owner-supplied pure excerpt from awebai/ac
7665d8638fac94b05db4101c6049fa4ea4c3b0e0. This is evidence of that implementation,
not a replacement gateway implementation. Known coercion/count divergences
are explicit per vector; do not report those as contract parity.
"""
import hashlib
import json
from pathlib import Path
import re
from typing import Any

_LOCAL_EVENT_TYPE_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_ALLOWED_DELIVERY_INTENTS = frozenset({"wake", "steer", "ambient"})


def _manifest_events(manifest: dict[str, Any], *, app_id: str) -> list[dict[str, str]]:
    allowed_keys = {"type", "default_delivery_intent", "description"}
    events: list[dict[str, str]] = []
    for index, event in enumerate(manifest.get("events") or []):
        if not isinstance(event, dict):
            raise ValueError(f"manifest.events[{index}] must be an object")
        extra_keys = sorted(set(event) - allowed_keys)
        if extra_keys:
            raise ValueError(f"manifest.events[{index}] contains unsupported fields")
        event_type = str(event.get("type") or "").strip()
        if not event_type:
            raise ValueError(f"manifest.events[{index}].type is required")
        prefix = f"{app_id}/"
        if event_type.startswith(prefix):
            event_type = event_type[len(prefix) :]
        elif "/" in event_type:
            raise ValueError(f"manifest.events[{index}].type must be app-local")
        if not _LOCAL_EVENT_TYPE_RE.fullmatch(event_type):
            raise ValueError(f"manifest.events[{index}].type is invalid")
        intent = str(event.get("default_delivery_intent") or "ambient").strip() or "ambient"
        if intent not in _ALLOWED_DELIVERY_INTENTS:
            raise ValueError(f"manifest.events[{index}].default_delivery_intent is invalid")
        normalized: dict[str, str] = {"type": event_type, "default_delivery_intent": intent}
        if "description" in event:
            raw_description = event.get("description")
            if not isinstance(raw_description, str):
                raise ValueError(f"manifest.events[{index}].description must be a string")
            description = raw_description.strip()
            if len(description) > 4096:
                raise ValueError(f"manifest.events[{index}].description is too long")
            normalized["description"] = description
        events.append(normalized)
    return events


def main():
    fixtures = Path(__file__).resolve().parents[1] / "cli/go/internal/appmanifest/testdata"
    vectors = json.loads((fixtures / "events-v1.json").read_text())
    divergences = []
    for case in vectors["cases"]:
        try:
            _manifest_events(case["manifest"], app_id=case["manifest"]["app"]["id"])
            accepted = True
        except (ValueError, TypeError):
            accepted = False
        assert accepted == case["gateway_accepted"], case["name"]
        if accepted != case["accepted"]:
            divergences.append(case["name"])
    for name, digest in {
        "folio": "480b157753e1ecc9cd257daf70a35b97c5943960d69183971c32498b48c313e3",
        "library": "0019130d90bbbc61fde49c144b4f883eabac837889b0c69f515d206b35552329",
    }.items():
        raw = (fixtures / f"{name}-deployed.json").read_bytes()
        assert hashlib.sha256(raw).hexdigest() == digest
        _manifest_events(json.loads(raw), app_id=name)
    print(json.dumps({"vectors": len(vectors["cases"]), "deployed_manifests": 2,
                      "known_gateway_divergences": divergences}, sort_keys=True))


if __name__ == "__main__":
    main()
