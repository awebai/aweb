"""secrets' manifest v2 template (secrets §13.1).

The authoring source fixes tools, contexts, hook productions and key purposes.
The shared runtime fills the deployment's app identity, origin and did:keys
from configured key files, validates with the X8 interpreter, and serves the
resolved bytes through the v2 catalog. No secret value enters a tool.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

MANIFEST_PATH = Path(__file__).resolve().parent / "aweb-app.json"

_STRING = {"type": "string"}
_REQUEST_ID = {
    "type": "string",
    "description": "The caller's key for this request; a retry with the same body returns the first receipt.",
}


def _params(*names: str, path: tuple[str, ...] = ()) -> list[dict[str, str]]:
    return [{"in": "path", "name": name} for name in path] + [
        {"in": "body", "name": name} for name in names
    ]


MANIFEST: dict[str, Any] = {
    "manifest_version": 2,
    "app": {
        "id": "secrets",
        "version": "0.1.0",
        "origin": "https://secrets.aweb.ai",
    },
    "app_keys": [
        {"kid": "secrets:hook-event-1", "purposes": ["hook-event"]},
        {"kid": "secrets:hook-delivery-1", "purposes": ["hook-delivery"]},
        {"kid": "secrets:grant-read-1", "purposes": ["app-grant-read"]},
    ],
    "hooks": {
        "registration_version": 1,
        "productions": [
            {"catalog": {"id": "aweb.hooks", "version": 1}, "hook": "post-secret-use-hook", "reads": []},
            {"catalog": {"id": "aweb.hooks", "version": 1}, "hook": "post-governance-hook", "reads": []},
        ],
    },
    "tools": [
        {
            "name": "list",
            "description": "List the secrets you may use: refs, kinds, sensitivity, destinations and approval requirements. Never values.",
            "method": "GET",
            "path": "/v1/secrets",
            "scopes": ["secrets:read"],
            "mutation": False,
            "params": [],
            "input_schema": {"type": "object", "properties": {}},
        },
        {
            "name": "describe",
            "description": "Show one secret's operations, with their parameters, and the jobs you may run with it.",
            "method": "GET",
            "path": "/v1/secrets/{secret}",
            "scopes": ["secrets:read"],
            "mutation": False,
            "params": _params(path=("secret",)),
            "input_schema": {
                "type": "object",
                "properties": {"secret": _STRING},
                "required": ["secret"],
            },
        },
        {
            "name": "request",
            "description": "Make a brokered call with a secret: a named operation, or an open request where the grant allows one. Returns the result, or awaiting_approval with an approval_ref.",
            "method": "POST",
            "path": "/v1/secrets/{secret}/requests",
            "scopes": ["secrets:use"],
            "mutation": True,
            "body": {"mode": "json"},
            "params": _params(
                "request_id",
                "operation",
                "params",
                "method",
                "url",
                "headers",
                "data",
                "reason",
                path=("secret",),
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "secret": _STRING,
                    "request_id": _REQUEST_ID,
                    "operation": {"type": "string", "description": "A named operation's id."},
                    "params": {"type": "object", "description": "The named operation's parameters."},
                    "method": {
                        "type": "string",
                        "enum": ["GET", "POST", "PUT", "PATCH", "DELETE"],
                        "description": "An open request's HTTP method.",
                    },
                    "url": {"type": "string", "description": "An open request's URL."},
                    "headers": {"type": "array", "description": "An open request's headers, as 'Name: value' strings."},
                    "data": {"description": "An open request's body: a string, or a JSON object."},
                    "reason": {"type": "string", "description": "Shown to the approver as untrusted text."},
                },
                "required": ["secret", "request_id"],
            },
        },
        {
            "name": "run",
            "description": "Run a job on a runner, with the credentials its definition names.",
            "method": "POST",
            "path": "/v1/jobs/{job}/runs",
            "scopes": ["secrets:run"],
            "mutation": True,
            "body": {"mode": "json"},
            "params": _params("request_id", "runner", "params", "reason", "secret", path=("job",)),
            "input_schema": {
                "type": "object",
                "properties": {
                    "job": _STRING,
                    "request_id": _REQUEST_ID,
                    "runner": {"type": "string", "description": "The runner to run the job on."},
                    "params": {"type": "object", "description": "The job's parameters."},
                    "reason": {"type": "string", "description": "Shown to the approver as untrusted text."},
                    "secret": {
                        "type": "string",
                        "description": "An ordinary derived child's ref for the unique durable slot; omit to use the job's fixed selectors.",
                    },
                },
                "required": ["job", "request_id", "runner"],
            },
        },
        {
            "name": "status",
            "description": "Show the state of a request, an approval or a reconciliation, by its request_id, approval_ref or reconcile_ref. Never a link.",
            "method": "GET",
            "path": "/v1/status/{ref}",
            "scopes": ["secrets:read"],
            "mutation": False,
            "params": _params(path=("ref",)),
            "input_schema": {
                "type": "object",
                "properties": {"ref": _STRING},
                "required": ["ref"],
            },
        },
        {
            "name": "cancel",
            "description": "Cancel your own request while it is not yet admitted.",
            "method": "POST",
            "path": "/v1/requests/{request_id}/cancel",
            "scopes": ["secrets:use"],
            "mutation": True,
            "body": {"mode": "json"},
            "params": _params(path=("request_id",)),
            "input_schema": {
                "type": "object",
                "properties": {"request_id": _STRING},
                "required": ["request_id"],
            },
        },
        {
            "name": "contain",
            "description": "Narrow authority at once: revoke a grant, approvals or an approver's passkey or contact, disable a secret or the installation, or deregister a runner. Owners only.",
            "method": "POST",
            "path": "/v1/containment",
            "scopes": ["secrets:admin"],
            "mutation": True,
            "body": {"mode": "json"},
            "params": _params("request_id", "action", "target"),
            "input_schema": {
                "type": "object",
                "properties": {
                    "request_id": _REQUEST_ID,
                    "action": {
                        "type": "string",
                        "enum": [
                            "revoke-grant",
                            "revoke-approvals",
                            "disable-secret",
                            "disable-installation",
                            "deregister-runner",
                            "revoke-approver",
                        ],
                    },
                    "target": {"type": "string", "description": "The grant, approval, secret, runner or approver id."},
                },
                "required": ["request_id", "action"],
            },
        },
        {
            "name": "propose-change",
            "description": "Draft a widening metadata or authority change. It takes effect only after an owner's passkey confirmation on the console. Never accepts a secret value.",
            "method": "POST",
            "path": "/v1/changes",
            "scopes": ["secrets:admin"],
            "mutation": True,
            "body": {"mode": "json"},
            "params": _params("request_id", "change"),
            "input_schema": {
                "type": "object",
                "properties": {"request_id": _REQUEST_ID, "change": {"type": "object"}},
                "required": ["request_id", "change"],
            },
        },
        {
            "name": "activity",
            "description": "Show the owner's operational record of requests, approvals and dispatches, including outcomes that need reconciliation. Never values.",
            "method": "GET",
            "path": "/v1/activity",
            "scopes": ["secrets:read"],
            "mutation": False,
            "params": [],
            "input_schema": {"type": "object", "properties": {}},
        },
    ],
}

for _tool in MANIFEST["tools"]:
    _tool["invocation_contexts"] = (
        ["surface"] if _tool["name"] in {"propose-change", "activity"} else ["agent", "surface"]
    )
