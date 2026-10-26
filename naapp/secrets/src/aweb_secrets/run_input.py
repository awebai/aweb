"""Detached run submission equality, separate from authenticated-byte audit MACs.

The resolved original job pin comes from scoped discovery or the existing run.
This type is inert: it supplies neither a plan nor a grant, key or admission.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from aweb_naapp.runtime.approvals import RequestNotCanonical, canonical_request
from aweb_naapp.runtime.approvals.request import DOMAIN_PREFIX

from aweb_secrets.admission import AdmissionRefused
from aweb_secrets.policy import IDENTIFIER
from aweb_secrets.runner_protocol import RUNNER_ID
from aweb_secrets.secret import REF
from aweb_secrets.use_approval import MAX_REASON_LENGTH

_DOMAIN = b"aweb.secrets.run-request/1\n"
_FIELDS = frozenset({"request_id", "runner", "params", "reason", "secret"})
_DIGEST = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True, repr=False)
class RunInput:
    _canonical: bytes

    @classmethod
    def from_body(cls, job: str, body: Mapping[str, Any], *, job_digest: str) -> RunInput:
        try:
            if (
                not isinstance(job, str)
                or IDENTIFIER.fullmatch(job) is None
                or not isinstance(job_digest, str)
                or _DIGEST.fullmatch(job_digest) is None
                or not isinstance(body, Mapping)
                or body.keys() - _FIELDS
            ):
                raise ValueError()
            request_id, runner = body.get("request_id"), body.get("runner")
            params, reason = body.get("params", {}), body.get("reason", "")
            selected = body.get("secret")
            if (
                not isinstance(request_id, str)
                or not request_id
                or not isinstance(runner, str)
                or RUNNER_ID.fullmatch(runner) is None
                or not isinstance(params, Mapping)
                or not isinstance(reason, str)
                or len(reason) > MAX_REASON_LENGTH
                or (
                    "secret" in body
                    and (not isinstance(selected, str) or REF.fullmatch(selected) is None)
                )
            ):
                raise ValueError()
            model = {
                "job": job,
                "job_digest": job_digest,
                "request_id": request_id,
                "runner": runner,
                "params": dict(params),
                "reason": reason,
                "secret": selected,
            }
            canonical = canonical_request(model)[len(DOMAIN_PREFIX) :]
            canonical.decode("utf-8").encode("utf-8")
        except (RequestNotCanonical, ValueError, TypeError, UnicodeError, RecursionError):
            raise AdmissionRefused("params_invalid", 400) from None
        return cls(canonical)

    @property
    def request_sha256(self) -> bytes:
        return hashlib.sha256(_DOMAIN + self._canonical).digest()

    @property
    def request_id(self) -> str:
        return json.loads(self._canonical)["request_id"]

    @property
    def runner_id(self) -> str:
        return json.loads(self._canonical)["runner"]

    @property
    def job_id(self) -> str:
        return json.loads(self._canonical)["job"]

    @property
    def job_digest(self) -> str:
        return json.loads(self._canonical)["job_digest"]

    @property
    def params(self) -> dict[str, Any]:
        return json.loads(self._canonical)["params"]

    @property
    def reason(self) -> str:
        return json.loads(self._canonical)["reason"]

    @property
    def secret_ref(self) -> str | None:
        return json.loads(self._canonical)["secret"]
