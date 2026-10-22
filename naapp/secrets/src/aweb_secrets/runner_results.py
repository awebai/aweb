"""Runner output validation and server-side redaction, before persistence.

S13 supplies KnownValues from the ORIGINAL released values. A later live
1Password read is not that context. None means that the context is unavailable,
in which case output is withheld. This helper opens nothing, stores no raw
streams, and grants no dispatch authority.
"""

from dataclasses import dataclass

from aweb_naapp.runtime.approvals.request import RequestNotCanonical, parse_request_json

from aweb_secrets.credential_shapes import has_credential_shape
from aweb_secrets.jobs import JobDefinition
from aweb_secrets.redaction import KnownValues
from aweb_secrets.responses import handle_response
from aweb_secrets.runner_protocol import canonical

_SAFE_INTEGER = 2**53 - 1
_FIELDS = {"exit_code", "stdout", "stderr", "truncated", "result_withheld", "redaction_count"}


class RunnerResultInvalid(ValueError):
    def __init__(self) -> None:
        super().__init__("runner_result_invalid")


@dataclass(frozen=True, repr=False)
class RunnerOutput:
    """Only projected/redacted output may reach storage or the agent.

    Runner-reported redactions are informational and kept separately from the
    server's count, so a safe maximum runner count cannot overflow a wire sum.
    Exit status and local observations remain visible independently of output
    projection or server withholding, including loss of the release context.
    """

    body: bytes | None
    result_withheld: bool
    withheld_reason: str | None
    truncated: bool
    redaction_count: int
    runner_redaction_count: int
    output_bytes: int
    exit_code: int
    runner_result_withheld: bool
    runner_truncated: bool


def process_runner_result(
    raw: bytes, *, job: JobDefinition, known: KnownValues | None
) -> RunnerOutput:
    """Process the bounded six-field report; never return its original streams.

    The sixfold frame allowance accommodates JSON escapes for each UTF-8 byte;
    the pinned bound applies to the DECODED combined stdout/stderr bytes.
    Malformed reports have a constant value-free error. The HTTP adapter owns
    the corresponding protocol refusal and authenticated effect transaction.
    """
    output = job.after["output"]
    limit = output["max_bytes"]
    frame_limit = 6 * limit + 1024
    try:
        if len(raw) > frame_limit:
            raise ValueError()
        report = parse_request_json(raw)
        if set(report) != _FIELDS:
            raise ValueError()
        canonical(report)
        if (
            type(report["exit_code"]) is not int
            or abs(report["exit_code"]) > _SAFE_INTEGER
            or type(report["truncated"]) is not bool
            or type(report["result_withheld"]) is not bool
            or type(report["redaction_count"]) is not int
            or not 0 <= report["redaction_count"] <= _SAFE_INTEGER
            or not all(isinstance(report[k], str) for k in ("stdout", "stderr"))
        ):
            raise ValueError()
        streams = [report[k].encode("utf-8") for k in ("stdout", "stderr")]
        size = sum(map(len, streams))
        if size > limit or report["result_withheld"] and any(streams):
            raise ValueError()
    except (RequestNotCanonical, ValueError, TypeError, RecursionError):
        raise RunnerResultInvalid() from None

    def withheld(reason: str, count: int = 0) -> RunnerOutput:
        return RunnerOutput(
            body=None,
            result_withheld=True,
            withheld_reason=reason,
            truncated=report["truncated"],
            redaction_count=count,
            runner_redaction_count=report["redaction_count"],
            output_bytes=size,
            exit_code=report["exit_code"],
            runner_result_withheld=report["result_withheld"],
            runner_truncated=report["truncated"],
        )

    if known is None:
        return withheld("release_context_unavailable")
    redactions = 0
    clean = []
    for stream in streams:
        stream, count = known.redact(stream)
        redactions += count
        if report["truncated"]:
            stream, count = known.redact_tail(stream)
            redactions += count
        # Detect each decoded stream before wrapping it in JSON, where escaped
        # credential-named fields would otherwise hide their original shape.
        if has_credential_shape(stream):
            return withheld("credential_shaped", redactions)
        clean.append(stream.decode("utf-8"))
    handled = handle_response(
        status=200,
        headers=[],
        body=canonical({"exit_code": report["exit_code"], "stdout": clean[0], "stderr": clean[1]}),
        # A locally cut stream is still inside a COMPLETE JSON object; retain
        # its safe prefix/exit projection and report the local cut separately.
        truncated=False,
        max_bytes=frame_limit,
        projection=output["projection"],
        known=known,
        token_issuing=False,
    )
    redactions += handled.redaction_count
    if report["result_withheld"]:
        return withheld("runner_withheld", redactions)
    return RunnerOutput(
        body=handled.body,
        result_withheld=handled.disposition == "withheld",
        withheld_reason=handled.withheld_reason,
        truncated=report["truncated"] or handled.truncated,
        redaction_count=redactions,
        runner_redaction_count=report["redaction_count"],
        output_bytes=size,
        exit_code=report["exit_code"],
        runner_result_withheld=report["result_withheld"],
        runner_truncated=report["truncated"],
    )
