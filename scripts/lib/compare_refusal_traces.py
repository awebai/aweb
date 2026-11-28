#!/usr/bin/env python3
"""Compare the final mail POST refusals of two aw traces as raw wire bytes.

  compare_refusal_traces.py <mail POST URL> <hidden trace> <missing trace>

Exits non-zero unless both final responses are the same 404 status, body and
content type, and every earlier attempt was a retried transient failure.
"""

from pathlib import Path
import sys


def response(path):
    requests = Path(path).read_bytes().split(b"AW TRACE request: ")
    target = b"POST " + sys.argv[1].encode() + b"\n"
    matches = [request for request in requests if request.startswith(target)]
    # Keep diagnostics after the temporary trace files are removed. Do not
    # print signed headers or message bodies, only request/status/retry lines.
    summary = [
        line.decode(errors="replace")
        for line in Path(path).read_bytes().splitlines()
        if line.startswith(
            (
                b"AW TRACE request: ",
                b"AW TRACE response: HTTP ",
                b"service temporarily unavailable, retrying ",
            )
        )
    ]
    assert matches, f"{Path(path).name}: no mail POST; trace summary: {summary}"
    assert len(matches) <= 4, (
        f"{Path(path).name}: too many mail POST attempts: {len(matches)}"
    )
    for index, attempt in enumerate(matches[:-1]):
        # These are the client's bounded retries, not a second command send.
        notice = f"service temporarily unavailable, retrying {index + 1}/3 (POST /v1/messages)\n".encode()
        assert notice in attempt, f"mail POST attempt {index + 1}: missing retry notice"
        if b"AW TRACE response" not in attempt:
            # A transport error has no response; the actual client retry
            # notice is required. A partial HTTP response must not pass here.
            continue
        status, _, _ = parse_response(attempt)
        assert status == 503, (
            f"mail POST attempt {index + 1}: non-retryable HTTP {status}"
        )
    status, headers, body = parse_response(matches[-1])
    assert status == 404, (
        f"{Path(path).name}: final mail POST HTTP {status}; trace summary: {summary}"
    )
    # Only the final JSON refusal is compared as raw wire bytes. An earlier
    # non-JSON 503 body may have been sanitized by the client's trace writer.
    length = int(headers[b"Content-Length"])
    assert length > 0 and body[length : length + 1] == b"\n", (
        "incomplete response trace"
    )
    return status, body[:length], headers[b"Content-Type"]


def parse_response(attempt):
    assert attempt.count(b"AW TRACE response: HTTP ") == 1, (
        "missing or ambiguous mail POST response"
    )
    head, body = attempt.split(b"AW TRACE response: HTTP ", 1)[1].split(
        b"AW TRACE response body: ", 1
    )
    status = int(head.splitlines()[0])
    prefix = b"AW TRACE response header: "
    headers = dict(
        line[len(prefix) :].split(b": ", 1)
        for line in head.splitlines()
        if line.startswith(prefix)
    )
    return status, headers, body


hidden, missing = map(response, sys.argv[2:])
assert missing[0] == 404, "missing conversation must return 404"
assert hidden == missing, "hidden and missing conversation wire responses differ"
