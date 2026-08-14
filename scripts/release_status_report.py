#!/usr/bin/env python3
"""Failure-preserving stop reports and recorded-observation loading
(aben, design section 8).

On any stop the original refusal is primary; the bounded probe sweep
renders failures as UNAVAILABLE rows; a reporting exception can never
replace the diagnostic; exit is nonzero for the original stop regardless
of what reporting does. Recorded observations (the B-row fixtures' shape,
committed to dev2 verbatim) load into rows without reinterpretation.
"""

from __future__ import annotations

import dataclasses

from release_status import Row

STOP_EXIT = 1


@dataclasses.dataclass(frozen=True)
class StopReportResult:
    text: str
    exit_code: int


def stop_report(*, refusal: str, rows) -> StopReportResult:
    lines = [refusal, ""]
    lines += [row.render() for row in rows]
    return StopReportResult(text="\n".join(lines), exit_code=STOP_EXIT)


def stop_report_with_probes(*, refusal: str, probe) -> StopReportResult:
    """The probe sweep runs after the refusal is already secured; any
    probe failure becomes an UNAVAILABLE row and any reporter bug is
    swallowed into one line - the diagnostic always survives."""

    lines = [refusal, ""]
    try:
        outcome = probe()
        if outcome:
            lines += [row.render() for row in outcome]
    except OSError as error:
        lines.append(
            Row(
                fact="status probe sweep",
                state="unavailable",
                evidence=str(error),
            ).render()
        )
    except Exception as error:  # noqa: BLE001 - the diagnostic survives
        lines.append(f"(status reporting failed: {error!r} - refusal above stands)")
    return StopReportResult(text="\n".join(lines), exit_code=STOP_EXIT)


def rows_from_recorded_observations(document) -> list[Row]:
    """dev2's recorded-observation shape, loaded verbatim:
    {"observations": {target: {version: {"state": present|absent,
    "evidence": ...}}}, "provenance": {...}}."""

    rows: list[Row] = []
    for target, versions in sorted(document["observations"].items()):
        for version, fact in sorted(versions.items()):
            state = {
                "present": "observed-present",
                "absent": "observed-absent",
            }[fact["state"]]
            rows.append(
                Row(
                    fact=f"{target} {version}",
                    state=state,
                    evidence=fact["evidence"],
                )
            )
    return rows
