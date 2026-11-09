"""One fixed weekly aggregate, with no SQL or target supplied by the caller."""

import json
from datetime import date

import pytest

from report import ReportRefused, parameters, render


@pytest.mark.parametrize("dataset", ["orders", "inventory"])
def test_fixed_dataset_and_calendar_week_are_typed(dataset):
    selected = parameters(["--dataset", dataset, "--week-start", "2026-11-02"])
    assert selected.dataset == dataset
    assert selected.start == date(2026, 11, 2)
    assert selected.end == date(2026, 11, 9)


@pytest.mark.parametrize(
    "argv",
    [
        [],
        ["--dataset", "other", "--week-start", "2026-11-02"],
        ["--dataset", "orders' OR 1=1 --", "--week-start", "2026-11-02"],
        ["--dataset", "orders", "--week-start", "2026-11-03"],
        ["--dataset", "orders", "--week-start", "2026-02-30"],
        ["--dataset", "orders", "--week-start", "20261102"],
        ["--dataset", "orders", "--week-start", "2026-W45-1"],
        ["--dataset", "orders", "--week-start", "2026-11-02", "--sql", "SELECT 1 FROM DUAL"],
        ["--dataset", "orders", "--week-start", "2026-11-02", "--dsn", "other.invalid"],
        ["--dataset", "orders", "--week-start", "2026-11-02", "--dataset", "inventory"],
    ],
)
def test_disallowed_inputs_are_refused_without_coercion(argv):
    with pytest.raises(ReportRefused):
        parameters(argv)


def test_report_projects_only_public_metadata_and_three_counts():
    selected = parameters(["--dataset", "orders", "--week-start", "2026-11-02"])
    raw = render(selected, (7, 2, 1))
    assert raw.endswith(b"\n") and len(raw) <= 1024
    assert json.loads(raw) == {
        "v": 1,
        "report": "weekly-data-quality",
        "dataset": "orders",
        "week_start": "2026-11-02",
        "week_end_exclusive": "2026-11-09",
        "rows_total": 7,
        "missing_required": 2,
        "invalid_status": 1,
    }


@pytest.mark.parametrize(
    "row",
    [None, (), (1, 0), (True, 0, 0), (-1, 0, 0), (1, 2, 0), (1, 0, 2), (2**53, 0, 0)],
)
def test_invalid_or_unbounded_result_shapes_are_refused(row):
    selected = parameters(["--dataset", "orders", "--week-start", "2026-11-02"])
    with pytest.raises(ReportRefused):
        render(selected, row)
