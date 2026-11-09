"""A single synthetic-lab weekly report; no caller-supplied SQL or destination."""

import json
import os
import re
import signal
import sys
from dataclasses import dataclass
from datetime import date, datetime, time, timedelta

MAX_BYTES = 1024
MAX_COUNT = 2**53 - 1
DEADLINE_SECONDS = 10

# This is intentionally one reviewed statement against one synthetic table.
# Only bind values vary. The account also has only CREATE SESSION and READ.
QUERY = """
SELECT COUNT(*),
       COALESCE(SUM(CASE WHEN required_value IS NULL THEN 1 ELSE 0 END), 0),
       COALESCE(SUM(CASE WHEN status IS NULL OR status NOT IN ('ready', 'rejected')
                         THEN 1 ELSE 0 END), 0)
  FROM LAB_OWNER.REPORT_EVENTS
 WHERE dataset_id = :dataset
   AND observed_at >= :week_start
   AND observed_at < :week_end
 FETCH FIRST 1 ROW ONLY
"""


class ReportRefused(ValueError):
    def __init__(self, code="report_parameters_invalid"):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class Parameters:
    dataset: str
    start: date
    end: date


def parameters(argv):
    if len(argv) != 4 or argv[0] != "--dataset" or argv[2] != "--week-start":
        raise ReportRefused()
    dataset, text = argv[1], argv[3]
    if dataset not in {"orders", "inventory"} or not re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}", text
    ):
        raise ReportRefused()
    try:
        start = date.fromisoformat(text)
        end = start + timedelta(days=7)
    except (ValueError, OverflowError):
        raise ReportRefused() from None
    if start.weekday() != 0:
        raise ReportRefused()
    return Parameters(dataset, start, end)


def render(selected, row):
    if (
        not isinstance(row, (tuple, list))
        or len(row) != 3
        or any(type(value) is not int or not 0 <= value <= MAX_COUNT for value in row)
        or row[1] > row[0]
        or row[2] > row[0]
    ):
        raise ReportRefused("report_output_refused")
    document = {
        "v": 1,
        "report": "weekly-data-quality",
        "dataset": selected.dataset,
        "week_start": selected.start.isoformat(),
        "week_end_exclusive": selected.end.isoformat(),
        "rows_total": row[0],
        "missing_required": row[1],
        "invalid_status": row[2],
    }
    raw = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if len(raw) > MAX_BYTES:
        raise ReportRefused("report_output_refused")
    return raw


def query(selected, username, password):
    import oracledb

    if username != "LAB_REPORT" or not password or len(password) > 1024 or "\0" in password:
        raise ReportRefused("report_configuration_invalid")
    target = oracledb.ConnectParams(
        host="10.203.0.2",
        port=1521,
        service_name="FREEPDB1",
        tcp_connect_timeout=3,
        retry_count=0,
    )
    with oracledb.connect(user=username, password=password, params=target) as connection:
        connection.call_timeout = 2000
        connection.autocommit = False
        with connection.cursor() as cursor:
            cursor.arraysize = cursor.prefetchrows = 2
            cursor.execute("SET TRANSACTION READ ONLY")
            cursor.execute(
                QUERY,
                dataset=selected.dataset,
                week_start=datetime.combine(selected.start, time()),
                week_end=datetime.combine(selected.end, time()),
            )
            rows = cursor.fetchmany(2)
            if len(rows) != 1:
                raise ReportRefused("report_output_refused")
            return render(selected, rows[0])


def _expired(signum, frame):
    raise ReportRefused("report_deadline_exceeded")


def main():
    try:
        selected = parameters(sys.argv[1:])
        username = os.environ.pop("ORACLE_REPORT_USER", "")
        password = os.environ.pop("ORACLE_REPORT_PASSWORD", "")
        signal.signal(signal.SIGALRM, _expired)
        signal.alarm(DEADLINE_SECONDS)
        try:
            raw = query(selected, username, password)
        finally:
            signal.alarm(0)
        sys.stdout.buffer.write(raw)
        return 0
    except ReportRefused as refused:
        sys.stderr.write(refused.code + "\n")
        return 2 if refused.code == "report_parameters_invalid" else 1
    except Exception:
        # Driver exceptions can carry SQL, connection details or input values.
        sys.stderr.write("report_unavailable\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
