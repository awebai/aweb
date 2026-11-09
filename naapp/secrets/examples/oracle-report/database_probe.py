"""Test-only real database permission control, run inside the isolated lab network."""

import json
import sys

import oracledb


def probe():
    password = json.loads(sys.stdin.buffer.read(4096))["password"]
    with (
        oracledb.connect(
            user="LAB_REPORT",
            password=password,
            params=oracledb.ConnectParams(
                host="10.203.0.2",
                port=1521,
                service_name="FREEPDB1",
                tcp_connect_timeout=3,
                retry_count=0,
            ),
        ) as connection,
        connection.cursor() as cursor,
    ):
        connection.call_timeout = 2000
        # No SET TRANSACTION READ ONLY: account permissions must stop real writes.
        cursor.execute("SELECT COUNT(*) FROM LAB_OWNER.REPORT_EVENTS")
        before = cursor.fetchone()[0]
        errors = []
        for sql in (
            "UPDATE LAB_OWNER.REPORT_EVENTS SET status='rejected' WHERE dataset_id='orders'",
            "DELETE FROM LAB_OWNER.REPORT_EVENTS WHERE dataset_id='orders'",
            "INSERT INTO LAB_OWNER.REPORT_EVENTS VALUES ('orders', DATE '2026-11-02', 'synthetic', 'ready')",
            "CREATE TABLE LAB_REPORT.WRITE_PROBE (value NUMBER)",
            "SELECT * FROM LAB_OWNER.REPORT_EVENTS FOR UPDATE",
        ):
            try:
                cursor.execute(sql)
            except oracledb.DatabaseError as error:
                errors.append(error.args[0].code)
            else:
                errors.append(0)
            connection.rollback()
        cursor.execute("SELECT COUNT(*) FROM LAB_OWNER.REPORT_EVENTS")
        after = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM USER_TABLES WHERE TABLE_NAME='WRITE_PROBE'")
        created = cursor.fetchone()[0]
        print(json.dumps({"before": before, "after": after, "errors": errors, "created": created}))


if __name__ == "__main__":
    try:
        probe()
    except Exception:
        print("database permission probe failed", file=sys.stderr)
        raise SystemExit(1) from None
