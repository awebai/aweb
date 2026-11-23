"""This suite's test databases are refused when the run names no Postgres server."""

from awid_service.testing import check_suite_refuses_an_unnamed_server


def test_an_unnamed_database_server_is_refused(request, tmp_path) -> None:
    check_suite_refuses_an_unnamed_server(request, tmp_path)
