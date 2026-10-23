"""Records acceptance through the installed CLI and the real table browser.

Called by the disposable wakes stack, after its verified v2 installation.
The helpers execute aw in the existing two members' homes; no auth/grant doubles.
"""

import json
import threading
from concurrent.futures import ThreadPoolExecutor


def exercise_records(aw, run, root, schema):
    collection = "records-acceptance"
    title = "Synthetic discovery records"

    def tool(who, name, *, check=True, **arguments):
        args = []
        for key, value in arguments.items():
            encoded = json.dumps(value) if isinstance(value, (dict, list)) else str(value)
            args.extend(["--" + key, encoded])
        return aw(who, "folio", name, *args, check=check)

    def result(who, name, **arguments):
        return json.loads(tool(who, name, **arguments).stdout)

    defined = result("alice", "collection-define", collection_id=collection,
                     title=title, schema=schema, request_id="records-define")
    slug = defined["document_slug"]
    assert defined["collection_id"] == collection
    assert "table_url" not in defined

    def query(who="alice", **arguments):
        return result(who, "record-query", collection_id=collection, **arguments)

    def browser(expected):
        documents = result("bob", "list")
        entry = next(item for item in documents if item["slug"] == slug)
        assert entry["kind"] == "table"
        link = result("bob", "present", slug=slug)
        # Pass capability bytes on stdin, never in retained output or process argv.
        run(["node", str(root / "scripts/e2e/folio-records-browser.mjs")],
            input=json.dumps({"url": link["url"], "values": expected}))

    assert query()["records"] == []
    browser([])
    value = {"source_url": "https://example.test/research?topic=pages",
             "date": "2026-10-23", "finding": "Synthetic record acceptance",
             "why_relevant": "Verify the same row through signed tools and a table",
             "status": "read", "kind": "awareness"}
    added = result("alice", "record-add", collection_id=collection,
                   values=value, request_id="records-add")
    row = added["record"]
    assert row["value"] == value and row["rev"] == 1
    assert result("alice", "record-add", collection_id=collection,
                  values=value, request_id="records-add") == added

    updated = result("bob", "record-update", collection_id=collection,
                     record_id=row["id"], expected_rev=1, patch={"status": "follow-up"},
                     request_id="records-update")
    expected = {**value, "status": "follow-up"}
    assert updated["record"]["value"] == expected
    assert updated["record"]["rev"] == 2
    filtered = query(filter=[{"field": "status", "op": "eq", "value": "follow-up"},
                             {"field": "kind", "op": "eq", "value": "awareness"}])
    assert filtered["count"] == 1 and filtered["records"] == [updated["record"]]
    assert query(filter=[{"field": "status", "op": "eq", "value": "read"}])["count"] == 0

    barrier = threading.Barrier(2)

    def race(who):
        barrier.wait(timeout=10)
        return who, tool(who, "record-update", collection_id=collection,
                         record_id=row["id"], expected_rev=2, patch={"status": who},
                         request_id="records-race-" + who, check=False)

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(race, ["alice", "bob"]))
    successes = [(who, json.loads(out.stdout)) for who, out in outcomes if out.returncode == 0]
    failures = [out for _, out in outcomes if out.returncode != 0]
    assert len(successes) == len(failures) == 1, outcomes
    assert "revision_conflict" in failures[0].stderr, failures[0].stderr
    assert "HTTP 409" in failures[0].stderr, failures[0].stderr
    winner, committed = successes[0]
    final_value = {**expected, "status": winner}
    assert committed["record"]["rev"] == 3
    assert committed["record"]["value"] == final_value
    assert query("bob")["records"] == [committed["record"]]
    # The original receipt remains original even after later writes by peers.
    assert result("alice", "record-add", collection_id=collection,
                  values=value, request_id="records-add") == added
    second_value = {**value, "finding": "Second synthetic record", "status": "later"}
    second = result("bob", "record-add", collection_id=collection,
                    values=second_value, request_id="records-add-second")
    first_page = query(limit=1, sort=[{"field": "finding", "direction": "asc"}])
    assert first_page["count"] == 2 and first_page["next_cursor"]
    next_page = query(limit=1, sort=[{"field": "finding", "direction": "asc"}],
                      cursor=first_page["next_cursor"])
    assert next_page["count"] == 2 and next_page["next_cursor"] is None
    assert {record["id"] for record in first_page["records"] + next_page["records"]} == {
        row["id"], second["record"]["id"],
    }
    browser([final_value, second_value])
    print("PASS installed CLI define/add/retry/one-field update/filter and two-member CAS; same table in Chromium", flush=True)
    return {"collection_id": collection, "document_slug": slug}
