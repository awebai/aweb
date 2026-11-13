"""The round trip's throttle leg: which real AWID limiter window it fills,
and the changed act it resends."""

import base64
import json

from protected_round_trip import changed_act, did_key_window


def test_the_window_is_the_limiters_own_key_for_the_front_address_now():
    seed = did_key_window(now=120.5, client_ip="172.31.0.250")
    assert seed == {"key": "aweb:rl:did_key:172.31.0.250:2", "limit": 60, "ttl": 62, "wait": 0.0, "remaining": 59.5}


def test_too_little_left_of_the_window_waits_for_the_next_one():
    # A short remainder would make a hint the SDK's own 5 s budget absorbs.
    seed = did_key_window(now=175.0, client_ip="172.31.0.250")
    assert seed == {"key": "aweb:rl:did_key:172.31.0.250:3", "limit": 60, "ttl": 62, "wait": 5.0, "remaining": 60.0}


def test_a_changed_act_differs_from_the_saved_one_only_in_its_role():
    body = {"subject": {"principal": "p", "role": "reader", "app_id": "a"}, "operation_id": "op"}
    record = {"operation_id": "op", "body": base64.b64encode(json.dumps(body).encode()).decode(), "profile": "x"}
    changed = changed_act(record, "reader-other")
    assert {k: v for k, v in changed.items() if k != "body"} == {k: v for k, v in record.items() if k != "body"}
    resent = json.loads(base64.b64decode(changed["body"]))
    assert resent == {**body, "subject": {**body["subject"], "role": "reader-other"}}
    assert base64.b64decode(changed["body"]) == json.dumps(resent, separators=(",", ":"), sort_keys=True).encode()
