from aweb.claims import _claim_focus_task_ref


def test_claim_focus_prefers_apex_task_ref():
    assert _claim_focus_task_ref("demo-123", "demo-1") == "demo-1"


def test_claim_focus_falls_back_to_claimed_task_ref():
    assert _claim_focus_task_ref("demo-123", None) == "demo-123"
    assert _claim_focus_task_ref("demo-123", "") == "demo-123"
