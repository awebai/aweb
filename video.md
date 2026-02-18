# Video Prep: TDD Bug Fix with BeadHub

## What the video shows

Live TDD fix of **aweb-bbc**: "MCP proxy auth silently falls back to
Bearer on tampered headers."  The workflow goes from claiming the issue
to closing it, using `bdh` throughout.

## The bug

In `src/aweb/mcp/auth.py`, `_resolve_proxy_auth` catches the
`HTTPException` raised by `_parse_internal_auth_context` on bad/tampered
proxy headers and returns `None` — which makes `__call__` silently fall
through to Bearer token auth.  The REST layer (`src/aweb/auth.py:370-378`)
hard-fails in the same scenario: if proxy headers are trusted and
`_parse_internal_auth_context` returns `None`, it raises 401 immediately
instead of trying Bearer.

The fix: when `AWEB_TRUST_PROXY_HEADERS=1` and proxy header validation
fails (HTTPException), MCP should reject the request with 401, not fall
back to Bearer.

## Pre-flight checklist

Run these steps before recording.  Every step matters — if the repo
isn't in the right state the fix won't demonstrate cleanly.

### 1. Reset to clean starting point

```bash
cd /Users/juanre/prj/beadhub-all/aweb
git stash                      # if needed
git checkout main
git pull
git status                     # must be clean
```

### 2. Verify tests pass before touching anything

```bash
uv run pytest --tb=short -q    # all green
uv run mypy src/ tests/        # 0 errors
```

### 3. Verify the bug exists

The silent fallback is at `src/aweb/mcp/auth.py:93-96`:

```python
try:
    internal = _parse_internal_auth_context(request)
except HTTPException:
    return None          # <-- BUG: falls through to Bearer
```

Compare to the REST hard-fail at `src/aweb/auth.py:370-378`:

```python
if _trust_aweb_proxy_headers():
    internal = _parse_internal_auth_context(request)
    if internal is None:
        raise HTTPException(status_code=401, ...)
    return internal["project_id"]
```

### 4. Confirm bdh issue is ready

```bash
bdh show aweb-bbc              # should be open, P2
```

## Recording workflow

### Step 1 — Claim the issue

```bash
bdh update aweb-bbc --status=in_progress
```

### Step 2 — Write a failing test (TDD red)

Create a test in `tests/test_aweb_mcp_auth.py` that:

1. Starts an app with `AWEB_TRUST_PROXY_HEADERS=1` and an
   `AWEB_INTERNAL_AUTH_SECRET`.
2. Sends a request to an MCP endpoint with a **tampered** proxy header
   (wrong HMAC signature) and **no** Bearer token.
3. Asserts the response is **401**, not a fallback success.

Also test the complementary case: tampered proxy header **with** a valid
Bearer token should still be 401 (proxy mode must not fall back).

Run the test — it should **fail** (the request currently falls through
to Bearer or returns a different error).

```bash
uv run pytest tests/test_aweb_mcp_auth.py -v
```

### Step 3 — Fix the code (TDD green)

Edit `src/aweb/mcp/auth.py` `_resolve_proxy_auth` to re-raise (or
return a 401 response) when the HTTPException is caught, instead of
returning None.  Also handle the case where `_parse_internal_auth_context`
returns `None` (headers present but empty/invalid) — that should also
reject, not fall back.

The key change in `__call__`: when proxy headers are trusted, proxy auth
failure must be terminal.  Only fall through to Bearer when proxy mode
is **not enabled**.

### Step 4 — Run all tests

```bash
uv run pytest --tb=short -q        # all green including new test
uv run mypy src/ tests/             # 0 errors
uv run black --check src/ tests/
uv run isort --check-only src/ tests/
uv run ruff check src/ tests/
```

### Step 5 — Commit and close

```bash
git add src/aweb/mcp/auth.py tests/test_aweb_mcp_auth.py
git commit -m "fix: reject tampered proxy headers in MCP auth instead of falling back to Bearer"
git push
bdh close aweb-bbc
bdh sync
```

## Re-recording

To re-record from scratch:

1. `git log --oneline -5` to find the commit before the fix.
2. `git reset --soft HEAD~1` to undo the fix commit (keeps files staged).
3. `git restore --staged . && git checkout .` to discard all changes.
4. `bdh update aweb-bbc --status=open` to reopen the issue.
5. Verify: `git status` clean, `bdh show aweb-bbc` open, test file gone.
6. Start from "Recording workflow" above.
