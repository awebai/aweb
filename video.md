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

Create `tests/test_aweb_mcp_proxy_auth.py` with two tests:

1. **Tampered headers, no Bearer** — sends tampered proxy headers
   without a Bearer token.  This currently returns 401 (but from the
   Bearer rejection path, not the proxy path — the behavior is
   coincidentally correct but for the wrong reason).

2. **Tampered headers + valid Bearer** — sends tampered proxy headers
   with a valid Bearer token.  This is the real bug: it currently
   returns **200** because proxy auth silently falls back to Bearer.
   After the fix it must return **401**.

Run the test — the second test should **fail**:

```bash
uv run pytest tests/test_aweb_mcp_proxy_auth.py -v
```

Expected output:
```
test_tampered_proxy_headers_rejected_without_bearer_fallback PASSED
test_tampered_proxy_headers_rejected_even_with_valid_bearer FAILED
  AssertionError: Expected 401 ..., got 200
```

### Step 3 — Fix the code (TDD green)

Edit `src/aweb/mcp/auth.py`.  The key change is in `__call__`: when
proxy headers are trusted, proxy auth failure must be terminal.  Only
fall through to Bearer when proxy mode is **not enabled**.

In `_resolve_proxy_auth`, the `except HTTPException: return None` on
line 95-96 must instead send a 401 response (matching how
`_resolve_bearer_auth` sends error responses).  Or, restructure
`__call__` so that when `_trust_aweb_proxy_headers()` is True, it only
tries proxy auth — never falls through to Bearer.

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
git add src/aweb/mcp/auth.py tests/test_aweb_mcp_proxy_auth.py
git commit -m "fix: reject tampered proxy headers in MCP auth instead of falling back to Bearer"
git push
bdh close aweb-bbc
bdh sync
```

## Re-recording

The prep commit adds the test file and video.md.  The fix commit adds
only the code change in `src/aweb/mcp/auth.py`.  To reset for another
take:

1. Find the prep commit (it has the test file but not the fix):
   ```bash
   git log --oneline -5
   # Look for "prep: add failing test for MCP proxy auth bug"
   ```
2. Reset to that commit:
   ```bash
   git reset --hard <prep-commit-sha>
   ```
3. Reopen the issue:
   ```bash
   bdh update aweb-bbc --status=open
   ```
4. Verify state is correct:
   ```bash
   git status                                        # clean
   uv run pytest tests/test_aweb_mcp_proxy_auth.py -v  # 1 pass, 1 FAIL
   bdh show aweb-bbc                                 # open
   ```
5. Start from "Step 1 — Claim the issue" above.
