# Recovered probes — the `.recovered` suffix is load-bearing

**Eight files across three components** carry a `.recovered` suffix. **That is a
guard, not a naming convention.** Renaming any of them back puts it into a release
gate on the next run — which gate depends on the component, see the table at the
end.

Five of them are here, and end in `.py.recovered` rather than `.py`; renaming
those puts them into `check-server-locked-suite`.

They were written by subagents of an audit workflow, executed against this suite,
deleted, and recovered from their authoring transcripts. They are preserved as
evidence for open defects.

**EIGHT files were recovered, not five, and they live in three components with
three different collection mechanisms.** This file used to say the recovered
probes "are not part of the suite" — that was true of the five here and false of
the two in `channel-core/test/`, which were unsuffixed and would have been run by
`make test-channel-core`. Fixed; the full set is listed below.

## What the guard rests on

`pytest` collects files matching `python_files`, which **defaults** to `test_*.py`.
`server/pyproject.toml` sets only `pythonpath`, so the default applies and these
five do not match it.

So the guard is "a config key that is absent stays absent". If anyone ever sets
`python_files` more broadly — `test_*` without the extension, for instance — all
five become collectible again, silently. The tracked-file check in
`scripts/pytest_tracked_collection.py` will **not** catch that: these files are
tracked, and tracked-ness is the only question it asks.

If you widen `python_files`, deal with these five first.

## Why each one cannot simply be un-renamed

| file | state today | what landing it requires |
|---|---|---|
| `test_probe_status_locks` | **FAILS** — reproduces `aweb-aavk` | land with the fix, or `xfail(strict=True)` |
| `test_probe_status_locks_control` | passes | lands beside its probe; the pair is what makes the result readable |
| `test_probe_hangon_wait` | **FAILS** — reproduces `aweb-aavr` | land with the fix, or `xfail(strict=True)` |
| `test_probe_hangon_drop` | passes, and **asserts the defect as expected behaviour** | must be *inverted* when `aweb-aavr` is fixed, not un-skipped. Also carries an unguarded wall-clock assertion, `assert elapsed > 3.0`, plus `asyncio.sleep(2)` — remove or exclude from the gate whichever way it lands |
| `test_probe_presence_key` | passes while asserting nothing about the question in its own docstring | its output was the artifact; `pytest` swallows stdout on success, so it needs `-s` to be worth running |

Two of the five are red by design. Landing them as ordinary tests reds the release
gate. One of them is a characterisation test: it encodes the bug as the
expectation, so landing it unchanged converts a reproduction into a guard
protecting the defect.

`xfail(strict=True)` is the ruled route for the two that fail — strict, so that
fixing the defect makes the test fail loudly as an unexpected pass and forces the
marker's removal. A plain `xfail` leaves a permanently-excused failure nobody
revisits.

## The full recovered set — eight files, three mechanisms

| file | guard | why it is inert |
|---|---|---|
| `server/tests/test_probe_*.py.recovered` (5) | `.py.recovered` | pytest's `python_files` defaults to `test_*.py` |
| `cli/go/awid/zz_probe_divergence_test.go.recovered` | `.go.recovered` | Go compiles test files only from `_test.go`. **A different mechanism** — it does not depend on any config key, and it would not be restored by fixing pytest's. It also does not compile against main: it calls `resolver.ResolveIdentity`, which does not exist |
| `channel-core/test/zz_probe_*.test.ts.recovered` (2) | `.test.ts.recovered` | vitest's **default** include, `**/*.test.ts` — `channel-core` has no `vitest.config.*`, so the default applies and `"test": "vitest run"` would otherwise collect them |

### The two TypeScript probes must never land as running tests

They are the reproduction for `aweb-aavh`, and in the ATTACK case they assert the
**current, vulnerable** behaviour:

```
expect(result.status).toBe("verified");   // resolution failed → pin check skipped
```

That is a characterisation test. Landing it as a live test would make the release
gate assert that the vulnerability exists, and **fixing `aweb-aavh` would turn the
gate red**. They must be inverted when that defect is fixed, not un-suffixed.

Same hazard as `test_probe_hangon_drop` above, in a second language.

