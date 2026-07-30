# Recovered probes — the `.py.recovered` suffix is load-bearing

Five files here end in `.py.recovered` rather than `.py`. **That is a guard, not a
naming convention.** Renaming any of them back to `.py` puts it into
`check-server-locked-suite` on the next run.

They were written by subagents of an audit workflow, executed against this suite,
deleted, and recovered from their authoring transcripts. They are preserved as
evidence for open defects. They are not part of the suite and must not become part
of it by accident.

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
