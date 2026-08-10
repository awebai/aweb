# Pin-store multi-process gate

The real-machine gate for changes to pin-store persistence: several resident
channel processes contending on ONE shared `known_agents.yaml`, which is the
condition the unit suites cannot reproduce. Built for the channel 1.7.6 release
(`aweb-abdo`) to verify the CAS retry and the `last_seen` coalescing together.

    node scripts/e2e/pin-store-multiprocess-gate/battery.mjs

Needs `channel-core/dist` built (`cd channel-core && npm run build`) and `aw` on
PATH, or `AW_BIN` pointing at it. Output goes to a temp directory it prints;
override with `ABDO_ROOT`.

## What is real and what is not

Real: separate OS processes, one shared pin-store file, the real
`aw id pin-store compare-and-set` binary as the writer, the real trust,
coalescing and retry code from the built dist, real Ed25519 signatures.

Stubbed: the message source. **This gate measures CAS, coalescing and retry
mechanics only. No claim about live-server, registry or hosted delivery
behaviour comes out of it.** Say so in any evidence you produce from it.

## Two rules that are not optional

**Run the runner proof before you trust any arm.** A silent runner and a passing
arm produce the same output. `runArm` with one agent, then assert the trace
exists and contains `lock_acquired`. This is not ceremony: on its first use the
proof reported `lock_acquired` ABSENT, which reads exactly like "the fix is not
firing", and the cause was the harness rather than the code — see the trap below.
Without the proof, three arms would have run against a broken trace reader and
produced a false RED against correct code.

**The live-store digest brackets every arm.** `runArm` records the sha256 of
`~/.config/aw/known_agents.yaml` before and after and returns `isolationHeld`.
If it is false the arm is VOID — report it void, do not report its numbers.

Isolation is belt and braces on purpose, and **both belts are load-bearing here**:

- `pinStorePath` is passed explicitly by `agent.mjs`. `commitPinStore` prefers it
  and it becomes the `--path` argument the `aw` binary receives
  (`local_aw.ts`: `["id","pin-store","compare-and-set","--path", path]`), so it
  is operative in this harness, not decorative — it would save you even if the
  `HOME` override failed to propagate.
- `HOME` is overridden per process. This is the one that moves the *default*,
  since `DEFAULT_PIN_STORE_PATH` is built from `homedir()` and no channel host
  ever sets `pinStorePath` in production. It moves the Go side too:
  `awconfig` derives the user state dir from `os.UserHomeDir()`, i.e. `$HOME`.

`AWEB_IDENTITY_HOME` looks like the isolation knob and is not — it governs
credentials only (see `aweb-abdp`).

## The trap: onTrace arity, and why it is SILENT

`onTrace` receives ONE `ChannelTraceEntry` object — `{ts, component, stage,
event_type}` plus, conditionally, `lane`, `message_id`, `conversation_id` and
`session_id` — not `(stage, event)`. The last two appear on chat-lane events, so
a reader who assumes the schema stops at six will meet undocumented fields.

Destructure it wrongly and every stage name renders as `[object Object]`, every
stage assertion silently fails to match, and the arms look like the fix is absent.

**The mechanism is what makes it silent, and it is deliberate:** `emitTrace`
wraps the `onTrace` call in `try {} catch {}` and swallows, commented
"Diagnostics must never change delivery behavior." That is correct design — a
broken tracer must not break delivery — and the cost is that a broken *consumer*
raises nothing at all. Any callback the channel invokes for diagnostics is in the
same family: the absence of an error is not evidence your handler ran correctly.
Assert on the *content* it produced, which is what the runner proof does.

## Reading traces

Under the semantics recorded in `aweb-abdo`:

- `lock_acquired` may fire up to **three** times per message under contention.
- `pin_commit_started` without `pin_commit_completed` means a **retry is coming**,
  not a dropped event.

So retries per message are `(count of lock_acquired) - 1`. Anyone who learned the
older single-fire reading will misread these.

## An arm that cannot fail is decoration

Every arm here was validated by removing the fix it measures, rebuilding the
dist, and re-running it. Do the same for any arm you add, and record both numbers:

    coalescing removed   arm B2: 18 messages -> 33 commit attempts (with: 3)
    retry bound 3 -> 1   arm C:  1 wake and 4 "remains pending" (with: 5 and 0)

Restore with `git checkout --` and prove the restore with a symbol count before
re-baselining; `cp` prompts on overwrite in some shells and can leave the
mutation applied while reporting success.

## Arms

| arm | shape | carries |
|---|---|---|
| A | 3 processes, stale baseline, simultaneous | contention resolves, all wakes present |
| C | 5 processes, stale baseline, simultaneous | forced conflict resolves silently |
| B2 | 3 processes, 6 messages at 10s | **the coalescing-suppression claim** |
| B1 | 3 processes, 3 messages at 84s | healthy-mode claims ONLY |

B1 is the production-shape control at the measured 84s median inter-arrival. At
that spacing every message falls outside the 60s window, so coalescing suppresses
nothing and the commit count tracks the message count. That is the correct
result, and it is why B1 must not be used to claim suppression — B2 alone carries
that.
