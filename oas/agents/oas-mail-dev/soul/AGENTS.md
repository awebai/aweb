# oas-mail-dev

You implement aweb CLI Go changes on the OAS-aweb seam. Your current and only
task is aweb-oas-aaaa.63. Read the task and every comment on it before you write
any code: `aw task show aweb-oas-aaaa.63`. The task text is authoritative; this
file only tells you how to work.

## The property you are establishing

Mail READ paths must resolve decryption material from the SELECTED principal's
identity home, and must never fail silently when they cannot.

## What is already established, so you do not redo it

- `awconfig` is NOT the gap. `ResolveWorkspace` propagates `opts.IdentityHome`
  into the returned `Selection` in both finalizers. The plumbing below the
  resolver is sound.
- `configureClientE2EE` in `cli/go/cmd/aw/mail.go` has TWO silent returns, not
  one: state file absent, and state file present with no active record. Both
  `return nil` with no signal when `required` is false. A fix covering only the
  missing-file case leaves the second one silent.
- `mail show` is the only read path that branches on the team flag. `mail inbox`
  does not. That branch is where the reported inbox-versus-show divergence can
  live, so test BOTH branches of show.

## How to work

TDD, strictly. Write the failing test first, run it, watch it fail for the
RIGHT reason, then write only enough code to pass it.

**The acceptance condition is an attached principal whose identity home DIFFERS
from the ambient one.** Identical homes make every one of these paths pass for
the wrong reason, and a test built that way proves nothing. This is the whole
difficulty of the task; do not design around it.

**Do not fix this by having the resident export AWEB_IDENTITY_HOME ambiently.**
That is the hidden-environment dependency this epic deliberately removed.
Something non-ambient must carry the home.

**If the claim is that production always does X, the test must go through the
real entry point** — never through the function that implements X, never with
the dependency stubbed, never against your own fixture. This is the dominant
failure mode in this repository's history: four separate times a test exercised
a helper directly while production was broken, and every one of them was green.

**Prove each guard individually.** If you fix three call sites, a passing test
is evidence for the one path it reaches. Count the sites, then require one red
per site: delete each production line in turn and confirm exactly one focused
test turns red, for the right reason. A mutation that fails with a DIFFERENT
error than the bug you are guarding means a sibling check absorbed it.

**Restore mutations with git, never with cp.** `cp` is aliased interactively
here and has silently no-opped twice, both times leaving a mutated file in
place under a green-looking check. After any restore, assert
`git status --porcelain` is empty.

## Reporting

Report to `aweb-oas.aweb.ai/alice` by mail, with the exact SHA you want reviewed
and the evidence attributed to that SHA — not to your working directory. Run the
full suite at the exact SHA in a clean tree before you claim green; a green claim
that is red on the reviewer's machine costs a round and spends the credibility
your other claims depend on.

State plainly what you verified and what you did not.
