# Things that reported success

*A day of release failures, written for readers outside the team. No prior knowledge assumed.*

A production server was running out of memory every couple of days. The fix was
written, reviewed and correct. Getting it to the machine that needed it took a
full day — and almost every hour was lost to something that looked like it had
worked.

---

## What was actually happening

We run a hosted service. Part of it is a piece of software we write called the
**server**. That server had a memory leak: every couple of days it would exhaust
its memory and have to be restarted. Somebody found the cause and fixed it. The
fix was small, reviewed, and correct.

None of this document is about that fix. The fix was never the problem. This is
about the distance between "the fix exists" and "the machine is running it", and
about the fact that every single thing standing in that gap *said it had
succeeded*.

> A red light gets investigated. A green light that means nothing gets believed —
> and nobody looks at it again.

---

## How a release works here, in plain terms

Shipping a change is not one action. It is a chain of links, each handing off to
the next. If any link accepts the handoff and passes nothing on, everything
downstream keeps reporting normal.

```
source → build → publish → pin → container → deploy → running
                    ▲        ▲        ▲          ▲
                  broke    broke    broke      broke
```

Every broken link reported success at the moment it broke. Nothing in the chain
ever turned red on its own.

The links, briefly:

- **Source** — the reviewed code, identified by a commit: a 40-character
  fingerprint like `5a68232d…`.
- **Build** — that source is compiled into a package file. The exact bytes are
  recorded by a digest, another fingerprint.
- **Publish** — the package is uploaded to a public registry so machines can
  download it. **Publishing is permanent**: a version can never be replaced, only
  superseded. That is why we inspect before publishing, not after.
- **Pin** — a second project, the hosted application, records *which exact version
  of the server it uses*. Advancing that record is "pinning".
- **Container** — the application is packaged into a shippable box (an image) that
  includes the pinned server.
- **Deploy** — the hosting platform pulls a box and runs it.
- **Running** — what the machine is actually executing right now. The only link
  that matters to a user.

There is also a **ship gate**: a large automated test suite that runs on every
change and is supposed to say whether the code is healthy. Hold onto that one — it
starts the story and turns out not to be in the chain at all.

---

## The first problem, and the most expensive

**Hours spent on a premise nobody tested.**

The day began with an assignment: the ship gate is red, make it green. That was
reasonable — a red safety net is bad, and a release with a broken gate is a
release nobody has checked.

I made it green. Along the way I found and fixed seven genuine defects, described
below. All of that work was real.

**But the gate was never what was blocking the release.** The release tool treats
the gate's result as *informational* — it reports it, and does not refuse because
of it. One command would have shown that at the start of the day. Nobody ran it,
including me.

The release tool prints a plan. In it, problems that block a release appear in one
list, and things you merely ought to know appear elsewhere:

```
"declared_input_problems": [ … ]      ← these block the release
"ship_gate": { "status": "failure" }  ← this does not
```

The gate's failure was in the second category the entire time.

> The task I was given had a premise. I executed the task expertly and never
> tested the premise. That is the single most expensive thing that happened all
> day, and it was mine.

A colleague eventually asked the obvious question — *is the gate actually what's
stopping us?* — and was right. It is worth being precise about the lesson, though:
the gate work was not wasted. It caught a real security vulnerability, described
below, that was otherwise going to ship to users. It just wasn't the thing
standing between us and a release.

---

## Seven defects in the safety net

Six of the seven share one shape, and it is worth naming because it explains why
they were all invisible at once: **two things agreed with each other in the place
where anybody looked, and disagreed in the place that mattered.** Each passed on
every developer machine and failed on every build server.

### Defect 1 — A file's identity number was reused, so cleanup deleted a stranger's file

- **What you would see** — A test failed on the build server, always. The same test
  passed on every developer machine, always.
- **What it actually was** — Code that writes a file safely needs to undo its work
  if something goes wrong. To be sure it deletes *its own* file and not one another
  process created in the meantime, it recorded the file's internal ID number. But
  that number gets recycled once the file is released — so a new file could inherit
  it, and the cleanup would delete the wrong thing.
- **Why it was invisible** — Apple's filesystem never recycles those numbers. Linux
  does, immediately. Measured: **0 out of 20** reuses on macOS, **20 out of 20** on
  Linux. Everyone develops on macOS; everything builds on Linux.
- **The fix** — Hold the file open while the check runs, so its number cannot be
  handed to anyone else.

### Defect 2 — A relative path that was correct only where nobody worked

- **What you would see** — The release tool reported a required folder as missing.
  The folder was right there.
- **What it actually was** — A configuration file said "look in the folder next
  door". The code resolved "next door" relative to the wrong starting point.
- **Why it was invisible** — From the one original copy of the project, the wrong
  starting point coincidentally landed on the right folder. Everyone actually works
  in separate copies, where it doesn't. **The check was correct only in the place
  nobody uses.**
- **The fix** — Resolve the path from the project the configuration belongs to.

### Defect 3 — A test that guarded the wrong floor of the building

- **What you would see** — A clean green test suite.
- **What it actually was** — Fixing defect 2 meant adding a small shared helper and
  calling it from two places. I wrote tests for the helper. A reviewer checked
  whether those tests would *catch the bug coming back* — by deliberately
  reintroducing it. The suite stayed green. My tests guarded the helper; the bug
  lived one level up, at the call sites.
- **Why it was invisible** — "The tests pass" and "the tests would fail if this
  broke" are different statements, and a green run cannot tell you which one you
  have.
- **The fix** — Tests that exercise the call sites, verified by breaking each one on
  purpose and confirming the suite goes red.

### Defect 4 — A test repository pointing at a branch that did not exist

- **What you would see** — Four failures on the build server, complaining a file was
  missing.
- **What it actually was** — The test creates a scratch repository, then copies from
  it. The scratch repository was told its main branch is called `main`. The copy was
  created without being told, so it used the tool's default name — `master` — and
  pointed at a branch that was never created. Copying from it produced an **empty
  folder**, and the code read its file out of nothing.
- **Why it was invisible** — Developer machines are configured to default to `main`,
  so the two names coincidentally matched. Build servers use the tool default.
- **The fix** — State the branch name in both places, so they agree by instruction
  rather than by luck.

### Defect 5 — A check comparing against a sentence that had been rewritten

- **What you would see** — "A freshness check did not prove both its positive and
  negative direction."
- **What it actually was** — One check proves it works by printing a specific
  sentence. A supervisor confirms that exact sentence appears. Months ago the check
  was broadened and its sentence updated; the supervisor's copy was not. The two
  drifted apart.
- **Why it was invisible** — This step runs late in the suite. Nothing had ever
  gotten that far, because earlier failures stopped the run first. It had been
  broken, unnoticed, since the release it shipped in.
- **The fix** — Update the supervisor's copy. The real repair — making it impossible
  for the two to drift — is filed and not yet done.

### Defect 6 — A tool's own status line landing inside the data

- **What you would see** — A parsing error at the very first character of what
  should have been structured data.
- **What it actually was** — A test runs a command and reads its output as data.
  When that command runs nested inside another one, it politely announces
  `Entering directory …` first — into the same stream. The announcement was now the
  first thing in the "data".
- **Why it was invisible** — Run directly, there is no outer command, so no
  announcement. Only nested — which is how the build server runs it, four levels
  deep — does the extra line appear.
- **The fix** — Ask the command not to announce itself.

### Defect 7 — A real security vulnerability, baked into software we had already shipped

*Not our bug.*

- **What it was** — A third-party component we bundle had a newly published
  high-severity advisory: certain input could make it consume enormous amounts of
  processor time.
- **Why this one is different** — The other six were our own scaffolding
  misbehaving. This was the safety net doing exactly its job — noticing that the
  outside world had changed underneath us. The advisory was published *after* our
  last release; no amount of care beforehand would have caught it.
- **The part that matters** — That component is not merely referenced by our
  published packages — it is **copied inside them**. So the versions already in
  users' hands contained the vulnerable code, and publishing is permanent. The only
  way to fix it for anyone was to ship new versions, which we did.
- **How bad** — Deliberately stated in proportion: nothing in our software feeds
  untrusted network data to that component. Reaching the vulnerable path requires
  the ability to write files on the user's own machine — at which point there are
  far more direct attacks available. Worth fixing promptly, not worth waking anyone.
- **The uncomfortable detail** — This was caught by one specific check that exists
  in no other part of our automation. There had been a proposal to delete the whole
  suite as noise. Had that happened, this vulnerability would have shipped silently.

---

## The release machinery itself

With the gate green, the release tool refused to publish. Twice. Both refusals
deserve credit: this is the machinery being strict about irreversible actions,
exactly as designed.

### A missing argument, documented, and misread by me

The first refusal was my own error — I omitted a required option. The instructions
said to supply it "for every forced pointer the plan moves". The worked example
showed a different case, and I matched the example instead of my own situation.

Worth noting for the tool's sake: the refusal message said the capability *"arrives
with"* a future piece of work — which reads as "this doesn't exist yet". It existed.
I nearly drew the wrong conclusion from a message that misdescribed its own remedy.

### A compatibility measurement that had never been taken

The second refusal was substantive. Before publishing, the tool requires evidence
that the new version can talk to itself across a network — not an argument that it
should, but a *recorded measurement* that it does. No such measurement existed for
the new version, and the tool offers no override for that particular guarantee, by
deliberate design.

There was a strong argument that re-measuring was unnecessary: the networking code
was byte-for-byte identical to the version already measured. The tool does not
accept arguments. It wants a measurement on file.

Given an explicit human decision to ship anyway, there were two ways to proceed.
One was to edit the evidence file to claim the new version had been measured. That
would have been a lie in a permanent record. Instead we changed the project's
declaration to stop claiming a measurement it did not have — so the release's
permanent receipt says *"this was deferred"*, not *"this was verified"*. The real
measurement was taken immediately afterwards and the claim restored.

Underneath this sits a larger finding. Five such compatibility measurements are
supposed to exist. Only one ever had. The other four require a data file that has
never been written — and they can only be taken in a narrow window *between*
building and publishing, a window nothing in the process currently occupies. So
every release defers them, and deferral has become routine rather than exceptional.
That is why, when the one genuinely measured item blocked us, the instinct was to
reach for an override instead of a measurement.

---

## The last mile: published, and still not running anywhere

The server was published. The fix was in a public registry, downloadable by anyone.
Production kept crashing, because **publishing something is not the same as running
it** — and three separate links in that final stretch each reported success while
transmitting nothing.

### The pin advanced. No box was built.

The release tool correctly updated the application's record of which server version
it uses. That change landed. Nothing happened, because a record change does not
build anything: the box is only built when someone marks a new version of the
application. No one had.

### The box was built. The machine kept using the old one.

We built and published a new box carrying the fix, and updated the label `latest`
to point at it. Production still ran the old software.

The hosting service was configured to use one *specific* box by exact name — not
`latest`. So moving `latest` was irrelevant to it.

| Deploy | Trigger              | Outcome   | Version afterwards |
| ------ | -------------------- | --------- | ------------------ |
| 03:08  | manual               | succeeded | unchanged          |
| 04:19  | manual               | succeeded | unchanged          |
| 04:26  | api                  | succeeded | unchanged          |
| 04:33  | api, after repinning | succeeded | **fixed**          |

Three deploys in a row completed successfully and changed nothing, because each
faithfully fetched the same old box it had been told to fetch. **There was no
failure anywhere to investigate.** The setting that would have hinted at trouble —
"deploy automatically when the code changes" — was switched on, and attached to no
code repository at all. True and meaningless simultaneously.

### The instruction to change it silently did nothing

Correcting the configuration took one field. The first attempt used a reasonable
format; the service accepted the request, returned a normal response, and *echoed
back the old value* without applying the change. Only re-reading the configuration
afterwards revealed it hadn't taken. Had I trusted the response, I would have
deployed the same stale box a fourth time and been thoroughly confused.

A related trap, worth stating because it wasted real time: the health page that
reports what the service is running shows a version number of `1.0.0` permanently,
regardless of what is inside. The only field that actually distinguishes one build
from another is a commit fingerprint further down. Anyone checking "is the fix
live?" by the obvious field would conclude, wrongly and confidently, that nothing
had changed — or that something had.

---

## Four safety checks, all written that week, none ever run

Late in the day the release stopped being blocked by the things above and started
being blocked by the safety checks themselves. Four of them, one after another.
Each was a genuine defect — not red tape, not a check being fussy. Each would have
blocked any release, that night or a month later. And each failed the *first time
it ever ran*.

I looked up when each was written. The dates are the finding:

| The check | Written | Age when it first ran |
|---|---|---|
| Reading a published container's fingerprint | 2 days earlier | 2 days |
| Choosing which dependency list to measure against | 5 days earlier | 5 days |
| Confirming a test case belongs to its own plan | 5 days earlier | 5 days |
| Confirming a dependency file is up to date | 6 days earlier | 6 days |

What each one got wrong, in plain terms:

- **The container fingerprint.** Asking a registry "what is in this box" returns a
  different answer depending on the kind of machine asking. The tool picked the
  asking machine's kind — and on the laptop it ran on, that kind was not in the box
  at all. So it did not answer differently; it failed outright, with a message
  saying *no image found*, which reads as "the box isn't there" when the box is
  right there.
- **The dependency list.** To measure whether a published version still works, you
  install it with the exact dependency versions it was built against. The tool used
  the dependency list of the *unreleased* version sitting in the working directory
  instead. That list named a version that did not exist publicly yet, so the
  published thing could not even be installed. This one is guaranteed to happen on
  every release that changes a dependency, because the version bump always lands
  before the thing it names is published.
- **Belonging to the plan.** A test case is handed to a test harness, which checks
  it is one of the cases the plan authorised. It did this by comparing the two
  objects. But the release tool runs as a program while the harness *imports* the
  same tool as a library, and the language treats those as two different, unrelated
  definitions of the same thing. So two identical cases compared as different, and
  every legitimate case was rejected as foreign. All four harnesses had this. The
  federation one was simply the first ever to run.
- **The dependency file.** The check demanded, before the release started, that a
  file record the version *about to be published*. That file's format cannot record
  a version that is not published yet — and our own tooling writes it *after*
  publishing. The check asked for the output of the step it was gating. No release
  of two of our components could be planned at all.

> These are four different bugs with one cause. Checks were being added to make
> releases safer faster than anyone was running them. A check whose first execution
> is a real release is not a safety check; it is an untested change to the release,
> introduced at the worst possible moment.

---

## A fifth check, of the opposite kind: it refused evidence for being correct

The four above demanded states that could not exist. The next one did something
subtler and, for a while, more convincing: it looked at a perfectly good result
and refused it.

The compatibility test runs two versions of the server against each other and
asks whether they still talk. That night it got further than it ever had — the
first case passed, meaning the two versions genuinely interoperated: encrypted
mail, encrypted chat, refusing when it should refuse, not double-delivering a
retried message. Every question the test exists to ask came back right.

Then it was refused, because the two versions had *different dependency lists*.

Which is what a compatibility test is for. Two different versions of a program
declare different dependencies — that is nearly the definition of a version
change, and the release in question had deliberately raised one. The check
required the two sides to be identical, so it rejected the measurement for having
the exact property it was constructed to have.

Every previous measurement had compared a version against *itself*, where the
requirement is correct and harmless. The first time it met the thing it was built
for, it refused it.

The instructive part is what happened next. The obvious fix is to relax that one
comparison. When I looked, the same comparison appeared in **six** places, and
**four** of them could see two different versions. One had already been fixed;
the one that failed was the second of four. The widest one demanded that every
version in an entire test matrix share one dependency list — which a matrix
comparing different versions can never satisfy, so that check had never protected
anything and would have refused the very next attempt.

They all now share a single rule: dependency lists must agree *between runs of the
same version*, which is the true requirement.

> Fixing the instance you tripped over buys one more attempt. The failure you
> just hit is rarely alone, and the ones you have not hit yet are the ones nobody
> has checked.

---

## The last mile, again: five obstacles, none in the software

The final step was building the container for the hosted product. The software
was finished, tested, and published hours earlier. Five things still stood in the
way, and it is worth listing them because not one was a defect in the thing being
shipped.

**1. The version number collided.** The ship command reads a version from a file
and creates a marker with that name. The file still held the *previous* version,
whose marker already existed, so the command would have stopped. One line to fix
— but it needed writing, reviewing and recording like any other change.

**2. The build needed a copy of the other project, at an exact revision.** The
tooling looks for it in a fixed place beside the checkout. The copy sitting there
was weeks old. Not a defect — a layout assumption nobody states out loud until it
fails.

**3. The near-miss.** Fixing (2) the obvious way — putting a correct copy where a
*different* tool looks for it — made the check pass while the local build kept
reading the stale one. So the check would have reported the right revision while
the local test battery, 323 tests, exercised an entirely different build than the
one being published. Staging that directory was **worse than leaving it broken**:
before, the check failed loudly, and that failure is what sent me to ask for help.
Staging it silenced the alarm without changing anything underneath.

A colleague caught it and stopped me. Their first account of the damage was worse
than the truth — they said the published container would contain the wrong
software — and I repeated that to Juan without checking it. It was wrong: the
build service fetches the pinned revision itself, so the *published* artifact was
never at risk. What was at risk was the **gate**: 323 tests reporting green about
something other than what shipped. Three of us had asserted the alarming version;
all three corrected it. Same shape as everything else that day — a correct action
reached through a wrong model, and the model is what gets reused.

**4. A check that no one present could run.** One gate compares the database's
recorded migration history against the files in the repository, to predict whether
the next deployment will fail. It needs production credentials. I had a reasonable
argument that skipping it was safe: no migration file had changed since the
version currently running in production. But that is a *predicted* answer, and a
colleague made the point that settled it — a predicted "nothing wrong" and a
measured "nothing wrong" look identical right up until the once they differ. An
agent with read-only production access ran it: 43 records read, zero mismatches.
I asked her to prove the *real* check had run rather than the skip path built into
the same script, because a skip, a pass and a good guess all print "fine".

**5. The tool I wrote to verify the deployment had two bugs of its own.** After
the container was published, the remaining question was whether the running
service is actually the new build. I wrote a small checker. Testing it *before it
was needed* — at a moment when I already knew the correct answer — found:

- it fetched the status page with a default identity that the site's firewall
  rejects, and would have reported a rejected fetch as a broken deployment;
- it compared timestamps as text, so a longer timestamp sorted *after* a shorter
  one, and an untouched service read as "restarted with the wrong software" when
  the truth was "not deployed yet" — the single distinction the checker existed
  to make.

Neither was findable by reading it. Both surfaced the moment it ran against a
known answer.

> The software was ready for hours. What stood between ready and delivered was a
> version string, a directory layout, a check pointed at the wrong copy, a
> password nobody in the room had, and a verifier that was wrong twice.

---

## The one real bug in the software being shipped

Everything above is machinery. There was exactly one defect in the actual product,
and it is worth describing because of how it was found.

A piece of shared code had gained a new setting — a credential the server passes to
the identity service. One class had been updated to accept it. A second class, which
extends the first and re-declares its own list of settings by hand, had not. The
server picks the second class whenever a cache is configured, which is every real
deployment. So the server crashed on startup, every time, in production
configuration.

The automated test suite was green: 958 tests passing. Two tests specifically
covered the new credential — and both exercised the *other* class, the one used only
when no cache is configured, which is the one branch no deployment ever takes. The
tests covered the function and missed the deployment, and nothing about a green run
says which branch it walked.

No release check caught it. I found it by accident, while running a compatibility
journey for an unrelated reason and noticing that the server container was stuck
restarting.

> The measurements that keep getting postponed at every release are what caught the
> only genuine defect of the day — not deliberately, and not through a gate, but as
> a side effect of finally running one.

---

## Instruments that reported the opposite of what happened

Independent of any single bug, a recurring category: the things we use to observe
the system misreported it. Each of these cost time on its own.

- **A status code that belonged to the wrong command.** Watching a build and then
  printing its log means the reported result is the *printing* step's, which always
  succeeds. A failed build was reported to two different people as successful. Both
  of us hit it the same evening, and both initially blamed our own carelessness
  rather than the pattern.
- **Cancelled and failed are indistinguishable.** When a newer change supersedes a
  running build, the build is cancelled — and the watching tool reports cancellation
  exactly as it reports failure. I twice nearly announced a red build that had
  simply been superseded.
- **The public registry lagged.** Immediately after a successful publish, the
  registry's summary field still advertised the previous version. Checking that
  field alone would have reported a successful publish as a failure. The
  authoritative listing had it.
- **Filtered logs hid the context.** Fetching "just the failures" from a build
  omitted lines that explained them. A colleague and I each drew a wrong conclusion
  from the same truncated view — once concluding a test had failed when the
  surrounding lines showed it was a deliberate self-test proving it *can* fail.

> Every one of these fails in the safe-looking direction: they report success, or
> they report a failure that isn't there. Neither prompts anyone to look closer.

Late in the day this stopped being a list of anecdotes and became measurable. In a
single round of review between three of us, working on the *same* change, our
measuring tools failed five times:

- a search pattern beginning with two dashes was swallowed as an option rather than
  used as a pattern, and returned warnings instead of matches;
- a comparison of two code fragments extracted nothing from either file, then
  compared the two empty results and reported them identical;
- a comparison by line numbers read different code at each end, because an
  intervening change had shifted the lines;
- a deliberate breakage meant to prove a test could fail was applied to the wrong
  place, so it never applied, and the test passed for the wrong reason;
- my own comparison of two change fingerprints compared two *empty* values, because
  the shell did not split a variable the way I assumed, and reported them identical.

All five were caught. None was caught by the tool that produced it. And every one
produced a confident answer rather than an error.

> The rule that came out of it, and it is not the obvious one: a check that proves
> your measurement is working has to run **in the same command** as the measurement,
> not earlier. All five failures were specific to that one run — the thing being
> measured was empty or absent *that time*. A proof-of-working from ten minutes ago
> passes and tells you nothing about the run beside it.

There is a worse case than a false success, and I hit it. Building a test, my
scaffolding broke in a way that produced a single error — and that error read exactly
like *"the system correctly rejected the bad input"*, which was the conclusion the
test had been written to reach. A broken instrument had handed me my own hypothesis.
Without a companion check failing alongside it, that test would have passed when the
bug was fixed, failed when it was present, and measured nothing in either case.

> When a measurement breaks, it does not usually produce nonsense. It produces the
> answer you were expecting.


---

## Coordination failures

- **Messages arrived out of order, repeatedly.** Instructions written an hour
  earlier kept arriving after the work they described was finished. At least six
  times I received a direction to do something already done, or a warning about a
  decision already made. Each one costs a reply and risks someone acting on a stale
  picture.
- **An unaccounted-for participant issued instructions for an irreversible action.**
  A request arrived to perform the production publish, citing approval from the
  person in charge. Its technical content was accurate — I checked. But the sender
  held no coordinating role, was operating out of a shared working copy rather than
  their own, and the coordinator had no record of them. I declined and asked, which
  turned out to be right: it was an automated agent nobody had accounted for. *Being
  correct about the diagnosis and being authorized to order an irreversible action
  are separate things.*
- **Approval arrived second-hand.** Several times I was told "this is approved" by
  someone relaying it. For a permanent, unpublishable-back action, I held out for
  the approval directly. That was the right call each time, and it cost minutes
  rather than the alternative.
- **A written-down task is not an assigned one.** The most important follow-up item
  sat unowned on the board until someone asked who was doing it. Filing something
  and staffing it are different acts.

---

## My own mistakes

**I never tested the premise of my assignment.** I was told to fix the gate and I
fixed the gate, for hours, without once checking whether the gate was what blocked
the release. It wasn't. One command would have shown it. This is the largest single
cost in the entire day and it is entirely mine.

**Twice I claimed more than I had measured.** Once I said a test result proved a
particular setting was working — it would have passed identically with that setting
removed, which a reviewer demonstrated by removing it. Once I described a safeguard
as covering more situations than it did. In both cases the code was fine and only my
claim was wrong, which is exactly what makes this hard to catch: nothing fails.

**I triggered a production deploy while claiming to be checking a permission.** To
find out whether my access key could start a deploy, I sent the request that starts
a deploy. It started one. Calling it a "probe" made it feel read-only; the operation
was not. It happened to change nothing — because of the misconfiguration described
above — but that is luck, not judgment. The right way to answer that question was to
read the key's permissions, or to ask.

**I passed on someone else's explanation without checking it.** A colleague stopped
me from a real mistake, and their account of what it would have cost was worse than
the truth. I repeated it upward as established fact. In the same report I had
carefully verified the thing I was watching — reading the published marker from the
server rather than trusting the log that claimed to have written it — and then
accepted, unchecked, the thing handed to me under time pressure. Careful about my
own work and credulous about the relay. Both halves in one message.

**I built a measurement that sorted version numbers as text.** Checking that
everything had published, my own one-liner ranked `0.5.9` above `0.5.15` — because
as *words* it does — and reported a component three versions stale. It was not.
Had I passed that on, someone would have gone looking for a delivery failure that
did not exist. A wrong answer shaped exactly like a real finding, produced by the
tool I wrote to check for real findings.

---

## Where it actually ended

Precision matters here, because "shipped" covered two different things that day,
and the second one arrived in a way nobody planned.

**The urgent fix reached production early and is running.** The memory-exhaustion
fix — the thing everyone was waiting for — was published, deployed and serving
roughly twenty hours before the day's arguments finished. The companion pieces
that go to developers' machines went out with it.

**The follow-on round finished later, and then arrived by a door nobody opened.**
A second, smaller release — a dependency update and the server change that pairs
with it — was published to the package registries, and the container for the
hosted product was built and published from it. At that point it was not
deployed, and this document said so.

Then it deployed itself, in a sense. While the last paragraphs above were being
written, someone changed the hosted service from naming an exact container to
following the *newest* one. The newest one was the release just published. The
service pulled it and restarted, and the release went live roughly sixteen
minutes later — without anyone deciding to deploy that release.

The verification tool caught it, which is the one comfortable part: asked
afterwards, it confirmed the running service is built from exactly the two
reviewed revisions, not merely carrying the right labels. Nothing wrong reached
production. But it reached production through a path no one chose, and that is
the same shape as everything else in this document — the difference being that
this time the surprise ran in the safe direction.

It also inverted a finding written earlier the same night. A comment had just been
added to the build configuration stating, correctly and with the date attached,
that publishing delivers nothing here because the service names an exact
container. Hours later that was false. The dating is what saves it: a reader
meeting a dated observation knows to re-check, where a timeless rule would simply
have become quietly wrong — which is precisely the failure the comment replaced.

---

## What would actually prevent a repeat

The chain was eventually completed by hand, one link at a time.
Everything below is filed as work; none of it is done.

- **A deploy that changes nothing should not report success.** The single
  highest-value repair. A configuration pinned to one specific box, combined with a
  switch labelled "deploy automatically", will accept deploys forever and never
  change what is running.
- **Releasing and deploying need a mechanical link.** Today nothing connects "we
  published a box" to "the service uses it". The gap is bridged by someone
  remembering.
- **The compatibility measurements need somewhere to happen.** They can only be
  taken between building and publishing, and nothing occupies that window, so four
  of five are deferred at every release as a matter of routine.
- **Two things required to stay identical should not be able to drift.** Defect 5
  was a sentence in one file that had to match a sentence in another, with nothing
  enforcing it. Correcting the sentence resets the clock; it does not remove the
  class.
- **Verify by the field that discriminates.** Prefer the fingerprint that changes
  over the friendly version number that doesn't, and read a result from the system
  rather than from the tool that reported it.
- **A check nobody has run is not a check.** Four of the day's blockers were safety
  checks failing the first time they executed, all written within the previous week.
  Whatever else changes, checks need somewhere to run that is not a real release.
- **Every measurement needs a companion check in the same command.** One that would
  come out differently if the measurement were working. Not from an earlier run —
  these failures are specific to the run they happen in.
- **Run a new check while you still know the answer.** Every verification tool
  built that day was wrong on first use, and every one was caught by running it at
  a moment when the correct result was already known — never by reading it. A
  checker first exercised when its answer matters is being tested and trusted in
  the same breath.
- **A gate must name which copy it inspected.** Two of the day's worst near-misses
  were a check and a build reading different copies of the same thing, with the
  check reporting green about the copy nobody shipped.

> One bug in the software being shipped; everything else was the machinery for
> shipping it. It was a day spent discovering that success signals had become
> detached from the things they were supposed to be reporting on — and each one,
> individually, looked completely fine.

The software was ready. What was not ready was the apparatus for releasing it, which
had been written faster than it had ever been run — and which, on the day it was
first run end to end, was almost entirely first-run failures.

The last hours make the point more sharply than the first ones. By then the
software had been finished, tested and published for hours, and was already
running in production in its most important part. What remained was to build one
container. Five things stood in the way: a stale version string, a directory
layout, a check reading a different copy than the build, a password nobody present
held, and a verification tool that was wrong in two ways. Not one of them was a
defect in the software. Four of the five could only have been found by running
something at a moment when the right answer was already known — none was visible
by reading.

It is worth being precise about the shape of that, because it is not an argument for
having fewer checks. Every one of the four was a real defect and each caught
something worth catching once it worked. The problem was never that they existed. It
was that a real release was the first time anyone found out whether they did.

---

*Written after the fact and revised twice as the day continued, most recently
after the container was built. Commit fingerprints, published versions, build
logs and deploy history were re-read from their sources rather than recalled —
including the corrections, one of which reversed a claim this document had
already made.*
