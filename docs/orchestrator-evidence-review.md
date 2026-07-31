# Evidence review: Gas Town, Paperclip, and agent fleets

Status: research snapshot, 2026-07-30.

This document evaluates whether two prominent agent orchestrators have shown
that they improve productivity or can reliably operate fleets of agents. It is
an evidence review, not a permanent verdict on either project.

## Bottom line

Gas Town and Paperclip are real, substantial systems. They should not be
dismissed as demos.

However, their strongest public evidence establishes different, narrower
claims:

- Gas Town can produce extraordinary coding throughput for an expert operator
  who has well-specified, independently verifiable work and accepts high cost,
  risk, and operational complexity. There are identifiable professionals using
  it for real work, not only demos.
- Paperclip can provision, invoke, schedule, observe, budget, and govern
  heterogeneous agent processes through a common task-oriented control plane.
  There are repeat operators, but little public evidence ties their fleets to
  independently verifiable business or engineering outcomes.

The public evidence does **not** yet establish either of these stronger claims:

- a large agent fleet creates more valuable, correct, maintainable output per
  unit of human attention than one strong agent or a small parallel set;
- a general business can be run autonomously through an agent org chart;
- the additional agents, hierarchy, heartbeats, and supervision layers produce
  a net productivity gain after review, repair, token cost, and operational
  failures are counted.

The right current posture for aweb is therefore:

1. Do not mention Gas Town or Paperclip in the homepage's product definition.
2. Do not build aweb around the assumption that large agent fleets will work.
3. Treat integrations as bounded experiments and distribution channels.
4. Build for the smaller, already-real case: a few independently running agent
   processes that need durable reachability, handoff, wake-up, and reply.

For the immediate operating decision: **do not replace the team currently
building aweb with Gas Town.** Test Gas Town on a bounded, test-rich,
non-critical epic if there is a genuine throughput bottleneck. A wholesale
replacement would exchange a tuned, working coordination system for an
experimental system optimized for a different kind of work.

## What counts as productivity evidence

Launching agents, generating patches, creating tasks, accumulating repository
stars, and producing an impressive activity feed are measures of activity or
throughput. They are not sufficient measures of productivity.

A convincing comparison should include:

- useful outcomes completed;
- correctness and escaped defects;
- rework and rejected output;
- human specification, supervision, review, and recovery time;
- elapsed time;
- model and infrastructure cost;
- maintainability over subsequent changes;
- performance against a simpler baseline.

No public controlled evaluation located for this review measures Gas Town or
Paperclip on those terms.

## Gas Town

### What is demonstrated

Gas Town is a functioning multi-agent coding workspace with persistent work
state, worktrees, task graphs, messaging, watchdogs, and a merge queue. Its
[repository](https://github.com/gastownhall/gastown) makes a concrete claim that
it can coordinate 20–30 agents.

The creator reports sustained productive use at that scale in
[Welcome to Gas Town](https://steve-yegge.medium.com/welcome-to-gas-town-4f25ee16dd04).
That report is meaningful founder dogfood, but it is not a controlled
comparison. The same article says the system is complicated, expensive, fully
vibe-coded, intended for an unusually advanced operator, and was the fourth
orchestrator iteration that year.

There is also credible independent evidence of a narrower gain. In a detailed
[one-week field report](https://tenzinwangdhen.com/posts/gastown-good-bad-ugly/),
an experienced multi-agent user assigned seven concrete tasks before dinner and
returned to six merged pull requests and one blocked task. That is a real
throughput result. It supports the value of:

- independent worktrees;
- explicit, durable tasks;
- parallel execution;
- a single merge path;
- mail and escalation;
- replaceable worker sessions.

These are valuable mechanisms even if the complete Gas Town product is not the
right abstraction.

The strongest attributable real-work case located for this review is DoltHub
CEO Tim Sehn's
[week building DoltLite](https://www.dolthub.com/blog/2026-03-24-a-week-in-gas-town/).
DoltLite is a non-toy attempt to replace SQLite's B-tree storage with a
Dolt-style Prolly Tree and add version-control operations. The resulting
release added roughly 18,000 lines of C. On the first day, Gas Town worked for
about four hours with minimal prompting and reached a state where SQLite's
87,000 acceptance tests passed. By the end of the week Sehn had released a
"mostly working" 0.1.0 and concluded that Gas Town had been critical to the
implementation speed.

This is real work by an identifiable domain expert, with a public repository,
tests, a release, and a stated cost. It is the clearest evidence that Gas Town
can create a step-change in prototype throughput.

The boundary conditions are equally important. Sehn attributes the result to
two existing reference implementations, a clean interface, a large acceptance
suite, a relatively small codebase, his eight years of domain expertise, and a
near-unlimited model budget. It cost $3,000 for the week. Once the project
reached coupled performance debugging, he stopped using most Gas Town
mechanisms: the work became direct interaction between him and the Mayor, with
Beads retained as the ledger. He still found broken indexes near the deadline
and described the result as "mostly working," not production-ready.

There is also evidence of retained professional use. Datopian CTO Anuar Ustayev
described
[several months using Gas Town as his primary orchestration
tool](https://www.datopian.com/blog/multi-agent-ai-workflow-infrastructure).
He reported spending 80% of his time planning and supervising and 20%
debugging, while no longer writing code himself. Yet his recommendation to a
new user was not to adopt Gas Town wholesale: start with the coding tool already
subscribed to and a few agents. Datopian's account says the bottleneck moved
from implementation to defining good work, and that poorly specified work can
cost more to unwind than to restart.

A
[launch-thread participant](https://news.ycombinator.com/item?id=46458936)
supplied another concrete but shorter case. After about 15 hours, the operator
reported that Gas Town improved the UI of a Postgres time-series project, fixed
remote Docker failures with some nudging, and opened and resolved roughly 50
Beads. They considered it useful for a complex, repetitive epic while still
calling the system early and inference-heavy. This is credible practitioner
evidence, but not a longitudinal productivity comparison.

### What is not demonstrated

The same independent report did not result in adoption. It describes broken
mail and maintenance processes, continued manual prodding, weak observability,
141 orphaned Claude processes, high resource use, and poor fit for ambiguous or
iterative work. The author kept the task ledger and parallel-work ideas but
abandoned the full system.

Gas Town explicitly optimizes for throughput and tolerance of lost work. That
can be rational for low-risk, highly decomposable work, but it is not equivalent
to optimizing for correct shipped product. Its economics also depend on
abundant model capacity and on a human who can continuously generate good,
independent work items.

The product's rapid succession is additional caution, not proof of failure. The
creator wrote at launch that Gas Town itself might not last twelve months. Four
months later, [Gas City became the official new
direction](https://steve-yegge.medium.com/welcome-to-gas-city-57f564bb3607),
described as a ground-up decomposition of Gas Town's complex, hard-wired team
shape into composable primitives. This validates some underlying mechanisms
while weakening the case for treating the original product shape as settled.

### Gas Town verdict

Gas Town appears to be a **real throughput enhancer for a narrow operating
regime**:

- the operator was already productive with many manually managed agents;
- the work can be decomposed into clear, independently verifiable tickets;
- completion can be judged by tests or a quick pull-request review;
- speed is worth additional cost and cleanup;
- the operator accepts broad runtime permissions and occasional loss.

There is no public evidence that it is a general productivity enhancer for
ordinary developers or for complex, ambiguous product development. Most users
should not be expected to invest enough in its concepts and operating discipline
to reach the creator's results.

### Should Gas Town replace the current aweb team?

No.

The current aweb workflow has already paid the setup cost that Gas Town asks a
new operator to pay. It has evolved project-specific roles and instructions,
durable mail and chat, claims and locks, isolated worktrees, explicit review,
repository authority rules, cross-repository escalation, and human product
judgment. Those are not incidental mechanics. They encode what has been learned
while building identity and communication infrastructure where subtle authority
or lifecycle mistakes matter.

Gas Town's most distinctive operating doctrine is also a poor fit for that
work. Its speed benefit assumes that the operator does not read all generated
code and instead relies on specifications, tests, and cheap replacement of bad
work. Aweb currently needs:

- ambiguous product discovery, not only execution against a settled spec;
- protocol, identity, security, and lifecycle correctness;
- careful independent review;
- coordinated changes across OSS and SaaS repositories;
- durable project understanding across changes.

Those are precisely the conditions in which parallelism stops helping in the
best Gas Town reports. Replacing the current team would likely preserve agent
cost while losing accumulated operating knowledge and adding a new
orchestration system to debug.

The sensible experiment is narrower:

1. Select one self-contained, non-critical epic with a stable interface and
   strong tests.
2. Freeze the same acceptance criteria for the current aweb team and a Gas Town
   run.
3. Measure elapsed time, total model cost, human minutes spent specifying,
   supervising, reviewing, and recovering, first-pass acceptance, rework, and
   defects.
4. Keep the existing team as the authority and reviewer.
5. Adopt only the mechanisms that produce a clear net gain.

If Gas Town wins that test, it has earned a role as a burst execution engine.
It has not earned control of product direction or wholesale replacement of the
team.

## Paperclip

### What is demonstrated

Paperclip is a large, actively developed control plane. Its
[product contract](https://github.com/paperclipai/paperclip/blob/master/doc/PRODUCT.md)
and
[implementation specification](https://github.com/paperclipai/paperclip/blob/master/doc/SPEC-implementation.md)
define real mechanisms for:

- agent adapters and heartbeat invocation;
- task checkout and hierarchical work;
- org structure and company boundaries;
- budgets and approvals;
- run history, workspaces, and recovery;
- plugins and external runtimes.

The project is visibly dogfooded with AI coding tools. For example,
[a large design-system change](https://github.com/paperclipai/paperclip/pull/9134)
records Claude and Codex assistance, deterministic codemods, extensive tests,
and human screenshot review. This is evidence that disciplined agent-assisted
development can produce substantial changes. It is not evidence that an
autonomous fleet produced or safely approved the change: the pull request
explicitly records human review and multiple quality gates.

Paperclip therefore has credible value as a task, invocation, and observability
layer. An operator with existing agents may prefer one place to see their state,
cost, work, and approvals.

There is also evidence of actual repeat operation:

- one operator reported a self-hosted, two-company, eight-agent factory on a
  Mac Mini;
- another reported fourteen agents "in production" and had optimized away the
  roughly 90% of heartbeats in which no work was available;
- another documented five weeks operating a single CEO agent;
- public discussions contain reports of ten to twenty-eight configured agents
  and multiple companies.

These reports establish that Paperclip is installed, retained, and used to
invoke agents. They do not by themselves establish what useful outcomes those
agents produced, whether the fleet beat a simpler workflow, or how much operator
attention it consumed.

### What operators say after trying it

The public comments are polarized, but a consistent pattern emerges.

Positive operators in a
[discussion explicitly asking whether Paperclip is
useful](https://www.reddit.com/r/aisolobusinesses/comments/1s9gfma/is_paperclip_ai_actually_useful_or_just_another/)
like the dashboard, centralized task state, agent-specific roles, and the
feeling of control compared with several opaque terminal sessions. One user who
built a seventeen-agent SaaS organization said the value appeared only after
extensive configuration and summarized the lesson as: the tool is not magic;
the Markdown instructions and skills make or break it. Another user reported
ten agents over roughly three months but also said a separate, more expensive
project-manager agent was needed to alleviate setup and team-management
problems.

Critical operators report:

- getting more done by working with one agent directly;
- agents following the corporate metaphor into make-work, such as inventing
  human hiring processes instead of completing the requested task;
- heavy ticket proliferation and manual comments needed to close parent tasks;
- drift into random tangents;
- large amounts of planning and governance activity that look productive in
  the dashboard without moving the actual goal;
- substantial effort stripping and rewriting the default configuration.

The strongest reports are reproducible issue reports rather than anonymous
reviews. A
[two-company, eight-agent operator](https://github.com/paperclipai/paperclip/issues/3819)
documented agents silently appearing healthy while doing no work; two incidents
in 24 hours required manual database intervention. A
[five-week, one-agent operator](https://github.com/paperclipai/paperclip/issues/5544)
found that 40% of 27 system-generated issues were meta-issues, producing a
recursive babysitting loop in which the agent audited its own stalls instead of
working. A
[fourteen-agent operator](https://github.com/paperclipai/paperclip/discussions/2744)
reported that about 90% of scheduled heartbeats found no work and described
local changes needed to avoid paying tokens for them.

There are positive outcome claims, but they are not yet dependable evidence. A
named solo founder
[reported that a sixteen-agent Paperclip
pipeline](https://www.reddit.com/r/AI_Agents/comments/1v3ft8c/running_16_agents_for_a_one_person_business_while/)
sent 214 cold emails and autonomously found the first pilot customer. In a
[separate post the same
day](https://www.reddit.com/r/SaaS/comments/1v3f5ie/10_weeks_of_cold_email_for_a_b2b_tool_in_a_blue/),
the founder reported that those 214 cold emails produced zero demos and that
the real pipeline came from three warm contacts, including the founder's
employer. The underlying company and workflow are real, but the conflicting
attribution means this case should not be counted as proof that the Paperclip
fleet produced the customer outcome.

Even if the stronger version of that account were fully verified, it would
validate a narrow pipeline, not Paperclip's autonomous-company thesis. The
agents had fixed functions in one funnel—research, enrichment, draft
preparation, quality checking, and CRM updates. The operator described moving
important rules from prompts into hard API gates, manually reviewed outbound
email, handled calls and the demo, and remained the product and commercial
decision-maker. That is a useful multi-step automation system with LLM workers.
It is far short of a fleet that chooses strategy, coordinates general work, and
runs a company.

The fairest synthesis of operator comments is:

> Paperclip can be a useful cockpit for an operator willing to engineer the
> organization. Out of the box it often turns agent activity into management
> activity, and the operator still supplies the real operating system through
> prompts, skills, gates, and intervention.

### Fleet claims exceed the acceptance contract

The public story speaks about autonomous companies and teams of twenty or more
agents. The actual V1 acceptance criteria in the implementation specification
are much narrower. They require that a company can run **at least one**
heartbeat-enabled agent and that the control-plane mechanics—checkout,
permissions, budgets, dashboard counts, and audit records—work.

That is a sensible software release gate. It does not validate fleet
productivity.

Likewise, the
[companies catalogue](https://github.com/paperclipai/companies) includes
packages with 28, 49, 54, or 167 named agents. The catalogue describes these as
importable configuration, prompts, and skills. Agent count in a template is not
evidence that those agents ran concurrently, collaborated successfully, or
produced a useful outcome.

### Public failure evidence

Paperclip's issue tracker contains credible reports from real operation:

- [timer heartbeats could resume agents in an empty fallback
  workspace](https://github.com/paperclipai/paperclip/issues/1844), causing
  silent stalls after restarts and requiring manual wake-up;
- [an operator could not reliably stop an in-flight
  agent](https://github.com/paperclipai/paperclip/issues/2224), while duplicate
  processes continued unauthorized browser actions;
- its public repository currently shows thousands of open issues and pull
  requests, which is evidence of extraordinary generation and contribution
  throughput but also a large review and integration burden.

There is also a concrete repository-hygiene warning. The upstream
[AGENTS.md](https://github.com/paperclipai/paperclip/blob/master/AGENTS.md)
currently contains a section that declares the repository to be a particular
contributor's fork and records that fork's local branch, port, and cleanup
instructions. This appears to have entered upstream as part of a much larger
[adapter contribution](https://github.com/paperclipai/paperclip/pull/8543). It
is not proof that Paperclip caused the mistake, but it is an observable example
of velocity outpacing review at the exact instruction surface used by future
agents.

These issues can be fixed, and rapid issue discovery is itself a sign of real
usage. Their relevance is that reliable process lifecycle, context delivery,
emergency stop, and review capacity are prerequisites for fleets, not secondary
polish.

### Paperclip verdict

Paperclip can plausibly **run a fleet mechanically** in the limited sense that
it can represent many agents, trigger them, assign work, and collect state.

There is not yet convincing public evidence that it can run a fleet
**productively and autonomously**. It does not solve the hardest parts merely by
providing an org chart:

- choosing valuable work;
- decomposing ambiguous goals;
- maintaining a correct shared world model;
- detecting confidently wrong output;
- resolving cross-agent inconsistency;
- verifying quality;
- controlling a failing process;
- deciding what deserves human attention.

Those responsibilities move into prompts, skills, external tools, tests, and
the operator. A highly customized Paperclip installation may work well because
its owner built those missing systems. That would validate Paperclip as a
control plane, but not the claim that a new user can create a fleet from a
template and obtain autonomous value.

The direct answer to "is anyone using it?" is therefore **yes**. The direct
answer to "is anyone publicly demonstrating that a Paperclip fleet runs a real
company or software team better than a skilled operator with a few agents?" is
**not yet**.

## Broader evidence about multi-agent systems

The skepticism is consistent with current controlled research.

A 2026
[Nature Machine Intelligence study](https://www.nature.com/articles/s42256-026-01268-y)
matched prompts, tools, and compute across single-agent and four multi-agent
architectures over 260 configurations and six agentic benchmarks. It found:

- results ranged from large gains to severe degradation depending on the task;
- all tested multi-agent architectures slightly underperformed the single-agent
  baseline on SWE-bench Verified;
- tool-heavy and sequential work suffered coordination overhead;
- independent agents amplified errors far more than centrally verified teams;
- stronger single-agent baselines reduced the expected benefit of adding agents.

This does not show that all multi-agent systems fail. It shows that agent count
is not a scaling law and that task shape, verification, and communication cost
determine the outcome.

[TeamBench](https://teambench.github.io/) similarly reports that the full
planner/executor/verifier team beats solo performance for some models but loses
to a simpler condition for others. Role separation is useful only when the task
actually needs the roles and the model can coordinate them.

On general workplace autonomy, the updated
[TheAgentCompany](https://arxiv.org/abs/2412.14161) evaluation reports a best
full-completion rate of 30.3% across well-scoped tasks in a simulated software
company. This benchmark is not a Paperclip test, but it bounds what an
orchestrator can obtain from the underlying agents: scheduling weak execution
does not make it reliable execution.

Finally, a
[survey of seven experienced coding-agent engineers](https://blog.kilo.ai/p/how-7-kilo-code-engineers-run-up)
found that most actively supervise two to four foreground agents. Larger counts
are primarily background agents doing narrow, low-to-medium complexity tasks
whose pull requests are cheap to accept or reject later. This is consistent
with the strongest Gas Town evidence.

The April 2026
[Thoughtworks Technology Radar entry on coding-agent
swarms](https://www.thoughtworks.com/radar/techniques/coding-agent-swarms)
reaches the same operating conclusion and assigns the technique "Caution."
Thoughtworks notes that the prominent successes had detailed specifications
and, in the compiler case, comprehensive tests. It says those conditions are
not representative of typical product development, where requirements are less
defined and verification is harder, and concludes that swarms remain costly
and far from mature.

## Implications for aweb

### Do not sell the fleet

Aweb should not say that it enables autonomous companies, agent swarms, or
twenty-agent development. Those claims inherit an unproven premise and put aweb
in competition with orchestration products on their most speculative ground.

The homepage should not name Paperclip or Gas Town. The product remains:

> Durable identity, inboxes, and wake-up events for independently running
> agents.

That statement is useful with two agents. It does not require belief in a
fleet.

### Design for the observed operating regime

The credible near-term pattern is:

- one to three foreground agents receiving active human attention;
- several narrow background workers;
- durable tasks and externalized state;
- explicit review or verification before integration;
- processes that stop and restart;
- a need to notify the right agent when input, review, or a reply arrives.

Aweb should help those processes communicate across lifecycle and runtime
boundaries. Examples should show a research agent handing evidence to a coding
agent, a background worker waking a reviewer, or two sessions resuming a thread
after restart—not an artificial corporate org chart.

### Treat integrations as experiments

A Paperclip or Gas City adapter can still be valuable. It may:

- expose aweb to operators who already feel the communication problem;
- test address provisioning, durable delivery, replay, acknowledgement, and
  wake contracts against a foreign lifecycle;
- solve a specific cross-instance or cross-system boundary the orchestrator
  does not own.

But the integration should be small, external, and evidence-seeking. It should
not determine aweb's homepage, resource model, or roadmap.

The integration is promising only if an external operator:

1. has an existing recurring workflow before aweb arrives;
2. installs without founder intervention;
3. completes a real round trip including offline delivery and wake-up;
4. keeps the integration enabled after the novelty period;
5. uses it repeatedly for valuable work;
6. reports less manual relay or recovery effort.

If that does not happen, the result is technical compatibility, not product
validation.

## What would change this conclusion

The assessment should be revised when one of these systems publishes or enables
independent reproduction of:

- a four-week or longer usage cohort with retention and recurring completed
  work;
- a comparison against strong single-agent and small-parallel baselines;
- outcomes per human hour, not tokens, commits, or agent count;
- accepted versus rejected output and post-merge defect rates;
- total model, review, recovery, and infrastructure cost;
- an externally operated fleet completing a meaningful long-horizon project
  without its creator continuously tuning the system.

Until then, the most defensible conclusion is:

> The useful infrastructure is real. The fleet productivity story is not yet
> proven.
