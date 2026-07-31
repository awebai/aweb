# Market-entry wedge research

Status: working market hypothesis, 2026-07-30.

This document refines the
[company-agent platform thesis](company-agent-platform-thesis.md) into a
testable go-to-market recommendation.

The [canonical aweb product SOT](aweb-product-sot.md) still governs the current
initial users, communication wedge, priorities, and public positioning. This
research proposes a company-layer discovery motion alongside that path. It does
not authorize a product or website pivot. Adopting the recommendation as the
company's primary market entry would require an explicit, reviewed SOT change
after the founder decides and the tests below produce evidence.

## Recommendation to test

Do not test company-layer demand by selling
`identity + coordination + OAS`. Use those components to deliver an urgent
outcome:

> Rescue one agent workflow that already matters but is too fragile, expensive
> to review, or forgetful to trust in production.

The design-partner prospect should already have a worker that sometimes
produces useful work. The intervention first applies the simplest effective
controls. It adds a second agent only when that agent can own distinct evidence,
tools, authority, and an independent asynchronous lifecycle.

The offer to test is a founder-delivered, paid **Production Rescue Sprint**:

> In two weeks, turn one fragile agent workflow into a supervised, measurable,
> learning production unit without replacing the customer's existing stack.

This is not an observability product, a general automation consultancy, or a
promise of autonomous employees. It is a narrow intervention between a
successful demo and dependable recurring work.

## Why this market exists now

Executive demand is real, but useful deployment lags the demand:

- PwC surveyed 4,454 CEOs and found that 42% named keeping pace with technology
  and AI as their largest concern. Only 12% reported both cost and revenue
  benefits from AI, while 56% reported neither
  ([PwC 2026 CEO survey](https://www.pwc.com/gx/en/news-room/press-releases/2026/pwc-2026-global-ceo-survey.html)).
- McKinsey found that 62% of organizations were at least experimenting with AI
  agents and 23% were scaling one somewhere, but no individual function had
  more than 10% of respondents reporting scaled agent use
  ([McKinsey State of AI 2025](https://www.mckinsey.com/capabilities/quantumblack/our-insights/the-state-of-ai)).
- IBM's study of 306 practitioners and 20 production case studies found that
  68% of production agents run at most ten steps before human intervention.
  Reliability was the leading development problem; practitioners primarily
  addressed it through systems-level design rather than model adaptation
  ([Measuring Agents in Production](https://research.ibm.com/publications/measuring-agents-in-production)).
- In a 2026 survey of 130 engineers, among respondents building AI in
  production, 69% reported not using a third-party agent framework. Among the
  reported framework gaps were failures made harder to trace and poor support
  for long-running state
  ([Inngest production benchmark](https://www.inngest.com/blog/ai-in-production-report-2026)).

These sources and the field reports below suggest a pattern to test:

1. a leader needs an AI result;
2. someone gets a narrow workflow to work sometimes;
3. the workflow encounters messy data, changing context, exceptions, and
   consequential actions;
4. human review, repeated correction, and recovery erase the promised gain;
5. the pilot stalls because nobody owns the production operating system.

The research establishes the transition problem, not a budget for aweb. The
paid-sprint test must establish whether a reachable segment will buy help and
whether the work repeats.

## Candidate wedge

The wedge is not every CEO who feels AI pressure. That group is too broad and
contains too much innovation theater.

The first discovery cohort should be narrower: **agentic operators in
founder-led B2B service firms** who already use more than one agent runtime for
recurring, source-grounded client or opportunity research. This includes
consultancies, agencies, and contractors preparing evidence packs, bid/no-bid
briefs, or proposals.

- the firm is roughly 5-100 people and can approve a small paid sprint without
  enterprise procurement;
- a founder, operations lead, or delivery lead owns the result;
- the worker already uses Codex, Claude Code, n8n, a custom script, or a similar
  tool on real research or proposal preparation;
- a second tool, model, or human currently verifies claims or turns the research
  into a client-facing artifact;
- transfer between those responsibilities is manual, loses context, fails
  across sessions, or cannot identify which execution produced a result;
- unsupported claims or review time have already damaged or erased value;
- can provide a human owner and production examples;
- the work happens frequently enough to establish a baseline during the sprint.

This buyer has already crossed the education barrier. We do not have to
persuade them that agents might matter. We have to make one existing result
repeatable.

The initial workflow envelope is:

- it produces an inspectable research brief, evidence pack, bid assessment, or
  proposal draft;
- authoritative source material exists and can travel with the handoff;
- a human already reviews the output and can explain acceptance;
- mistakes are detectable before an irreversible external action;
- independent work must cross a runtime, machine, session, or provider boundary
  and survive one participant being unavailable or replaced.

Do not start with autonomous customer conversations, money movement, legal
notices, destructive system access, or a workflow whose owner cannot describe
what good looks like.

There are visible examples of this buyer now:

- A construction-company owner reported abandoning Hermes and OpenClaw as too
  fragile, then rebuilding company research and future operations around
  Codex, Claude Code, Git, Markdown handoffs, logs, and independent
  verification. They explicitly asked how to carry context across sessions and
  operate multiple agents on real company work
  ([public request](https://www.reddit.com/r/AI_Agents/comments/1tamfgh/what_actually_works_for_business_ai_agents/)).
- A Codex user described a repo-based continuity workaround that succeeds for
  one agent but breaks when several agents trample one another's unfinished
  work. They asked how to hand off work and bring new agents up to speed
  ([public request](https://www.reddit.com/r/codex/comments/1v852jd/how_do_you_guys_handoff_work_between_agents/)).
- An operator with agents serving more than 40 customers reported that document
  extraction, deterministic routing, and human-reviewed drafting held up,
  while consequential judgment and irreversible action did not. Customers
  wanted supervised autonomy and recoverability
  ([production report](https://www.reddit.com/r/AI_Agents/comments/1sa6ol9/agents_replacing_workflows_agents_replacing/)).
- Another business owner reported that a research agent's fabricated claims
  damaged customer credibility and that verification could consume more time
  than drafting saved
  ([production discussion](https://www.reddit.com/r/AI_Agents/comments/1tc7pxq/anyone_actually_running_ai_agents_in_production/)).

These reports are anecdotal and some public agent communities contain
promotion disguised as experience. They are useful as recruiting signals, not
market-size proof. The larger surveys establish the production gap; direct
customer interviews must establish willingness to pay.

This cohort is a deliberately chosen discovery wedge, not yet a validated
repeatable market. The first batch must reveal whether the same job, failure,
buyer, and acquisition channel recur. Selling unrelated rescue work would
validate a consultancy, not a product wedge.

## When a production pair is justified

The customer keeps the existing worker. Before adding another agent, compare
three designs:

1. the current worker and human review;
2. the worker plus deterministic schema, citation, policy, or evaluation
   checks and a human gate;
3. the same controls plus a second durable responsibility.

Choose the third only when the supervisor has a genuine independent job:

| Responsibility | Job |
| --- | --- |
| Worker | Performs the bounded research, extraction, or drafting that already creates value |
| Supervisor | Checks evidence and policy, detects exceptions, requests missing context, routes decisions to a human, and records why work passed or stopped |

The supervisor is not a second model asked "is this good?" It needs:

- evidence or tools not reducible to the worker's own narrative;
- explicit acceptance and stop conditions;
- authority to return, block, or escalate work, but not silently widen scope;
- an asynchronous lifecycle that makes durable handoff, offline delivery, and
  instance attribution necessary;
- an append-only record of the handoff, evidence, decision, and responsible
  instance;
- a reviewed path from repeated correction to a changed instruction, skill,
  evaluation, or policy.

Independent context or a different model is not independent evidence.
Correlated model errors remain possible. The second agent must beat the simpler
baseline on accepted output, review time, or recovery; otherwise remove it.

Humans retain approval for external, financial, legal, security-sensitive, and
hard-to-reverse actions. The sprint should automate preparation and cheap
verification before it attempts autonomy.

## What the customer buys

The sprint starts from one workflow and one baseline. It includes:

1. Map the workflow, sources of truth, side effects, current failure classes,
   and human review cost.
2. Bound the worker's responsibility and make its output inspectable.
3. Implement the deterministic checks, acceptance contract, stop rules, and
   human escalation that should exist regardless of agent count.
4. Add and connect a supervisor only if the distinct-job and asynchronous-
   lifecycle tests above are satisfied.
5. Run production examples with a human owner.
6. Turn at least one real correction into reviewed, versioned operating
   knowledge and demonstrate that a later run reuses it.
7. Report a before/after result and leave the customer with a recoverable
   operating system, not a demo.

Measure only workflow outcomes:

- useful cases completed without rework;
- human review minutes per accepted case;
- unsupported or incorrect claims reaching the reviewer;
- time from intake to an accepted output;
- appropriate versus unnecessary escalations;
- repeated failures after a correction was approved;
- operating cost per accepted result.

Traces, messages, and agent counts are diagnostic evidence, not value metrics.

The first three design partners should pay. The initial pricing hypothesis is
$2,500-$5,000 for the sprint, with a continuing fee offered only after a
measured improvement. Customer conversations may disprove that range.
Discounting may buy deep access and a public case study; free pilots do not
test demand.

## Where aweb and OAS fit

The answer to "do we start with ID/coordination plus OAS?" is:

> Yes as architecture; no as the thing the customer must understand or adopt.

### Aweb underneath

Aweb should provide:

- a durable address for each responsibility;
- reliable worker-to-supervisor handoff across runtimes and machines;
- durable delivery while one side is offline;
- verifiable sender and instance attribution;
- membership, delegation, revocation, and eventual succession;
- communication evidence that does not depend on one orchestrator's transcript.

To count as evidence for aweb rather than for a general reliability service, a
design-partner workflow must require an independently running sender and
receiver and at least two of:

- cross-runtime or cross-provider handoff;
- operation on different machines;
- delivery while a receiver is offline;
- continuity across session or instance replacement;
- attributable communication across an organizational boundary.

If a single-process queue or deterministic check solves the problem, solve it
simply or decline it as an aweb design-partner pilot.

This remains differentiated when the customer uses several vendors or crosses
an organizational boundary. It should not be pitched as a replacement for the
customer's identity provider.

Microsoft Entra now gives enterprise agents identities, sponsors, conditional
access, lifecycle control, and audit logs
([Microsoft Entra Agent ID](https://learn.microsoft.com/en-us/entra/agent-id/)).
Okta provides an agent registry, scoped access, token exchange, revocation, and
agent-to-agent authorization
([Okta for AI Agents](https://support.okta.com/help/s/product-hub/okta-for-AI-agents)).
A standalone enterprise "identity for agents" pitch would place aweb directly
against the installed identity control plane.

### OAS underneath

OAS should initially provide:

- durable definitions for the worker and supervisor responsibilities;
- explicit operating instructions and skills;
- instance/session separation;
- capture of corrections and incidents;
- human-reviewed promotion of durable learning;
- clean succession when an execution instance is replaced.

Do not require the customer's existing worker to be rewritten as an OAS agent.
Use OAS as a sidecar or delivery implementation until repeated customer
evidence reveals the smallest interface worth productizing.

This caution matters because OAS has no meaningful external adoption evidence,
and the organizational-agent platform is becoming a first-party category.
OpenAI Frontier already promises shared business context, agent execution,
learning from feedback, identity, permissions, and forward-deployed help to
large enterprises
([OpenAI Frontier](https://openai.com/index/introducing-openai-frontier/)).
Aweb cannot win by presenting a smaller checklist of the same abstractions.
The market hypothesis is that aweb can serve smaller, provider-independent
operators that Frontier and its global consulting motion are not designed to
serve economically. Interviews and paid delivery must validate that assumption.

## Why not the other entry points

| Entry | Urgency | Reachability | Current fit | Fast proof | Competitive room | Learning toward vision | Total / 30 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Discover through a narrow production rescue | 5 | 4 | 4 | 5 | 4 | 5 | **27** |
| Agentic engineering enablement | 4 | 5 | 5 | 5 | 2 | 4 | **25** |
| Build a new CEO/founder workflow | 4 | 3 | 3 | 3 | 3 | 5 | **21** |
| Vertical support or IT agent product | 5 | 2 | 2 | 4 | 1 | 4 | **18** |
| Orchestrator integration plugin | 2 | 3 | 5 | 2 | 2 | 3 | **17** |
| Horizontal OAS/company OS | 2 | 2 | 3 | 2 | 2 | 5 | **16** |
| Enterprise agent identity/governance | 5 | 1 | 2 | 2 | 1 | 4 | **15** |

Scores are directional judgment, not market data. Their purpose is to expose
the tradeoff.

### Agentic engineering is the fallback, not the first story

Coding-agent use is real. A study of tens of thousands of Microsoft engineers
associated command-line agent adoption with roughly 24% more merged pull
requests over four months
([Microsoft rollout study](https://arxiv.org/abs/2607.01418)).
The founder has deep credibility and aweb already runs this way.

It is nevertheless a crowded and rapidly platform-owned surface. AQ, Coder,
Lockstep, Memeri, and many others now sell isolated workspaces, shared context,
decisions, and cross-agent visibility. Codex, Claude Code, and GitHub are
absorbing more orchestration and skills themselves. Engineering should be the
first fallback and a rich source of design partners, not a return to "make a
team of coding agents."

### Integrations are distribution, not the product

An adapter or upstream pull request can be useful when a design partner already
uses that system. Priority should follow demonstrated production use:

1. Codex and Claude Code;
2. n8n or the customer's existing deterministic workflow system;
3. LangGraph, Temporal, Inngest, or another runtime named by a paying customer;
4. experimental orchestrators only when an actual operator requests them.

An integration that produces installs but no accepted workflow outcome repeats
the current activation problem.

### Do not begin with a blank company builder

Organization is learned from recurring responsibility, handoffs, exceptions,
and correction. Asking a new user to invent roles, prompts, reporting lines,
and operating rules before value reverses that sequence. The first organization
should appear because a real worker needs a real supervisor.

## Customer acquisition: find pain, not AI interest

For the first month of this discovery motion, do only the platform work needed
for direct recruiting and delivery. This does not reprioritize the canonical
communication roadmap unless the founder adopts the recommendation.

### Public lead pools

- Authors of the production and handoff requests linked above.
- Authors and commenters on concrete GitHub issues such as durable feedback
  routing in Hermes
  ([issue](https://github.com/NousResearch/hermes-agent/issues/3506)).
- Small automation agencies already delivering client workflows and hiring
  builders
  ([example](https://www.reddit.com/r/n8n/comments/1ts6l52/hiring_n8n_automation_builder_for_a_growing/)).
- Teams discussing production reliability in LangChain, n8n, Codex, Claude
  Code, and AI-agent communities.
- The founder's existing network of CEOs and CTOs, filtered for an existing
  workflow rather than general AI ambition.

The highest-signal immediate interview list from this research is:

| Public handle | Why contact them | Intended test |
| --- | --- | --- |
| `Select_Werewolf7453` | Construction-company owner who abandoned fragile platforms and is assembling Codex, Claude, Git, handoffs, and verification for company operations | Closest candidate profile; ask for the last failed research-to-artifact workflow |
| `HopefulReason7` | Business owner who shut down most internal agents after review and rework erased the gains | Strongest falsification interview; learn whether any workflow needed a distinct supervisor rather than simpler controls |
| `Infinite_Pride584` | Claims to operate agent workflows for more than 40 customers and reports demand for supervised autonomy | Potential agency channel; verify the claims and identify repeated client failure classes |
| `automation_experto` | Warned that agency edge cases accumulate after the demo and asked who owns mismatched client inputs | Experienced delivery interview; test whether the sprint removes expensive recurring support |
| `ToxicFlames` | Active Codex user whose multi-agent attempts lose context and collide in shared work | Engineering fallback design partner |
| `kshitijk4poor` | Opened Hermes's durable-feedback routing proposal and precisely separated memory, skills, product defects, and session detail | Expert interview or integration collaborator, not assumed buyer |

These are public pseudonyms, not qualified prospects. Claims must be verified,
and outreach should refer to the specific problem they chose to publish rather
than treating a forum post as consent to a sales sequence.

### The outreach

Do not lead with aweb, OAS, cryptographic identity, or multi-agent teams. Lead
with the failure the person described:

> You wrote that your agent loses context / needs more review than it saves /
> becomes unsafe when it acts. We have built around the same problem in our own
> company. We are testing a two-week paid sprint that keeps your current worker,
> adds the simplest reliable checks and, only where justified, a durable
> independent supervisor. Approved corrections become durable operating
> knowledge. We measure review time and accepted output, not agent activity.
> Would you show us one workflow that is failing this way?

The first call should reconstruct one recent failure. It should not demo a
dashboard.

### Thirty-day test

1. Contact 30 founder-led B2B service operators who have publicly described a
   relevant research, proposal, review, or handoff failure or are one warm
   introduction away.
2. Hold at least 15 problem interviews using the customer's last failed case.
3. Qualify only workflows that exercise aweb's independent communication
   boundary and ask ten qualified prospects to buy the fixed-scope sprint.
4. Close three paid discovery partners.
5. Complete at least two sprints in the same workflow cohort on the existing
   stack with minimal new platform work.
6. Publish one honest case study with baseline, intervention, result, and
   remaining human work.

The test fails if fewer than three of ten qualified prospects will pay, if the
customer cannot name a recurring workflow and baseline, or if review and
integration work cannot be reduced enough to create a visible gain. It also
fails as a wedge if at least two paid customers do not share the same job,
failure pattern, buyer, and acquisition channel.

## What to productize after the sprints

Do not decide the final product from the architecture. Look for repeated manual
work across the first five same-cohort deployments.

If the pair pattern repeats, the candidate first product boundary is not
`aw team`. It is closer to `aw pair`, `aw supervise`, or an equivalent API:

- register a durable worker and supervisor;
- define a typed handoff and acceptance contract;
- attach evidence and stop reasons;
- route an escalation to a human owner;
- preserve work across runtime replacement;
- propose a correction for review;
- apply a versioned learning and prove that a later run used it.

For a validated pair product, the hosted dashboard should then show, in order:

1. work waiting for a human decision;
2. accepted, returned, blocked, and escalated cases;
3. evidence and responsibility for each decision;
4. corrections proposed, approved, applied, and rolled back;
5. workflow outcome and review-cost trends;
6. identities, instances, and delivery health as diagnostic detail.

That surface answers "can I trust this workflow and is it getting better?"
An agent org chart or chat transcript does not.

## Expansion path

If validated, the wedge reaches the company-layer vision through demonstrated
need:

```text
one useful but fragile worker
  -> one accountable production pair
  -> several pairs with shared human owners
  -> reviewed learning shared across responsibilities
  -> durable company agents that can delegate across functions
  -> cross-company trust and communication
```

Each step should be earned by repeated use. The first pair proves
organization. Several pairs create the need for company policy and shared
learning. Cross-company messages become valuable only after durable
participants exist on both sides.

## Falsification and strategic guardrails

Abandon or revise this wedge if:

- prospects enjoy discussing agents but will not expose a failed workflow;
- the same result is cheaper with a deterministic check inside the existing
  automation;
- a second agent adds review theater rather than independent evidence;
- most improvement comes from one-off consulting that does not repeat across
  customers;
- customers value tracing or identity but not lower review cost or better
  accepted output;
- the customer would obtain the same result by enabling a native feature in
  their existing platform.

If the research-to-artifact cohort does not repeat but engineering examples do,
run a separate agentic-engineering cohort rather than mixing the evidence. If
one narrower business workflow repeats strongly across several customers,
verticalize around that outcome. Do not retreat to a horizontal framework
merely because the outcome work is harder.
