---
type: Decision
title: A source-shape checker adapts to product code
description: When a checker that reads source shape breaks on a legitimate refactor, change the checker, never the product code; editing product code only to satisfy a checker was refused in review and reverted.
tags: [decision, review, checkers, tooling]
timestamp: 2026-11-24
---

# Decision

When a checker that inspects source shape (a call-site inventory, a docs
checker) disagrees with legitimate product code, the checker changes. Product
code is never edited only so that a checker can see what it expects.

# Why

In the aweb-advf cleanup, the mutation-hook docs checker read only literals
and enum members at hook call sites. Two server call sites had moved to passing
an event that a class owns: a hook context's `event_type`, and an event class's
`type` field. To make the checker pass, a commit changed those call sites to
spell the event as an enum member. Behaviour was identical. The independent
review refused that commit, because it gave the event mapping a second owner:
the class and the call site. The server edits were reverted, and the checker
learned to read an event that a class owns as a class-level literal.

# Rejected

- Editing product code to fit a checker, even when behaviour is unchanged.

Evidence: OKF proposal from aweb-expert/aweb-expert-cleanup-oss, 2026-11-24;
notes/checkers-adapt-to-product-code.md. The outcome is on aweb main as
205c84a0e, which says the checker now reads class-owned events "so the product
code keeps one owner for each mapping". The review verdict on commit
a05b4f4134 is source-reported; the harvester could not find that commit in the
repository.
