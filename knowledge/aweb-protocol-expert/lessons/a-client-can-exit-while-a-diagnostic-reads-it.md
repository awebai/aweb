---
type: Lesson
title: A client can exit while a diagnostic reads it
description: A diagnostic that names the process on the other end of a connection in several separate reads must treat "the process exited between reads" as an expected outcome and say so; a test client that times out before the diagnostic answers makes the test measure machine load, not the code.
tags: [lesson, testing, egress, attribution, race]
timestamp: 2026-11-21
---

The test egress guard holds a denied CONNECT while it names the client in
three separate reads: the socket owner, then `ps`, then the `lsof` working
directory. Attribution takes 0.3-0.5 s on an idle Mac and seconds under load.
A client that gives up inside that window exits between two reads, and each
window gives a different wrong receipt.

Reproduced on 2026-11-21 with children that exit early under the guard on
aweb main d8d0bfa1e:

- exit after 0.05-0.1 s: "no process holds the connection";
- after 0.2-0.3 s: a `ValueError` from an empty `ps` line;
- between `ps` and `lsof`: `cwd=?`;
- 0.5 s and later: a correct receipt.

The guard's own attribution test used a child with a 2 s `urlopen` timeout. At
a Mac load around 150 one gate seat got `cwd=?` while the others passed, so
the test passed or failed with the load.

# Reading the symptom

A `?`, an empty field or a parse error from such a diagnostic is not a lookup
the platform lacks, and the test is not flaky. Compare the client's lifetime
with the diagnostic's latency first.

# How to apply

- Each per-process read raises a lookup error (`ProcessLookupError`) once the
  pid is gone. The receipt then says the process exited during attribution and
  keeps what was already read. "Unknown" or "unavailable" is reserved for a
  live process whose fact could not be read.
- A test client of the diagnostic waits for the diagnostic's answer, with a
  timeout equal to the run's, not a short timeout of its own.
- Test the exited path deterministically on a real child that has exited and
  been reaped, not by racing timing.

This applies to any guard or receipt that inspects the process at the other
end of a connection.

# Status and elimination route

The fix in the guard and its reaped-child test is commit d1999d5540, on a
review branch and not on main at d8d0bfa1e. The new test failed before the fix
and passes after it. The proposal reports the native suite passing 10 of 10
runs and the attribution test 20 of 20 repeats at load 66. The between-reads
paths are covered by the reaped-child test; they were not observed end to end.
Once the fix lands, the code carries the handling, and this lesson keeps the
reading of the symptom and the rule for test clients.

Related, about the lifetime of a process you own rather than one you observe:
[process helpers keep no idle tasks](/aweb-protocol-expert/lessons/process-helpers-keep-no-idle-tasks.md).

# Provenance

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-aw-tests-1,
2026-11-21; notes/a-client-can-exit-while-the-guard-reads-it.md. The harvester
verified that main's guard makes the three separate reads and that d1999d5540
is on a review branch, not on main.
