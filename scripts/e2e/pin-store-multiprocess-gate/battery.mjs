import { runArm } from "./orchestrate.mjs";
import { writeFile, mkdtemp } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
const root = process.env.ABDO_ROOT || await mkdtemp(join(tmpdir(), "pin-store-gate-"));
console.log("output root:", root);

function analyse(r) {
  const perAgent = r.results.map((res) => {
    if (!res) return null;
    const byMsg = new Map();
    for (const s of res.stages) {
      if (!s.messageID) continue;
      if (!byMsg.has(s.messageID)) byMsg.set(s.messageID, []);
      byMsg.get(s.messageID).push(s);
    }
    let locks = 0, started = 0, completed = 0, maxGapMs = 0, latencies = [];
    for (const [, ss] of byMsg) {
      locks += ss.filter((s) => s.stage === "lock_acquired").length;
      started += ss.filter((s) => s.stage === "pin_commit_started").length;
      completed += ss.filter((s) => s.stage === "pin_commit_completed").length;
      const done = ss.find((s) => s.stage === "harness_message_done");
      if (done) latencies.push(done.ms);
      const times = ss.map((s) => s.at).sort((a, b) => a - b);
      for (let i = 1; i < times.length; i++) maxGapMs = Math.max(maxGapMs, times[i] - times[i - 1]);
    }
    return {
      wakes: res.wakes.length,
      messages: byMsg.size,
      lockAcquired: locks,
      commitStarted: started,
      commitCompleted: completed,
      retries: locks - byMsg.size,           // new semantics: up to 3 locks per message
      pendingWarnings: res.logLines.filter((l) => /remains pending/i.test(l.message)).length,
      anyWarning: res.logLines.length,
      maxStageGapMs: maxGapMs,
      latencyMs: latencies,
    };
  });
  const sum = (f) => perAgent.reduce((a, p) => a + (p ? f(p) : 0), 0);
  const allLat = perAgent.flatMap((p) => (p ? p.latencyMs : []));
  return {
    arm: r.name, agents: r.agents, elapsedMs: r.elapsedMs,
    isolationHeld: r.isolationHeld, liveBefore: r.liveBefore, liveAfter: r.liveAfter,
    devBefore: r.devBefore, devAfter: r.devAfter,
    exitCodes: r.exitCodes, stderr: r.stderr,
    totalMessages: sum((p) => p.messages),
    totalWakes: sum((p) => p.wakes),
    totalCommitStarted: sum((p) => p.commitStarted),
    totalCommitCompleted: sum((p) => p.commitCompleted),
    totalRetries: sum((p) => p.retries),
    totalPendingWarnings: sum((p) => p.pendingWarnings),
    totalAnyWarning: sum((p) => p.anyWarning),
    maxStageGapMs: Math.max(0, ...perAgent.map((p) => (p ? p.maxStageGapMs : 0))),
    latencyMsMin: allLat.length ? Math.min(...allLat) : null,
    latencyMsMax: allLat.length ? Math.max(...allLat) : null,
    perAgent,
  };
}

const arms = [];
const plan = (n, gapMs) => Array.from({ length: n }, (_, i) => ({ id: `m${i}`, delayMs: i === 0 ? 0 : gapMs }));

// ARM A - fan-out contention from a stale baseline: all three must write, one wins.
arms.push(analyse(await runArm({ name: "armA-fanout", agents: 3, lastSeenOffsetMs: 3600_000, plan: plan(1, 0), root })));
// ARM C - forced conflict, more simultaneous writers to make contention near-certain.
arms.push(analyse(await runArm({ name: "armC-forced-conflict", agents: 5, lastSeenOffsetMs: 3600_000, plan: plan(1, 0), root })));
// ARM B2 - SUB-WINDOW spacing. This arm ALONE carries the coalescing-suppression claim.
arms.push(analyse(await runArm({ name: "armB2-subwindow-10s", agents: 3, lastSeenOffsetMs: 3600_000, plan: plan(6, 10_000), root })));
// ARM B1 - production-shape control at the measured 84s median. Healthy-mode claims ONLY.
arms.push(analyse(await runArm({ name: "armB1-production-84s", agents: 3, lastSeenOffsetMs: 3600_000, plan: plan(3, 84_000), root })));

await writeFile(`${root}/battery-results.json`, JSON.stringify(arms, null, 2), "utf-8");
for (const a of arms) {
  console.log(`\n=== ${a.arm}  agents=${a.agents}  elapsed=${(a.elapsedMs/1000).toFixed(1)}s ===`);
  console.log(`  isolation      live ${a.liveBefore} -> ${a.liveAfter}  ${a.isolationHeld ? "HELD" : "*** ARM VOID ***"}`);
  console.log(`  dev store      ${a.devBefore} -> ${a.devAfter}`);
  console.log(`  messages/wakes ${a.totalMessages} / ${a.totalWakes}   ${a.totalMessages===a.totalWakes ? "all present" : "*** MISSING ***"}`);
  console.log(`  commits        started ${a.totalCommitStarted}  completed ${a.totalCommitCompleted}  retries ${a.totalRetries}`);
  console.log(`  warnings       pending ${a.totalPendingWarnings}  any ${a.totalAnyWarning}`);
  console.log(`  max stage gap  ${a.maxStageGapMs} ms   latency ${a.latencyMsMin}-${a.latencyMsMax} ms`);
  console.log(`  exit codes     ${JSON.stringify(a.exitCodes)}${a.stderr.length ? "  STDERR: "+a.stderr.join(" ").slice(0,200) : ""}`);
}
