import type { ChildProcess } from "node:child_process";
import { execFileSync } from "node:child_process";

export interface OwnedProcessMember {
  pid: number;
  parent_pid: number;
  process_group_id: number;
  command: string;
}

export interface OwnedProcessTreeProof {
  observed_members: OwnedProcessMember[];
  observed_pids: number[];
  sigkill_required: boolean;
  termination_proven: true;
}

export function processGroupExists(processGroupID: number): boolean {
  try {
    process.kill(-processGroupID, 0);
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ESRCH") return false;
    if ((error as NodeJS.ErrnoException).code === "EPERM") return true;
    throw error;
  }
}

export function processGroupIDForPID(pid: number): number | undefined {
  return listProcessTable().find((member) => member.pid === pid)?.process_group_id;
}

export async function stopOwnedProcessTree(
  leader: ChildProcess,
  expectedProcessGroupID: number,
  termGraceMs = 5_000,
): Promise<OwnedProcessTreeProof> {
  const leaderPID = leader.pid;
  if (!leaderPID) throw new Error("owned process-tree leader has no PID");
  const observedMembers = listProcessTree(leaderPID);
  if (!observedMembers.some(({ pid }) => pid === leaderPID)) {
    throw new Error(`owned process tree lacks its expected leader ${leaderPID}`);
  }
  const escaped = observedMembers.filter(
    ({ process_group_id }) => process_group_id !== expectedProcessGroupID,
  );
  signalOwnedMembers(observedMembers, "SIGTERM");
  let sigkillRequired = false;
  if (!await waitForOwnedPIDsExit(observedMembers, termGraceMs)) {
    sigkillRequired = true;
    signalOwnedMembers(observedMembers, "SIGKILL");
    if (!await waitForOwnedPIDsExit(observedMembers, 10_000)) {
      throw new Error(`owned process tree survived SIGKILL: ${JSON.stringify(observedMembers)}`);
    }
  }
  await waitForLeaderObservation(leader, 1_000);
  if (escaped.length > 0) {
    throw new Error(
      `owned process tree escaped supervisor group before cleanup: ${JSON.stringify(escaped)}`,
    );
  }
  return {
    observed_members: observedMembers,
    observed_pids: observedMembers.map(({ pid }) => pid),
    sigkill_required: sigkillRequired,
    termination_proven: true,
  };
}

function listProcessTable(): OwnedProcessMember[] {
  const output = execFileSync("/bin/ps", ["-ww", "-axo", "pid=,ppid=,pgid=,command="], {
    encoding: "utf8",
    killSignal: "SIGKILL",
    timeout: 2_000,
  });
  const members: OwnedProcessMember[] = [];
  for (const line of output.split("\n")) {
    const match = line.match(/^\s*(\d+)\s+(\d+)\s+(\d+)\s+(.*)$/);
    if (!match) continue;
    members.push({
      pid: Number(match[1]),
      parent_pid: Number(match[2]),
      process_group_id: Number(match[3]),
      command: match[4],
    });
  }
  return members;
}

function listProcessTree(leaderPID: number): OwnedProcessMember[] {
  const processTable = listProcessTable();
  const ownedPIDs = new Set([leaderPID]);
  let changed = true;
  while (changed) {
    changed = false;
    for (const member of processTable) {
      if (ownedPIDs.has(member.parent_pid) && !ownedPIDs.has(member.pid)) {
        ownedPIDs.add(member.pid);
        changed = true;
      }
    }
  }
  return processTable.filter(({ pid }) => ownedPIDs.has(pid));
}

function signalOwnedMembers(
  members: OwnedProcessMember[],
  signal: NodeJS.Signals,
): void {
  const current = new Map(listProcessTable().map((member) => [member.pid, member]));
  for (const member of [...members].reverse()) {
    const currentMember = current.get(member.pid);
    if (
      !currentMember
      || currentMember.process_group_id !== member.process_group_id
      || currentMember.command !== member.command
    ) continue;
    try {
      process.kill(member.pid, signal);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ESRCH") throw error;
    }
  }
}

async function waitForOwnedPIDsExit(
  members: OwnedProcessMember[],
  timeoutMs: number,
): Promise<boolean> {
  const identities = new Map(members.map((member) => [member.pid, member]));
  const hasSurvivor = () => listProcessTable().some((current) => {
    const observed = identities.get(current.pid);
    return observed !== undefined
      && current.process_group_id === observed.process_group_id
      && current.command === observed.command;
  });
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (!hasSurvivor()) return true;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  return !hasSurvivor();
}

async function waitForLeaderObservation(leader: ChildProcess, timeoutMs: number): Promise<void> {
  if (leader.exitCode !== null || leader.signalCode !== null) return;
  await Promise.race([
    new Promise<void>((resolve) => leader.once("exit", () => resolve())),
    new Promise<void>((resolve) => setTimeout(resolve, timeoutMs)),
  ]);
}
