import type { ChildProcess } from "node:child_process";
import { execFileSync } from "node:child_process";

export interface OwnedProcessMember {
  pid: number;
  command: string;
}

export interface OwnedProcessGroupProof {
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

export function listProcessGroupMembers(processGroupID: number): OwnedProcessMember[] {
  const output = execFileSync("/bin/ps", ["-ww", "-axo", "pid=,pgid=,command="], {
    encoding: "utf8",
  });
  const members: OwnedProcessMember[] = [];
  for (const line of output.split("\n")) {
    const match = line.match(/^\s*(\d+)\s+(\d+)\s+(.*)$/);
    if (!match || Number(match[2]) !== processGroupID) continue;
    members.push({ pid: Number(match[1]), command: match[3] });
  }
  return members;
}

export async function stopOwnedProcessGroup(
  leader: ChildProcess,
  termGraceMs = 5_000,
): Promise<OwnedProcessGroupProof> {
  const processGroupID = leader.pid;
  if (!processGroupID) throw new Error("owned process-group leader has no PID");
  let observedMembers: OwnedProcessMember[] = [];
  let observationFailure: unknown;
  try {
    observedMembers = listProcessGroupMembers(processGroupID);
  } catch (error) {
    observationFailure = error;
  }
  let sigkillRequired = false;
  if (processGroupExists(processGroupID)) {
    signalProcessGroup(processGroupID, "SIGTERM");
    if (!await waitForProcessGroupExit(processGroupID, termGraceMs)) {
      sigkillRequired = true;
      signalProcessGroup(processGroupID, "SIGKILL");
      if (!await waitForProcessGroupExit(processGroupID, 10_000)) {
        const remaining = listProcessGroupMembers(processGroupID);
        throw new Error(
          `owned process-group ${processGroupID} survived SIGKILL: ${JSON.stringify(remaining)}`,
        );
      }
    }
  }
  await waitForLeaderObservation(leader, 1_000);
  if (processGroupExists(processGroupID)) {
    throw new Error(`owned process-group ${processGroupID} still exists after cleanup`);
  }
  const survivingPIDs = observedMembers.map(({ pid }) => pid).filter(pidExists);
  if (survivingPIDs.length > 0) {
    throw new Error(`owned process PIDs survived cleanup: ${survivingPIDs.join(", ")}`);
  }
  if (observationFailure) {
    throw new Error("could not record owned process-group members before cleanup", {
      cause: observationFailure,
    });
  }
  return {
    observed_members: observedMembers,
    observed_pids: observedMembers.map(({ pid }) => pid),
    sigkill_required: sigkillRequired,
    termination_proven: true,
  };
}

function pidExists(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ESRCH") return false;
    if ((error as NodeJS.ErrnoException).code === "EPERM") return true;
    throw error;
  }
}

function signalProcessGroup(processGroupID: number, signal: NodeJS.Signals): void {
  try {
    process.kill(-processGroupID, signal);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ESRCH") throw error;
  }
}

async function waitForProcessGroupExit(
  processGroupID: number,
  timeoutMs: number,
): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (!processGroupExists(processGroupID)) return true;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  return !processGroupExists(processGroupID);
}

async function waitForLeaderObservation(leader: ChildProcess, timeoutMs: number): Promise<void> {
  if (leader.exitCode !== null || leader.signalCode !== null) return;
  await Promise.race([
    new Promise<void>((resolve) => leader.once("exit", () => resolve())),
    new Promise<void>((resolve) => setTimeout(resolve, timeoutMs)),
  ]);
}
