import { mkdirSync } from "node:fs";
import { join } from "node:path";

export function prepareKernelProbeDirectories({ root }) {
  const home = join(root, "home"), deployment = join(root, "deploy");
  const source = join(root, "source"), bin = join(root, "bin");
  // Released OATS discovers a deployment through agents/ (docs/wake-runner-integrity.md).
  for (const path of [home, deployment, join(deployment, "agents"), source, bin, join(root, "tmux")]) {
    mkdirSync(path, { recursive: true, mode: 0o700 });
  }
  return { home, deployment, source, bin };
}

export function kernelCommandErrorCode(output) {
  // Command stdout can contain private results; retain only the kernel's code.
  try {
    const code = JSON.parse(output)?.error?.code;
    return typeof code === "string" && /^E_[A-Z0-9_]{1,61}$/.test(code) ? code : null;
  } catch (error) {
    if (!(error instanceof SyntaxError)) throw error;
    return null;
  }
}
