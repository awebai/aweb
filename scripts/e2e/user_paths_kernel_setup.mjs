import { mkdirSync } from "node:fs";
import { join } from "node:path";

export function prepareKernelProbeDirectories({ root }) {
  const home = join(root, "home"), deployment = join(root, "deploy");
  const source = join(root, "source"), bin = join(root, "bin");
  for (const path of [home, deployment, source, bin, join(root, "tmux")]) {
    mkdirSync(path, { recursive: true, mode: 0o700 });
  }
  return { home, deployment, source, bin };
}
