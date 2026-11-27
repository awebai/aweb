// The @awebai/channel-core dependency is a file: link to the sibling
// workspace. npm installs the link but never installs or builds the sibling,
// so building or testing the plugin against a stale channel-core/dist would
// silently bundle out-of-date code (including missing security fixes). Rebuild
// channel-core from source first so the plugin bundle always reflects src.
import { execSync } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const channelCore = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "channel-core");

if (!existsSync(join(channelCore, "package.json"))) {
  console.error(`ensure-channel-core: no sibling checkout at ${channelCore}`);
  process.exit(1);
}
if (!existsSync(join(channelCore, "node_modules"))) {
  execSync("npm ci", { cwd: channelCore, stdio: "inherit" });
}
execSync("npm run build", { cwd: channelCore, stdio: "inherit" });
