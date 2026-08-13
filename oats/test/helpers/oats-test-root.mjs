import { existsSync } from "node:fs";
import { join } from "node:path";

// These tests exercise a REAL OATS checkout, and which one must be decided by this
// repository rather than by whatever happens to be installed on the machine - the
// same reason `make test-oats` pins PATH to this checkout's own binaries.
//
// The make target refuses early when OATS_TEST_ROOT names a root without the
// launch-environment contract. It cannot help someone who runs `node --test`
// directly, and an UNSET root used to fall through to an ambient `oats` binary: the
// suite then failed four assertions out of eighty-six, which reads as a small real
// defect rather than a missing environment, and was reported as one.
export function requireOatsTestRoot() {
  const root = (process.env.OATS_TEST_ROOT || "").trim();
  if (!root) {
    throw new Error(
      "OATS_TEST_ROOT is not set, so there is no OATS checkout to test against. " +
        "These tests do not fall back to an ambient `oats` on PATH, because an ambient " +
        "install must not decide whether this suite passes. " +
        "Run `make test-oats`, which prepares the pinned root and sets this for you, " +
        "or `make prepare-oats-test-root` and then set OATS_TEST_ROOT to .cache/oats-pinned.",
    );
  }
  return root;
}

// Resolves the CLI from the required root, so every caller reports a missing root
// the same way rather than each re-deriving it.
export function oatsCliPath() {
  const root = requireOatsTestRoot();
  const cli = join(root, "bin", "oats.mjs");
  if (!existsSync(cli)) {
    throw new Error(
      `real OATS CLI not found at ${cli}. OATS_TEST_ROOT=${root} does not look like an OATS checkout; ` +
        "`make prepare-oats-test-root` populates .cache/oats-pinned.",
    );
  }
  return cli;
}
