import { existsSync } from "node:fs";
import { join } from "node:path";

// These tests exercise a REAL OAS checkout, and which one must be decided by this
// repository rather than by whatever happens to be installed on the machine - the
// same reason `make test-oas` pins PATH to this checkout's own binaries.
//
// The make target refuses early when OAS_TEST_ROOT names a root without the
// launch-environment contract. It cannot help someone who runs `node --test`
// directly, and an UNSET root used to fall through to an ambient `oas` binary: the
// suite then failed four assertions out of eighty-six, which reads as a small real
// defect rather than a missing environment, and was reported as one.
export function requireOasTestRoot() {
  const root = (process.env.OAS_TEST_ROOT || "").trim();
  if (!root) {
    throw new Error(
      "OAS_TEST_ROOT is not set, so there is no OAS checkout to test against. " +
        "These tests do not fall back to an ambient `oas` on PATH, because an ambient " +
        "install must not decide whether this suite passes. " +
        "Run `make test-oas`, which prepares the pinned root and sets this for you, " +
        "or `make prepare-oas-test-root` and then set OAS_TEST_ROOT to .cache/oas-pinned.",
    );
  }
  return root;
}

// Resolves the CLI from the required root, so every caller reports a missing root
// the same way rather than each re-deriving it.
export function oasCliPath() {
  const root = requireOasTestRoot();
  const cli = join(root, "bin", "oas.mjs");
  if (!existsSync(cli)) {
    throw new Error(
      `real OAS CLI not found at ${cli}. OAS_TEST_ROOT=${root} does not look like an OAS checkout; ` +
        "`make prepare-oas-test-root` populates .cache/oas-pinned.",
    );
  }
  return cli;
}
