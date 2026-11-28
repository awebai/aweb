// A Pi session whose session_shutdown hook never settles, and so never
// reaches the bundle's own abort, stays alive: its stream and the harness's
// server keep the process running. Stopping it is not the harness's job. The
// hook writes the marker named by AWEB_HUNG_SHUTDOWN_MARKER when it is
// entered; the freshness runner bounds this process and requires its own
// timeout verdict after that marker.
import { writeFileSync } from "node:fs";
import test from "node:test";

import { bundleWith, eventually, keepOpen, serverWatch, startPiSession } from "./pi_host.mts";

const marker = process.env.AWEB_HUNG_SHUTDOWN_MARKER;
if (!marker) throw new Error("AWEB_HUNG_SHUTDOWN_MARKER must name the marker file");

test("a Pi session whose shutdown never settles holds its process", async (t) => {
  const { watch, observe } = serverWatch();
  const extension = bundleWith({
    shutdown: () => {
      writeFileSync(marker, "shutdown withheld\n");
      return new Promise(() => {});
    },
  });
  const session = await startPiSession(t, keepOpen, { extension, observe });
  await eventually(() => watch.streamOpened, "the bundle never opened the event stream");
  await session.close();
});
