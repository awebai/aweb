// A Pi session whose session_shutdown hook never settles, and so never
// reaches the bundle's own abort, stays alive: its stream and the harness's
// server keep the process running. Stopping it is not the harness's job. The
// freshness runner bounds this process and requires that bound to fire after
// the marker named by AWEB_HUNG_SHUTDOWN_MARKER is written.
import { writeFileSync } from "node:fs";
import test from "node:test";

import { bundleWith, eventually, keepOpen, serverWatch, startPiSession } from "./pi_host.mts";

const marker = process.env.AWEB_HUNG_SHUTDOWN_MARKER;
if (!marker) throw new Error("AWEB_HUNG_SHUTDOWN_MARKER must name the marker file");

test("a Pi session whose shutdown never settles holds its process", async (t) => {
  const { watch, observe } = serverWatch();
  const extension = bundleWith({ shutdown: () => new Promise(() => {}) });
  const session = await startPiSession(t, keepOpen, { extension, observe });
  await eventually(() => watch.streamOpened, "the bundle never opened the event stream");
  writeFileSync(marker, "shutdown withheld\n");
  await session.close();
});
