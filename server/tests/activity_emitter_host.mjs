// Drives channel-core's activity emitter against a running aweb server for
// test_agent_activity_emitter_e2e.py. It reads one JSON object on stdin, runs
// its steps through the real emitter and publisher, waits until everything
// queued has been published, and prints the outcomes as one JSON line.
//
// With identity_home, the emitter is built the way a runtime builds it: the
// identity home is loaded with resolveConfig, and createChannelClient and
// createActivityEmitter build the client and emitter (outcomes then go
// unrecorded; the test reads what the server relayed).
import { APIClient } from "../../channel-core/dist/api/client.js";
import { ActivityEmitter } from "../../channel-core/dist/activity/emitter.js";
import { publishActivity } from "../../channel-core/dist/activity/publish.js";
import { createActivityEmitter, createChannelClient, resolveConfig } from "../../channel-core/dist/index.js";

let input = "";
for await (const chunk of process.stdin) input += chunk;
const spec = JSON.parse(input);
const outcomes = [];
const logs = [];
let emitter;
if (spec.identity_home) {
  const config = await resolveConfig(spec.work_root, { identityHome: spec.identity_home, teamID: spec.team_id });
  emitter = createActivityEmitter(config, createChannelClient(config), { workRoot: spec.work_root, log: (line) => logs.push(line) });
} else {
  const seed = Uint8Array.from(Buffer.from(spec.seed_hex, "hex"));
  const client = new APIClient(spec.base_url, {
    did: spec.did,
    stableID: "",
    signingKey: seed,
    teamID: spec.team_id,
    teamCertificateHeader: spec.certificate,
  });
  emitter = new ActivityEmitter({
    identityRoot: spec.identity_root,
    workRoot: spec.work_root,
    signer: { did: spec.did, teamID: spec.team_id, seed },
    publish: async (body) => {
      const outcome = await publishActivity(client, body);
      outcomes.push(outcome.kind);
      return outcome;
    },
    log: (line) => logs.push(line),
  });
}

for (const step of spec.steps) {
  if (step.op === "wake") emitter.chatWakeDelivered(step.session_id, { encrypted: Boolean(step.encrypted) });
  else if (step.op === "turn_started") emitter.turnStarted();
  else if (step.op === "tool") emitter.tool(step.name, step.input);
  else if (step.op === "turn_ended") emitter.turnEnded();
  else if (step.op === "drain") await emitter.drained();
  else if (step.op === "wait") await new Promise((resolve) => setTimeout(resolve, step.ms));
  else throw new Error(`unknown step ${step.op}`);
}
await emitter.drained();
process.stdout.write(JSON.stringify({ outcomes, logs }) + "\n");
