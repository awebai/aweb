// A runtime's activity emitter, built from its loaded channel config.
import type { APIClient } from "../api/client.js";
import type { AgentConfig } from "../config.js";
import { ActivityEmitter, type ActivitySigner } from "./emitter.js";
import { publishActivity } from "./publish.js";

/**
 * The signer of activity events: the key that signs this runtime's requests.
 * For a grant seat that is the grant session key, not the subject's key; the
 * server attributes the event to the subject (docs/agent-activity.md).
 */
export function activitySigner(config: AgentConfig): ActivitySigner {
  let did = config.did;
  if (config.authMode === "grant") {
    if (!config.grantSessionDID) throw new Error("a grant seat needs its grant session DID to sign activity");
    did = config.grantSessionDID;
  }
  return {
    did,
    ...(config.stableID ? { stableID: config.stableID } : {}),
    teamID: config.teamID,
    seed: config.signingKey,
  };
}

export function createActivityEmitter(
  config: AgentConfig,
  client: APIClient,
  options: { workRoot?: string; log?: (line: string) => void } = {},
): ActivityEmitter {
  if (!config.identityHome) throw new Error("the activity opt-in needs the identity root");
  return new ActivityEmitter({
    identityRoot: config.identityHome,
    workRoot: options.workRoot,
    signer: activitySigner(config),
    publish: (body) => publishActivity(client, body),
    log: options.log,
  });
}
