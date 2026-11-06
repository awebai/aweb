import { decodeIdChain, type IdChain } from "./id_certificates.js";
import { canonicalJSONValue } from "./canonical.js";
import { verifyIdChain, type IdStatusEvidence, type IdSubject, type IdVerification } from "./id_verification.js";

export interface ReceivedIdChain {
  id_chain?: unknown;
  from_did?: string;
  from_stable_id?: string;
  from_address?: string;
}
export interface ReceivedIdStatus {
  evidence(chain: IdChain | null, subject: IdSubject, domain?: string): Promise<IdStatusEvidence | null>;
  enrollmentFor?(id: string, address: string): Promise<{ state: string; domain: string | null }>;
}
export function receivedIdSubject(message: ReceivedIdChain): IdSubject {
  return { id: message.from_stable_id || message.from_did || "", did_key: message.from_did || "", team_member_did_aw: null, team_member_did_key: null };
}

/** Call only after ordinary sender authentication; adjacent metadata is never authority. */
export async function readReceivedIdChain(message: ReceivedIdChain, authenticated: boolean, status: ReceivedIdStatus): Promise<IdVerification> {
  const refused = (reason: IdVerification["reason"]): IdVerification => ({ outcome: "unknown", human_id: null, identity_valid: false, kind: null, reason });
  const subject = receivedIdSubject(message);
  if (!authenticated) return refused("subject_mismatch");
  let chain: IdChain | null = null;
  if (message.id_chain !== undefined && message.id_chain !== null) {
    let decoded;
    try { decoded = decodeIdChain(new TextEncoder().encode(canonicalJSONValue(message.id_chain, "invalid chain"))); }
    catch { return refused("invalid_shape"); }
    if (!decoded.ok) return refused(decoded.reason);
    chain = decoded.value;
    // The pure verifier checks local sender binding/structure before evidence.
    const preflight = verifyIdChain(chain, subject, null);
    if (preflight.reason !== "evidence_unavailable") return preflight;
  } else if (!subject.id.startsWith("did:aw:")) {
    return verifyIdChain(null, subject, null);
  }
  let domain: string | undefined;
  if (chain === null) {
    const enrollment = await status.enrollmentFor?.(subject.id, message.from_address || "");
    if (enrollment?.state === "not_enrolled") return { outcome: "unknown", human_id: null, identity_valid: null, kind: null, reason: "unregistered_identity" };
    if (enrollment?.state !== "enrolled" || !enrollment.domain) return verifyIdChain(null, subject, null);
    domain = enrollment.domain;
  }
  const evidence = await status.evidence(chain, subject, domain);
  const presented = verifyIdChain(chain, subject, evidence);
  // A presented verified human is final. Only complete independent evidence
  // can improve a registered none/stale presentation to a current human.
  if (chain && subject.id.startsWith("did:aw:") && (presented.outcome === "no_human" || presented.reason === "superseded_certificate" || presented.reason === "stale_issuer_key")) {
    const current = verifyIdChain(null, subject, evidence);
    if (current.outcome === "nearest_human") return current;
  }
  return presented;
}
