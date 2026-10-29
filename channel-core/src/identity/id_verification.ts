// Pure id-chain verification (docs/id-certificates.md sections 3-5). The
// caller supplies already trusted facts: the authoritative status snapshot
// from the production cached client, the independently selected exact-domain
// namespace authority, and the cache age. Nothing here reads DNS, HTTP or a
// cache, and nothing here decides a request; see requestDisposition for that.
import {
  ID_CHAIN_MAX_CERTIFICATES,
  hasExactKeys,
  idCertificateId,
  idChainRefusal,
  isCanonicalDidAw,
  isCanonicalDidKey,
  isRecord,
  parseSignedIdCertificate,
  type IdCertificate,
  type IdChain,
  type IdDecodeRefusal,
  type IdKind,
  type SignedIdCertificate,
} from "./id_certificates.js";
import { verifyDidLogEntries, type DidKeyEvidence } from "./registry.js";

export const ID_STATUS_FRESH_SECONDS = 60;
export const ID_STATUS_OUTAGE_GRACE_SECONDS = 900;

export type IdVerificationReason =
  | IdDecodeRefusal
  | "verified"
  | "legacy_no_chain"
  | "unregistered_identity"
  | "unregistered_parent"
  | "stale_issuer_key"
  | "superseded_certificate"
  | "revoked"
  | "root_replaced"
  | "subject_mismatch"
  | "status_expired"
  | "evidence_unavailable"
  | "duplicate_id"
  | "cycle"
  | "missing_parent"
  | "human_issuer_is_agent";

/** The one shared result: exactly these five fields. */
export interface IdVerification {
  outcome: "nearest_human" | "no_human" | "unknown" | "unavailable";
  human_id: string | null;
  identity_valid: boolean | null;
  kind: IdKind | null;
  reason: IdVerificationReason;
}

/** The independently authenticated subject; for a grant, its SUBJECT, never the session key. */
export interface IdSubject {
  id: string;
  did_key: string;
  team_member_did_aw: string | null;
  team_member_did_key: string | null;
}

/** Exact-domain DNS authority, selected independently of anything the agent presents. */
export interface IdNamespaceAuthority {
  domain: string;
  dns_name: string;
  inherited: boolean;
  controller_key: string;
}

/**
 * Private, in-process evidence. `status` is the registry's status response
 * as received; it is never accepted from a request or an agent.
 */
export interface IdStatusEvidence {
  status: unknown;
  namespace_authority: IdNamespaceAuthority;
  age_seconds: number | null;
  refresh_failed: boolean;
}

export type IdStatusCacheMode = "fresh" | "outage_grace" | "unavailable";

export interface IdStatusRequest {
  v: 1;
  domain: string;
  ids: string[];
}

export type IdStatusPlan =
  | { lookup: "none" }
  | { lookup: "unavailable" }
  | { lookup: "status"; request: IdStatusRequest };

/**
 * The 60s/900s rule: evidence is fresh to 60 seconds inclusive; past that it
 * serves only while refreshes fail, to 900 seconds inclusive.
 */
export function idStatusCacheMode(ageSeconds: number | null, refreshFailed: boolean): IdStatusCacheMode {
  if (ageSeconds === null || !Number.isFinite(ageSeconds) || ageSeconds < 0) return "unavailable";
  if (ageSeconds <= ID_STATUS_FRESH_SECONDS) return "fresh";
  if (refreshFailed && ageSeconds <= ID_STATUS_OUTAGE_GRACE_SECONDS) return "outage_grace";
  return "unavailable";
}

/**
 * What status, if any, verifying this presentation needs. Local did:key IDs
 * are never submitted. A did:aw is domain-free, so an omitted chain for a
 * stable ID needs the domain from the existing stable-ID resolution.
 */
export function idStatusRequest(chain: IdChain | null, subject: IdSubject, domain?: string): IdStatusPlan {
  if (chain === null) {
    if (!subject.id.startsWith("did:aw:")) return { lookup: "none" };
    if (domain === undefined) return { lookup: "unavailable" };
    return { lookup: "status", request: { v: 1, domain, ids: [subject.id] } };
  }
  // A chain the bundle checks refuse is refused before any evidence is read.
  if (idChainRefusal(chain)) return { lookup: "none" };
  const ids: string[] = [];
  for (const { certificate } of chain.certificates) {
    if (certificate.id.startsWith("did:aw:") && !ids.includes(certificate.id)) ids.push(certificate.id);
  }
  return { lookup: "status", request: { v: 1, domain: chain.certificates[0].certificate.domain, ids } };
}

export function verifyIdChain(chain: IdChain | null, subject: IdSubject, evidence: IdStatusEvidence | null): IdVerification {
  try {
    return verify(chain, subject, evidence);
  } catch (error) {
    if (error instanceof Refusal) return refusal(error.reason);
    throw error;
  }
}

class Refusal extends Error {
  constructor(readonly reason: IdVerificationReason) {
    super(reason);
  }
}

function refusal(reason: IdVerificationReason): IdVerification {
  const unavailable = reason === "status_expired" || reason === "evidence_unavailable";
  const validityUnknown = unavailable || reason === "legacy_no_chain" || reason === "unregistered_identity";
  return {
    outcome: unavailable ? "unavailable" : "unknown",
    human_id: null,
    identity_valid: validityUnknown ? null : false,
    kind: null,
    reason,
  };
}

function verify(presented: IdChain | null, subject: IdSubject, evidence: IdStatusEvidence | null): IdVerification {
  let chain = presented;
  if (chain === null) {
    // A chainless local key keeps ordinary legacy authentication with no lookup.
    if (!subject.id.startsWith("did:aw:")) return refusal("legacy_no_chain");
    // An enrolled stable ID cannot escape status by omitting its chain.
    const snapshot = trustedSnapshot(evidence, evidence?.namespace_authority.domain);
    if (snapshot.missing.has(subject.id)) return refusal("unregistered_identity");
    chain = currentChain(snapshot, subject.id);
  }

  const bundleRefusal = idChainRefusal(chain);
  if (bundleRefusal) throw new Refusal(bundleRefusal);
  const certificates = chain.certificates.map(signed => signed.certificate);
  const leaf = certificates[certificates.length - 1];

  checkSubjectIds(subject, leaf);
  checkStructure(certificates);
  const domain = certificates[0].domain;
  if (certificates.some(certificate => certificate.domain !== domain)) throw new Refusal("domain_mismatch");
  checkIssuerKinds(certificates);
  for (let i = 1; i < certificates.length; i += 1) {
    // No registered child under an unregistered local parent in v1.
    if (isRegistered(certificates[i]) && !isRegistered(certificates[i - 1])) throw new Refusal("unregistered_parent");
  }

  const snapshot = trustedSnapshot(evidence, domain);
  for (const certificate of certificates) {
    if (!isRegistered(certificate)) continue;
    if (snapshot.missing.has(certificate.id)) throw new Refusal("unregistered_identity");
    if (!snapshot.identities.has(certificate.id)) throw new Refusal("evidence_unavailable");
  }
  if (isRegistered(leaf) && subject.did_key !== snapshot.identities.get(leaf.id)!.currentKey) {
    throw new Refusal("subject_mismatch");
  }
  for (const signed of chain.certificates) {
    const { certificate } = signed;
    if (isRegistered(certificate) && idCertificateId(certificate) !== snapshot.identities.get(certificate.id)!.head.id) {
      throw new Refusal("superseded_certificate");
    }
  }
  for (let i = 0; i < certificates.length; i += 1) checkIssuerKey(snapshot, certificates, i);
  // Which ancestors must be currently valid follows from the leaf: agent
  // edges need a current parent, human edges a parent valid at registration.
  const invalid = invalidity(snapshot, certificates, certificates.length - 1);
  if (invalid) throw new Refusal(invalid);

  const human = [...certificates].reverse().find(certificate => certificate.kind === "human");
  return {
    outcome: human ? "nearest_human" : "no_human",
    human_id: human ? human.id : null,
    identity_valid: true,
    kind: leaf.kind,
    reason: "verified",
  };
}

function isRegistered(certificate: IdCertificate): boolean {
  return certificate.id.startsWith("did:aw:");
}

function checkSubjectIds(subject: IdSubject, leaf: IdCertificate): void {
  if (subject.id !== leaf.id) throw new Refusal("subject_mismatch");
  if (subject.team_member_did_aw !== null && subject.team_member_did_aw !== leaf.id) throw new Refusal("subject_mismatch");
  if (subject.team_member_did_key !== null && subject.team_member_did_key !== subject.did_key) {
    throw new Refusal("subject_mismatch");
  }
  // A local leaf's ID is the authenticated key itself; a registered leaf's
  // key is checked against its verified key history once status is in hand.
  if (!isRegistered(leaf) && subject.did_key !== leaf.id) throw new Refusal("subject_mismatch");
}

/** Namespace child first, each link the child of the one before. */
function checkStructure(certificates: IdCertificate[]): void {
  const ids = certificates.map(certificate => certificate.id);
  if (new Set(ids).size !== ids.length) throw new Refusal("duplicate_id");
  certificates.forEach((certificate, i) => {
    const { parent } = certificate;
    const linked = i === 0 ? parent.kind === "namespace" : parent.kind === "identity" && parent.id === ids[i - 1];
    if (linked) return;
    throw new Refusal(parent.kind === "identity" && ids.indexOf(parent.id) >= i ? "cycle" : "missing_parent");
  });
}

/** R1: a human's issuer is the namespace or a human, never an agent. */
function checkIssuerKinds(certificates: IdCertificate[]): void {
  for (let i = 1; i < certificates.length; i += 1) {
    if (certificates[i].kind === "human" && certificates[i - 1].kind === "agent") throw new Refusal("human_issuer_is_agent");
  }
}

// ---------------------------------------------------------------- status

interface Epoch {
  seq: number;
  didKey: string;
  registeredAt: string;
  retiredAt: string | null;
  continuity: "rotated" | "replaced";
}

interface CertificateRevision {
  id: string;
  signed: SignedIdCertificate;
  certificate: IdCertificate;
  registeredAt: string;
  supersededAt: string | null;
  issuerKeySeq: number;
}

interface IdentityStatus {
  keys: Map<number, string>;
  currentKey: string;
  head: CertificateRevision;
  revisions: CertificateRevision[];
  revocation: { revokedAt: string; effectiveFrom: string } | null;
}

interface Snapshot {
  epochs: Epoch[];
  /** Registered revisions admitted before this time lost their authority to a namespace replacement. */
  replacedAt: string;
  identities: Map<string, IdentityStatus>;
  missing: Set<string>;
}

const MICROSECOND_TIMESTAMP = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z$/;

/** Evidence that is trusted, current enough and internally consistent, or a refusal. */
function trustedSnapshot(evidence: IdStatusEvidence | null, domain: string | undefined): Snapshot {
  if (evidence === null || domain === undefined) throw new Refusal("evidence_unavailable");
  const mode = idStatusCacheMode(evidence.age_seconds, evidence.refresh_failed);
  // Only last-known-good evidence outliving its outage grace has expired;
  // stale evidence that was never refreshed is not evidence at all.
  if (mode === "unavailable") {
    const expired =
      evidence.refresh_failed && evidence.age_seconds !== null && evidence.age_seconds > ID_STATUS_OUTAGE_GRACE_SECONDS;
    throw new Refusal(expired ? "status_expired" : "evidence_unavailable");
  }
  const authority = evidence.namespace_authority;
  // Only this exact domain's own _awid record is authority; never an ancestor's.
  if (authority.inherited || authority.domain !== domain || authority.dns_name !== `_awid.${domain}`) {
    throw new Refusal("evidence_unavailable");
  }
  const snapshot = parseSnapshot(evidence.status, domain);
  if (!snapshot) throw new Refusal("evidence_unavailable");
  // DNS and the registry's current epoch must name the same root key; a
  // disagreement is a contradictory authority snapshot, not a bad proof.
  if (snapshot.epochs[snapshot.epochs.length - 1].didKey !== authority.controller_key) {
    throw new Refusal("evidence_unavailable");
  }
  return snapshot;
}

/** Strictly read the whole status response; anything contradictory is unavailable. */
function parseSnapshot(status: unknown, domain: string): Snapshot | undefined {
  if (!isRecord(status) || !hasExactKeys(status, ["domain", "identities", "missing", "namespace", "observed_at", "v"])) return undefined;
  if (status.v !== 1 || status.domain !== domain || !isTimestamp(status.observed_at)) return undefined;
  const epochs = parseEpochs(status.namespace);
  if (!epochs || !Array.isArray(status.identities) || !Array.isArray(status.missing)) return undefined;
  const identities = new Map<string, IdentityStatus>();
  for (const row of status.identities) {
    const parsed = parseIdentity(row, domain);
    if (!parsed || identities.has(parsed.id)) return undefined;
    identities.set(parsed.id, parsed.status);
  }
  const missing = new Set<string>();
  for (const id of status.missing) {
    if (typeof id !== "string" || !isCanonicalDidAw(id) || identities.has(id) || missing.has(id)) return undefined;
    missing.add(id);
  }
  const replacedAt = epochs.filter(epoch => epoch.continuity === "replaced").at(-1)!.registeredAt;
  return { epochs, replacedAt, identities, missing };
}

function parseEpochs(namespace: unknown): Epoch[] | undefined {
  if (!isRecord(namespace) || !hasExactKeys(namespace, ["epochs"]) || !Array.isArray(namespace.epochs)) return undefined;
  const epochs: Epoch[] = [];
  for (const [index, row] of namespace.epochs.entries()) {
    if (!isRecord(row) || !hasExactKeys(row, ["continuity", "did_key", "registered_at", "retired_at", "seq"])) return undefined;
    const { seq, did_key, registered_at, retired_at, continuity } = row;
    if (continuity !== "rotated" && continuity !== "replaced") return undefined;
    if (!isPositiveInteger(seq) || typeof did_key !== "string" || !isCanonicalDidKey(did_key)) return undefined;
    if (!isTimestamp(registered_at) || !(retired_at === null || isTimestamp(retired_at))) return undefined;
    const previous = epochs[index - 1];
    if (previous && (seq <= previous.seq || previous.retiredAt === null || previous.retiredAt > registered_at)) return undefined;
    if (retired_at !== null && retired_at <= registered_at) return undefined;
    // Only the previous controller can continue the history: a rotation starts
    // exactly when its predecessor retires, and the first epoch has none.
    if (continuity === "rotated" && (!previous || previous.retiredAt !== registered_at)) return undefined;
    epochs.push({ seq, didKey: did_key, registeredAt: registered_at, retiredAt: retired_at, continuity });
  }
  if (epochs.length === 0 || epochs[epochs.length - 1].retiredAt !== null) return undefined;
  return epochs;
}

const IDENTITY_FIELDS = ["certificates", "current_certificate_id", "current_key_seq", "id", "key_history", "revocation"];
const DID_LOG_FIELDS = [
  "authorized_by", "entry_hash", "new_did_key", "operation", "prev_entry_hash",
  "previous_did_key", "seq", "signature", "state_hash", "timestamp",
];

function parseIdentity(row: unknown, domain: string): { id: string; status: IdentityStatus } | undefined {
  if (!isRecord(row) || !hasExactKeys(row, IDENTITY_FIELDS)) return undefined;
  const { id, current_certificate_id, current_key_seq, key_history, certificates, revocation } = row;
  if (typeof id !== "string" || !isCanonicalDidAw(id) || !isPositiveInteger(current_key_seq)) return undefined;

  // Key history is a DID continuity log, verified from its genesis.
  if (!Array.isArray(key_history) || key_history.length === 0) return undefined;
  const entries: DidKeyEvidence[] = [];
  for (const item of key_history) {
    if (!isRecord(item) || !hasExactKeys(item, ["entry", "registered_at"]) || !isTimestamp(item.registered_at)) return undefined;
    if (!isRecord(item.entry) || !hasExactKeys(item.entry, DID_LOG_FIELDS)) return undefined;
    entries.push(item.entry as unknown as DidKeyEvidence);
  }
  if (verifyDidLogEntries(id, entries, 0).error) return undefined;
  const keys = new Map(entries.map(entry => [entry.seq, entry.new_did_key]));
  if (entries[entries.length - 1].seq !== current_key_seq) return undefined;

  if (!Array.isArray(certificates) || certificates.length === 0) return undefined;
  const revisions: CertificateRevision[] = [];
  for (const [index, item] of certificates.entries()) {
    if (!isRecord(item) || !hasExactKeys(item, ["issuer_key_seq", "registered_at", "signed", "superseded_at"])) return undefined;
    const { signed, registered_at, superseded_at, issuer_key_seq } = item;
    if (!isTimestamp(registered_at) || !(superseded_at === null || isTimestamp(superseded_at))) return undefined;
    if (!isPositiveInteger(issuer_key_seq) || !parseSignedIdCertificate(signed).ok) return undefined;
    const certificate = (signed as SignedIdCertificate).certificate;
    // R2: a registered ID's kind and domain are fixed at first enrollment.
    if (certificate.id !== id || certificate.domain !== domain) return undefined;
    if (revisions.length > 0 && certificate.kind !== revisions[0].certificate.kind) return undefined;
    const previous = revisions[index - 1];
    if (previous && (previous.supersededAt === null || previous.supersededAt > registered_at)) return undefined;
    if (superseded_at !== null && superseded_at <= registered_at) return undefined;
    revisions.push({
      id: idCertificateId(certificate),
      signed: signed as SignedIdCertificate,
      certificate,
      registeredAt: registered_at,
      supersededAt: superseded_at,
      issuerKeySeq: issuer_key_seq,
    });
  }
  const head = revisions[revisions.length - 1];
  if (head.supersededAt !== null || head.id !== current_certificate_id) return undefined;

  let parsedRevocation: IdentityStatus["revocation"] = null;
  if (revocation !== null) {
    if (!isRecord(revocation) || !hasExactKeys(revocation, ["effective_from", "revoked_at"])) return undefined;
    if (!isTimestamp(revocation.revoked_at) || !isTimestamp(revocation.effective_from)) return undefined;
    if (revocation.effective_from > revocation.revoked_at) return undefined;
    parsedRevocation = { revokedAt: revocation.revoked_at, effectiveFrom: revocation.effective_from };
  }
  return { id, status: { keys, currentKey: keys.get(current_key_seq)!, head, revisions, revocation: parsedRevocation } };
}

/** An omitted chain: the stable ID's current head, then each parent's current head. */
function currentChain(snapshot: Snapshot, id: string): IdChain {
  const certificates: SignedIdCertificate[] = [];
  let next: string | undefined = id;
  while (next !== undefined) {
    const identity = snapshot.identities.get(next);
    if (!identity || certificates.length === ID_CHAIN_MAX_CERTIFICATES) throw new Refusal("evidence_unavailable");
    certificates.unshift(identity.head.signed);
    const { parent } = identity.head.certificate;
    next = parent.kind === "identity" ? parent.id : undefined;
  }
  return { v: 1, type: "aweb.id-chain", certificates };
}

// ---------------------------------------------------------------- evaluation

/**
 * A registered child is checked against the issuer key at its witnessed
 * issuer_key_seq; an unregistered local child against its parent's current key.
 */
function checkIssuerKey(snapshot: Snapshot, certificates: IdCertificate[], i: number): void {
  const certificate = certificates[i];
  const parentId = i === 0 ? null : certificates[i - 1].id;
  if (isRegistered(certificate)) {
    const revision = snapshot.identities.get(certificate.id)!.head;
    if (witnessedIssuerKey(snapshot, parentId, revision) !== certificate.issuer_key) throw new Refusal("evidence_unavailable");
    return;
  }
  if (certificate.issuer_key !== currentKey(snapshot, parentId)) throw new Refusal("stale_issuer_key");
}

function witnessedIssuerKey(snapshot: Snapshot, parentId: string | null, revision: CertificateRevision): string | undefined {
  if (parentId === null) {
    // The witnessed epoch must have been open when the revision was registered.
    const epoch = snapshot.epochs.find(epoch => epoch.seq === revision.issuerKeySeq);
    if (!epoch || epoch.registeredAt > revision.registeredAt) return undefined;
    if (epoch.retiredAt !== null && revision.registeredAt >= epoch.retiredAt) return undefined;
    return epoch.didKey;
  }
  return snapshot.identities.get(parentId)?.keys.get(revision.issuerKeySeq);
}

function currentKey(snapshot: Snapshot, parentId: string | null): string {
  if (parentId === null) return snapshot.epochs[snapshot.epochs.length - 1].didKey;
  // A local did:key parent is its own key and cannot rotate.
  if (!parentId.startsWith("did:aw:")) return parentId;
  return snapshot.identities.get(parentId)!.currentKey;
}

type Invalidity = "revoked" | "root_replaced" | null;

/**
 * Why the identity at chain position i is not currently valid, or null. An
 * agent needs a currently valid parent; a human needs its parent to have been
 * valid when the human was registered.
 */
function invalidity(snapshot: Snapshot, certificates: IdCertificate[], i: number): Invalidity {
  const certificate = certificates[i];
  if (isRegistered(certificate)) {
    const identity = snapshot.identities.get(certificate.id)!;
    if (identity.revocation) return "revoked";
    if (identity.head.registeredAt < snapshot.replacedAt) return "root_replaced";
  }
  if (i === 0) return null;
  if (certificate.kind === "agent") return invalidity(snapshot, certificates, i - 1);
  const registeredAt = snapshot.identities.get(certificate.id)!.head.registeredAt;
  return invalidityAt(snapshot, certificates[i - 1].id, registeredAt, ID_CHAIN_MAX_CERTIFICATES);
}

/**
 * Why a registered human parent was not valid at time `at`, or null: its
 * certificate revision in force then, any revocation cutoff strictly after
 * `at`, the latest namespace replacement, and the same rule repeated through
 * its own historical human parent.
 */
function invalidityAt(snapshot: Snapshot, id: string, at: string, depth: number): Invalidity {
  const identity = snapshot.identities.get(id);
  if (!identity || depth === 0) throw new Refusal("evidence_unavailable");
  const revision = identity.revisions.find(r => r.registeredAt < at && (r.supersededAt === null || r.supersededAt > at));
  if (!revision) throw new Refusal("evidence_unavailable");
  // Registration exactly at the cutoff is not before it.
  if (identity.revocation && identity.revocation.effectiveFrom <= at) return "revoked";
  // Surviving an ordinary revocation does not cross a namespace replacement.
  if (revision.registeredAt < snapshot.replacedAt) return "root_replaced";
  const { parent } = revision.certificate;
  const parentId = parent.kind === "identity" ? parent.id : null;
  if (witnessedIssuerKey(snapshot, parentId, revision) !== revision.certificate.issuer_key) {
    throw new Refusal("evidence_unavailable");
  }
  if (parentId === null) return null;
  if (snapshot.identities.get(parentId)?.revisions[0].certificate.kind !== "human") throw new Refusal("human_issuer_is_agent");
  return invalidityAt(snapshot, parentId, revision.registeredAt, depth - 1);
}

function isTimestamp(value: unknown): value is string {
  return typeof value === "string" && MICROSECOND_TIMESTAMP.test(value);
}

function isPositiveInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0;
}

export type IdDisposition = "continue" | "refuse";

/** What the request does with a verification result: the same on all five lanes. */
export interface IdRequestDisposition {
  ordinary: IdDisposition;
  human_required: IdDisposition;
}

/**
 * Section 5's disposition table. Ordinary admission (signatures, membership,
 * grant scope, audience) must already have passed; this never replaces it. A
 * local did:key leaf with stale or unavailable ancestry keeps ordinary work,
 * as omission would; the same result for an enrolled ID refuses.
 */
export function idRequestDisposition(result: IdVerification, subject: IdSubject, originalAuthPassed: boolean): IdRequestDisposition {
  if (!originalAuthPassed) return { ordinary: "refuse", human_required: "refuse" };
  const human_required: IdDisposition = result.outcome === "nearest_human" ? "continue" : "refuse";
  const localLeaf = !subject.id.startsWith("did:aw:");
  switch (result.reason) {
    case "verified":
    case "legacy_no_chain":
    case "unregistered_identity":
      return { ordinary: "continue", human_required };
    case "stale_issuer_key":
    case "status_expired":
    case "evidence_unavailable":
      return { ordinary: localLeaf ? "continue" : "refuse", human_required };
    default:
      return { ordinary: "refuse", human_required };
  }
}
