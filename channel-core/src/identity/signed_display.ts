// A signature covers the signed payload. What a reader is shown comes from
// separate fields of the response, so those fields are compared with the
// signed claims before a message is reported verified. The rules are the Go
// client's (cli/go/awid/signed_payload.go), so both clients agree.

export type DisplayedFields = Readonly<Record<string, string | undefined>>;

/** Who is reading: their current did:key and their did:aw, each empty when unknown. */
export interface ReaderIdentity {
  did: string;
  stableID: string;
}

function claims(signedPayload: string): Record<string, unknown> | null {
  try {
    const parsed: unknown = JSON.parse(signedPayload);
    return parsed !== null && typeof parsed === "object" && !Array.isArray(parsed)
      ? parsed as Record<string, unknown>
      : null;
  } catch {
    return null;
  }
}

/** Whether every displayed field is exactly the signed claim of the same name. */
export function signedClaimsEqual(signedPayload: string, displayed: DisplayedFields): boolean {
  const signed = claims(signedPayload);
  if (!signed) return false;
  return Object.entries(displayed).every(([name, shown]) => signed[name] === shown);
}

/**
 * Whether the displayed fields agree with the signed claims of a message that
 * may predate some of them. A field the sender did not sign is not a claim; a
 * signed field must be a string and match. A displayed did:aw may stand for
 * the signed did:key of the same side when the sender also signed that did:aw.
 */
export function signedDisplayMatches(signedPayload: string, displayed: DisplayedFields): boolean {
  const signed = claims(signedPayload);
  return signed !== null && everyClaimMatches(signed, displayed);
}

/**
 * signedDisplayMatches for mail read by its recipient. A sender that could not
 * resolve the recipient's key signs an empty to_did and no to_stable_id; the
 * displayed recipient may then be this reader, whom the read authenticated.
 */
export function signedMailDisplayMatches(
  signedPayload: string,
  displayed: DisplayedFields,
  reader: ReaderIdentity,
): boolean {
  const signed = claims(signedPayload);
  if (!signed) return false;
  const recipient = displayed.to_did ?? "";
  const readerIsRecipient = recipient !== "" && (recipient === reader.did || recipient === reader.stableID);
  if (readerIsRecipient && signed.to_did === "" && !("to_stable_id" in signed)) {
    const { to_did: _recipient, ...rest } = displayed;
    return everyClaimMatches(signed, rest);
  }
  return everyClaimMatches(signed, displayed);
}

function everyClaimMatches(signed: Record<string, unknown>, displayed: DisplayedFields): boolean {
  for (const [name, shown = ""] of Object.entries(displayed)) {
    if (!(name in signed)) continue;
    const claim = signed[name];
    if (typeof claim !== "string") return false;
    if (claim === shown) continue;
    if (stableIdentityStandsFor(signed, name, shown, claim, displayed)) continue;
    return false;
  }
  return true;
}

function stableIdentityStandsFor(
  signed: Record<string, unknown>,
  name: string,
  shown: string,
  claim: string,
  displayed: DisplayedFields,
): boolean {
  if (name !== "from_did" && name !== "to_did") return false;
  if (!shown.startsWith("did:aw:")) return false;
  const stable = signed[name === "from_did" ? "from_stable_id" : "to_stable_id"];
  if (claim.startsWith("did:key:")) return stable === shown;
  // A continuation over a stored route signs the stable recipient without
  // resolving its current key, within one signed conversation.
  return name === "to_did" && claim === "" && stable === shown
    && typeof signed.conversation_id === "string" && signed.conversation_id !== ""
    && signed.conversation_id === (displayed.conversation_id ?? "");
}
