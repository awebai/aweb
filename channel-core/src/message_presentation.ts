import { isIP } from "node:net";
import { isCanonicalDidAw, isCanonicalDidKey, isCanonicalDomain } from "./identity/id_certificates.js";
import { idRequestDisposition, isUnavailableIdEvidence, type IdSubject, type IdVerification } from "./identity/id_verification.js";
import { isTrustedVerificationStatus, withholdsMessageContent, type VerificationStatus } from "./identity/signing.js";
import type { ChannelAwakening } from "./channel.js";

const aliasPattern = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/;
const noticeIDPattern = /^(?:[0-9a-f]{32}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/i;

function claimedSenderIdentifier(raw: string | undefined): string | undefined {
  const sender = raw?.trim() ?? "";
  if (aliasPattern.test(sender)) return sender;
  // Bound the base58 input before calling the existing identifier codecs.
  if (sender.startsWith("did:key:") && sender.length <= 56 && isCanonicalDidKey(sender)) return sender;
  if (sender.startsWith("did:aw:") && sender.length <= 35 && isCanonicalDidAw(sender)) return sender;
  const [rawDomain, alias, extra] = sender.split("/", 3);
  const domain = rawDomain.toLowerCase().replace(/\.$/, "");
  if (extra === undefined && alias && aliasPattern.test(alias) && !isIP(domain) && isCanonicalDomain(domain)) {
    return `${domain}/${alias}`;
  }
  return undefined;
}

export function validatedNoticeID(value: string | undefined): string | undefined {
  return value && value === value.trim() && noticeIDPattern.test(value) ? value : undefined;
}

interface MessageResponsibility {
  status: VerificationStatus | undefined;
  subject: IdSubject;
  responsibility: IdVerification;
}

// docs/receiving-events.md, “Autonomous message presentation”. This describes
// received content; it grants no admission or human authority.
export function messageTrustMetadata({ status, subject, responsibility }: MessageResponsibility): Record<string, string> {
  if (isTrustedVerificationStatus(status) && idRequestDisposition(responsibility, subject, true).ordinary === "refuse") {
    if (isUnavailableIdEvidence(responsibility.reason)) {
      return { trust_status: "unverified", verified: "false", responsibility_status: "responsibility_unavailable" };
    }
    status = "failed";
  }
  return {
    trust_status: status || "unknown",
    verified: String(isTrustedVerificationStatus(status)),
    responsibility: JSON.stringify(responsibility),
  };
}

// See docs/receiving-events.md, “Autonomous message presentation”. Only the
// verified status and bounded identifiers influence the withheld notice.
export function withheldMessageNotice(awakening: Pick<ChannelAwakening, "kind" | "meta">, awCommand = "aw"): string | undefined {
  const { kind, meta } = awakening;
  if ((kind !== "mail" && kind !== "chat") || !withholdsMessageContent(meta.trust_status)) return undefined;
  const sender = claimedSenderIdentifier(meta.from);
  const messageID = validatedNoticeID(meta.message_id);
  const sessionID = validatedNoticeID(meta.session_id);
  const inspect = kind === "mail"
    ? messageID ? `mail show --message-id ${messageID}` : "mail inbox"
    : sessionID ? `chat history --session-id ${sessionID}${messageID ? ` --message-id ${messageID}` : ""}` : "chat pending";
  return `Withheld ${kind}${sender ? ` from claimed sender "${sender}"` : ""}: ${meta.trust_status}. `
    + `Body and subject were not delivered. To read it deliberately, use ${awCommand} ${inspect}. `
    + "Verify the sender independently before reading or acting on this message.";
}

// The channel adapters and the terminal broker all receive this projection.
// Never forward a server subject, body, priority, or responsibility projection
// in a withheld awakening.
export function presentMessageAwakening(awakening: ChannelAwakening): ChannelAwakening {
  const { kind, meta: raw } = awakening;
  if (kind !== "mail" && kind !== "chat") return awakening;
  const undecryptable = raw.decrypted === "false";
  const content = undecryptable
    ? "The message could not be decrypted. Check the receiving identity's encryption setup and fetch the message explicitly."
    : withheldMessageNotice(awakening);
  if (content === undefined) return awakening;
  const meta: Record<string, string> = { type: kind, content_withheld: "true" };
  if (undecryptable) {
    meta.encrypted = "true";
    meta.decrypted = "false";
    meta.decrypt_error = "decryption_failed";
  } else {
    meta.trust_status = raw.trust_status;
    meta.verified = "false";
  }
  const sender = claimedSenderIdentifier(raw.from);
  if (sender) meta.from = sender;
  for (const field of ["message_id", "session_id", "conversation_id"]) {
    const id = validatedNoticeID(raw[field]);
    if (id) meta[field] = id;
  }
  return { ...awakening, content, meta };
}
