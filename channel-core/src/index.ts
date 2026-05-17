export { APIClient, APIError, type APIClientAuth } from "./api/client.js";
export { streamAgentEvents, parseAgentEvent, type AgentEvent, type AgentEventType } from "./api/events.js";
export { ackMessage, fetchInbox, type InboxMessage } from "./api/mail.js";
export { fetchHistory, markRead, type ChatMessage } from "./api/chat.js";
export { resolveConfig, type AgentConfig } from "./config.js";
export { PinStore, type Pin, type PinResult } from "./identity/pinstore.js";
export { RegistryResolver, DEFAULT_AWID_REGISTRY_URL, type StableIdentityVerification } from "./identity/registry.js";
export { SenderTrustManager, type TrustResult, type RotationAnnouncement, type ReplacementAnnouncement } from "./identity/trust.js";
export { computeDIDKey, extractPublicKey } from "./identity/did.js";
export { loadSigningKey } from "./identity/keys.js";
export { loadTeamCertificate, encodeTeamCertificateHeader, type TeamCertificate } from "./identity/certificate.js";
export { verifyMessage, verifySignedPayload, type VerificationStatus } from "./identity/signing.js";
export {
  DEFAULT_PIN_STORE_PATH,
  createChannelClient,
  createRegistryResolver,
  dispatchAgentEvent,
  formatAwakeningForAgent,
  isTrustedVerificationStatus,
  loadPinStore,
  resolveRegistryFallbackURL,
  startChannelLoop,
  trustWarningLine,
  type ChannelAwakening,
  type ChannelAwakeningKind,
  type ChannelDeliveryIntent,
  type ChannelLoopOptions,
  type SelfIdentity,
} from "./channel.js";
