export { APIClient, APIError, type APIClientAuth } from "./api/client.js";
export { streamAgentEvents, parseAgentEvent, formatEventStreamState, streamErrorCause, type AgentEvent, type AgentEventType, type EventStreamState } from "./api/events.js";
export { ackMessage, fetchInbox, type InboxMessage } from "./api/mail.js";
export { fetchHistory, markRead, type ChatMessage } from "./api/chat.js";
export { resolveConfig, type AgentConfig } from "./config.js";
export { PinStore, type IdentityScope, type Pin, type PinResult, type PinStoreWriter } from "./identity/pinstore.js";
export { RegistryResolver, DEFAULT_AWID_REGISTRY_URL, type StableIdentityVerification } from "./identity/registry.js";
export { SenderTrustManager, canonicalReplacementJSON, canonicalRotationJSON, normalizeIdentityScope, type TrustResult, type RotationAnnouncement, type ReplacementAnnouncement } from "./identity/trust.js";
export { computeDIDKey, extractPublicKey } from "./identity/did.js";
export { CHANNEL_CORE_SECURITY_CONTRACT } from "./contract.js";
export { loadSigningKey } from "./identity/keys.js";
export { certificateIdentityScope, loadTeamCertificate, encodeTeamCertificateHeader, type CertificateIdentityScope, type LegacyCertificateLifetime, type TeamCertificate } from "./identity/certificate.js";
export { verifyMessage, verifySignedPayload, type VerificationStatus } from "./identity/signing.js";
export {
  createLocalAWDecryptProvider,
  createLocalAWPinStoreWriter,
  type LocalAWDecryptOptions,
  type LocalAWPinStoreOptions,
  type LocalDecryptProvider,
} from "./local_aw.js";
export {
  DEFAULT_DELIVERY_STORE_PATH,
  DEFAULT_PIN_STORE_PATH,
  createChannelClient,
  consumeAgentEvents,
  DeliveryStore,
  createRegistryResolver,
  dispatchAgentEvent,
  formatAwakeningForAgent,
  isTrustedVerificationStatus,
  loadPinStore,
  loadSessionPinStore,
  resolveRegistryFallbackURL,
  startChannelLoop,
  trustWarningLine,
  type ChannelAwakening,
  type ChannelAwakeningKind,
  type ChannelDeliveryIntent,
  type ChannelLoopOptions,
  type SelfIdentity,
} from "./channel.js";
