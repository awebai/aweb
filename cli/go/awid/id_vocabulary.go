package awid

// IDRefusal is a stable ID-certificate or chain refusal/evidence code.
// Text and Go error wrapping do not change this machine-readable reason.
type IDRefusal string

const (
	IDRefusalBundleTooLarge         IDRefusal = "bundle_too_large"
	IDRefusalChainTooDeep           IDRefusal = "chain_too_deep"
	IDRefusalCycle                  IDRefusal = "cycle"
	IDRefusalDepthExceeded          IDRefusal = "depth_exceeded"
	IDRefusalDomainMismatch         IDRefusal = "domain_mismatch"
	IDRefusalDuplicateId            IDRefusal = "duplicate_id"
	IDRefusalEvidenceUnavailable    IDRefusal = "evidence_unavailable"
	IDRefusalHumanApprovalRequired  IDRefusal = "human_approval_required"
	IDRefusalHumanIssuerIsAgent     IDRefusal = "human_issuer_is_agent"
	IDRefusalInvalidDomain          IDRefusal = "invalid_domain"
	IDRefusalInvalidEncoding        IDRefusal = "invalid_encoding"
	IDRefusalInvalidJson            IDRefusal = "invalid_json"
	IDRefusalInvalidKind            IDRefusal = "invalid_kind"
	IDRefusalInvalidProof           IDRefusal = "invalid_proof"
	IDRefusalInvalidShape           IDRefusal = "invalid_shape"
	IDRefusalInvalidSignature       IDRefusal = "invalid_signature"
	IDRefusalInvitationConflict     IDRefusal = "invitation_conflict"
	IDRefusalInvitationModeMismatch IDRefusal = "invitation_mode_mismatch"
	IDRefusalIssuanceNotRecorded    IDRefusal = "issuance_not_recorded"
	IDRefusalIssuerKeyNotCurrent    IDRefusal = "issuer_key_not_current"
	IDRefusalLegacyNoChain          IDRefusal = "legacy_no_chain"
	IDRefusalMissingParent          IDRefusal = "missing_parent"
	IDRefusalNoncanonicalJson       IDRefusal = "noncanonical_json"
	IDRefusalParentRevoked          IDRefusal = "parent_revoked"
	IDRefusalRequestBindingMismatch IDRefusal = "request_binding_mismatch"
	IDRefusalRequestConflict        IDRefusal = "request_conflict"
	IDRefusalResignBindingMismatch  IDRefusal = "resign_binding_mismatch"
	IDRefusalRevoked                IDRefusal = "revoked"
	IDRefusalRootReplaced           IDRefusal = "root_replaced"
	IDRefusalStaleIssuerKey         IDRefusal = "stale_issuer_key"
	IDRefusalStatusExpired          IDRefusal = "status_expired"
	IDRefusalSubjectMismatch        IDRefusal = "subject_mismatch"
	IDRefusalSupersededCertificate  IDRefusal = "superseded_certificate"
	IDRefusalUnregisteredIdentity   IDRefusal = "unregistered_identity"
	IDRefusalUnregisteredParent     IDRefusal = "unregistered_parent"
)

// IDChainOutcome distinguishes valid ancestry, absent evidence and unavailable evidence.
type IDChainOutcome string

const (
	IDChainOutcomeUnknown      IDChainOutcome = "unknown"
	IDChainOutcomeUnavailable  IDChainOutcome = "unavailable"
	IDChainOutcomeNoHuman      IDChainOutcome = "no_human"
	IDChainOutcomeNearestHuman IDChainOutcome = "nearest_human"
)

// IDStatusFreshness describes whether a cached status may supply current facts.
type IDStatusFreshness string

const (
	IDStatusFresh       IDStatusFreshness = "fresh"
	IDStatusUnavailable IDStatusFreshness = "unavailable"
)

// IDRequestAction is an ID-chain policy result, not authentication on its own.
type IDRequestAction string

const (
	IDRequestContinue IDRequestAction = "continue"
	IDRequestRefuse   IDRequestAction = "refuse"
)

// IdentityScope is the declared local/global lifetime and addressability model.
// Released string-based configuration fields and IdentityMode constants remain adapters.
type IdentityScope string

const (
	IdentityScopeLocal  IdentityScope = IdentityModeLocal
	IdentityScopeGlobal IdentityScope = IdentityModeGlobal
)

// IdentityCustody identifies who can use an identity private key; it does not grant team authority.
type IdentityCustody string

const (
	IdentityCustodySelf   IdentityCustody = CustodySelf
	IdentityCustodyHosted IdentityCustody = CustodyCustodial
)

// IDRefusalCode reads the typed reason through wrapped released IDCertificateErrors.
func IDRefusalCode(err error) IDRefusal { return IDRefusal(IDCertificateErrorCode(err)) }
