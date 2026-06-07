package awid

const (
	A2APublicationCodePublicationExistsDifferentDigest  = "a2a_publication_exists_different_digest"
	A2APublicationCodePublicationExistsDifferentGateway = "a2a_publication_exists_different_gateway"
	A2APublicationCodeDelegationMissing                 = "a2a_delegation_missing"
	A2APublicationCodeDelegationDigestMismatch          = "a2a_delegation_digest_mismatch"
	A2APublicationCodeDelegationExpired                 = "a2a_delegation_expired"
	A2APublicationCodeDelegationRevoked                 = "a2a_delegation_revoked"
	A2APublicationCodeCardDigestMismatch                = "a2a_card_digest_mismatch"
	A2APublicationCodeCardURLInvalid                    = "a2a_card_url_invalid"
	A2APublicationCodeRPCURLInvalid                     = "a2a_rpc_url_invalid"
	A2APublicationCodeRouteIDInvalid                    = "a2a_route_id_invalid"
	A2APublicationCodeIdentitySignatureInvalid          = "a2a_identity_signature_invalid"
	A2APublicationCodeDelegationSignatureInvalid        = "a2a_delegation_signature_invalid"
	A2APublicationCodeTimestampStale                    = "a2a_timestamp_stale"
	A2APublicationCodeNamespaceNotRegistered            = "a2a_namespace_not_registered"
	A2APublicationCodeAddressNotRegistered              = "a2a_address_not_registered"
	A2APublicationCodeCustodyCombinationUnsupported     = "a2a_custody_combination_unsupported"
	A2APublicationCodeAuthoritySourceInvalid            = "a2a_authority_source_invalid"
	A2APublicationCodePayloadCanonicalization           = "a2a_payload_canonicalization_mismatch"
	A2APublicationCodePrimitiveDisabled                 = "a2a_primitive_disabled"
	A2APublicationCodePrimitiveNotSupported             = "a2a_primitive_not_supported"
)

var A2APublicationConflictCodes = []string{
	A2APublicationCodePublicationExistsDifferentDigest,
	A2APublicationCodePublicationExistsDifferentGateway,
	A2APublicationCodeDelegationMissing,
	A2APublicationCodeDelegationDigestMismatch,
	A2APublicationCodeDelegationExpired,
	A2APublicationCodeDelegationRevoked,
	A2APublicationCodeCardDigestMismatch,
	A2APublicationCodeCardURLInvalid,
	A2APublicationCodeRPCURLInvalid,
	A2APublicationCodeRouteIDInvalid,
	A2APublicationCodeIdentitySignatureInvalid,
	A2APublicationCodeDelegationSignatureInvalid,
	A2APublicationCodeTimestampStale,
	A2APublicationCodeNamespaceNotRegistered,
	A2APublicationCodeAddressNotRegistered,
	A2APublicationCodeCustodyCombinationUnsupported,
	A2APublicationCodeAuthoritySourceInvalid,
	A2APublicationCodePayloadCanonicalization,
	A2APublicationCodePrimitiveDisabled,
	A2APublicationCodePrimitiveNotSupported,
}
