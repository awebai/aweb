package awid

// IDInvitationRequestStore optionally indexes a received request without listing
// the issuer's invitation history. IDInvitationStore remains the released port;
// existing implementations need not add this capability.
type IDInvitationRequestStore interface {
	InvitationForRequest(requestID string) (*IDInvitation, error)
}

// FindIDInvitationForRequest returns a received request's invitation, or nil.
// docs/id-certificates.md:1275-1282 requires request IDs to be unambiguous across
// an issuer. An indexed store enforces that rule on write; older stores retain
// the listing fallback. Errors from either store are never absence.
func FindIDInvitationForRequest(store IDInvitationStore, requestID string) (*IDInvitation, error) {
	if indexed, ok := store.(IDInvitationRequestStore); ok {
		return indexed.InvitationForRequest(requestID)
	}
	all, err := store.Invitations()
	if err != nil {
		return nil, err
	}
	var found *IDInvitation
	for _, inv := range all {
		if inv.Request == nil || inv.Request.RequestID != requestID {
			continue
		}
		if found != nil && found.InvitationID != inv.InvitationID {
			return nil, idCertificateRefusal(IDRefusalRequestConflict)
		}
		found = inv
	}
	return found, nil
}
