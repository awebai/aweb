package main

import (
	"errors"
	"fmt"

	"github.com/awebai/aw/awid"
)

// identityRetainingFailure is supplied by the error owner after it has kept an
// attempted effect for reconciliation. It is a local error contract, never a
// server refusal code or permission to release an invitation.
type identityRetainingFailure interface {
	error
	RetainsIdentity() bool
}

func retainUnfinishedProvisioningIdentity(err error) bool {
	var retained identityRetainingFailure
	if errors.As(err, &retained) && retained.RetainsIdentity() {
		return true
	}
	var pending *hostedInviteSignaturePendingError
	var incomplete *provisionedMembershipIncompleteError
	return errors.As(err, &pending) || errors.As(err, &incomplete)
}

// retainedIdentityError carries the operation owner's retained-home decision
// without replacing its diagnostic, refusal code or transport cause.
type retainedIdentityError struct{ cause error }

func (err *retainedIdentityError) Error() string         { return err.cause.Error() }
func (err *retainedIdentityError) Unwrap() error         { return err.cause }
func (err *retainedIdentityError) RetainsIdentity() bool { return true }

func retainIdentityForRecovery(cause error) error {
	if cause == nil || retainUnfinishedProvisioningIdentity(cause) {
		return cause
	}
	return &retainedIdentityError{cause: cause}
}

func retainedIssuedIdentityStateFailure(cert *awid.TeamCertificate, cause error) error {
	return retainIdentityForRecovery(fmt.Errorf("save the local identity for issued membership certificate %s: %w; retain the identity home and repair its local state before resuming enrollment", cert.CertificateID, cause))
}
