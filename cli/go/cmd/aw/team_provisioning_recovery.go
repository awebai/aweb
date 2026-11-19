package main

import "errors"

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
	if cause == nil {
		return nil
	}
	return &retainedIdentityError{cause: cause}
}
