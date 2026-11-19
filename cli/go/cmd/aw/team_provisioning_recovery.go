package main

import "errors"

func retainUnfinishedProvisioningIdentity(err error) bool {
	var pending *hostedInviteSignaturePendingError
	var incomplete *provisionedMembershipIncompleteError
	return errors.As(err, &pending) || errors.As(err, &incomplete)
}
