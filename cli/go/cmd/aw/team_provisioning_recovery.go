package main

import "errors"

func retainUnfinishedProvisioningIdentity(err error) bool {
	var pending *hostedInviteSignaturePendingError
	return errors.As(err, &pending)
}
