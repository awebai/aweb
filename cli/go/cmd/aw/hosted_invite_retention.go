package main

import "github.com/awebai/aw/awconfig"

type hostedInviteRecoveryFailure struct {
	Home     awconfig.IdentityHome
	Creation *hostedInviteCreation
	Cause    error
}

// retainHostedInviteRecoveryFailure keeps credentials needed for an interrupted
// acceptance or a retained successful answer (docs/identity.md:239-245). Only
// this operation's recovery evidence decides retention, never a service code.
func retainHostedInviteRecoveryFailure(input hostedInviteRecoveryFailure) error {
	if input.Cause == nil {
		return nil
	}
	// A later cleanup can fail after removing the journal and marker. The
	// retained response still requires this exact credential to finish setup.
	if input.Creation != nil && input.Creation.ResponseJSON != "" {
		return retainIdentityForRecovery(input.Cause)
	}
	path, err := awconfig.IdentityHomePath(input.Home, hostedInviteRecoveryFile)
	if err != nil {
		return retainIdentityForRecovery(input.Cause)
	}
	creation, err := loadHostedInviteCreation(path)
	if err != nil || creation != nil {
		return retainIdentityForRecovery(input.Cause)
	}
	present, err := (acceptanceMintedKey{Home: input.Home}).present()
	if err != nil || present {
		return retainIdentityForRecovery(input.Cause)
	}
	return input.Cause
}
