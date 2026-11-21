package main

import (
	"encoding/json"
	"errors"
	"os"

	"github.com/awebai/aw/awconfig"
)

const doctorCheckSignupRecovery = "local.signup.recovery_pending"

// runSignupRecoveryCheck reports only the journal's presence and next action.
// Its private signer and response credentials never enter doctor output.
func (r *doctorRunner) runSignupRecoveryCheck() {
	home := awconfig.IdentityHome{Root: r.identityHome}
	if home.Root == "" {
		home.Root = awconfig.WorktreeIdentityHome(r.workingDir)
	}
	record := awconfig.RecoveryFile{Home: home, Name: hostedSignupRecoveryFile}
	path, err := record.Path()
	if err != nil {
		r.add(localCheck(doctorCheckSignupRecovery, doctorStatusFail, nil, "Signup recovery path is invalid.", "Select the original identity home and retry.", nil))
		return
	}
	raw, err := record.ReadBounded(hostedSignupRecoveryLimit)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	action := "Run `aw init` in the original signup directory to finish. To discard local recovery, check whether signup created the account, then remove " + path + "; this does not delete that account."
	if err != nil {
		r.add(localCheck(doctorCheckSignupRecovery, doctorStatusFail, localPathTarget(path), "Signup recovery cannot be read; its state is unknown.", action, nil))
		return
	}
	var state hostedSignupRecovery
	if err := json.Unmarshal(raw, &state); err != nil {
		r.add(localCheck(doctorCheckSignupRecovery, doctorStatusFail, localPathTarget(path), "Signup recovery is malformed; retain it for reconciliation.", action, nil))
		return
	}
	if err := state.Validate(); err != nil {
		r.add(localCheck(doctorCheckSignupRecovery, doctorStatusFail, localPathTarget(path), "Signup recovery progress is unknown; retain it for reconciliation.", action, nil))
		return
	}
	r.add(localCheck(doctorCheckSignupRecovery, doctorStatusWarn, localPathTarget(path), "Signup recovery is retained; the original request or credential can finish this home.", action, nil))
}
