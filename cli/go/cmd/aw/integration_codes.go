package main

// CLI integration refusal codes supplement the shared awid.ErrorDetail classes.
// Their messages remain independently useful to people; consumers use the code.
const (
	codeControllerKeyMissing    = "controller_key_missing"
	codeInviteNotCreated        = "invite_not_created"
	codeTeamNameTaken           = "team_name_taken"
	codeTeamServerRecordMissing = "team_server_record_missing"
)
