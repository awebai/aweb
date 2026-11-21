package main

// CLI integration refusal codes supplement the shared awid.ErrorDetail classes.
// Their messages remain independently useful to people; consumers use the code.
const (
	codeControllerKeyMissing    = "controller_key_missing"
	codeInviteNotCreated        = "invite_not_created"
	codeTeamNameTaken           = "team_name_taken"
	codeTeamNameUnconfirmed     = "team_name_unconfirmed"
	codeTeamServerRecordMissing = "team_server_record_missing"

	codeNativeAgentSignaturePending = "native_agent_signature_pending"
)
