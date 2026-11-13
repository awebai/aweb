package handoff

import (
	"time"

	"github.com/awebai/aw/awid"
)

// preparedArtifactMismatch binds a consumer's closed artifact to the retained
// typed request. It is called only after the common B2 digest and exact-request
// checks. A new codec never replaces those checks or selects signing bytes.
func preparedArtifactMismatch(sent map[string]any, artifact map[string]any) string {
	scope, _ := sent["scope"].(map[string]any)
	authority, _ := scope["authority"].(map[string]any)
	if sent["operation"] == "team.server-record.publish" {
		subject, _ := sent["subject"].(map[string]any)
		if sent["variant"] != "default" || authority["kind"] != "team_controller" ||
			!exactMembers(subject, []string{"server_url"}) ||
			!exactMembers(artifact, []string{"v", "type", "team_id", "team_did_key", "server_url", "issued_at"}) ||
			!sameJSON(artifact["v"], 1) || artifact["type"] != awid.TeamServerRecordType {
			return "its artifact is not a team server record"
		}
		team, _ := artifact["team_id"].(string)
		if team == "" || !sameJSON(team, authority["id"]) || !sameJSON(artifact["server_url"], subject["server_url"]) {
			return "its artifact names another team or server"
		}
		serverURL, _ := artifact["server_url"].(string)
		if _, _, err := awid.CanonicalTeamServerURL(serverURL); err != nil {
			return "its artifact names an invalid server URL"
		}
		key, _ := artifact["team_did_key"].(string)
		if _, err := awid.ExtractPublicKey(key); err != nil {
			return "its artifact names an invalid team key"
		}
		stamp, _ := artifact["issued_at"].(string)
		const layout = "2006-01-02T15:04:05Z"
		if issued, err := time.Parse(layout, stamp); err != nil || issued.Format(layout) != stamp {
			return "its artifact has an invalid issued_at"
		}
		return ""
	}
	// Preserve the released owner-act binding. The consumer's verifier remains
	// responsible for its signature and current authority before application.
	if artifact == nil || !exactMembers(artifact, artifactMembers) || artifact["type"] != "aweb.owner-act" {
		return "its artifact is not an owner act"
	}
	if !sameJSON(artifact["act"], sent["operation"]) || !sameJSON(artifact["team_id"], authority["id"]) {
		return "its artifact is for another act or team"
	}
	if !sameJSON(artifact["subject"], sent["subject"]) || !sameJSON(artifact["aud"], sent["audience"]) {
		return "its artifact names another subject or audience"
	}
	return ""
}
