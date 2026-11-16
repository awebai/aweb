package handoff

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"time"

	"github.com/awebai/aw/awid"
)

// AdmissionPolicyRead is a protected service's answer for one team
// (human-assurance-contract.md section 5): whether the team is protected or
// legacy, and the immutable admission policy that applies to it, or none.
type AdmissionPolicyRead struct {
	ServiceID string
	TeamID    string
	Mode      string
	// Policy is nil when the service has no policy for the team.
	Policy *AdmissionPolicy
}

// AdmissionPolicy is a team's immutable admission policy. An admission binds
// its version and digest; Fields is the complete policy as the service sent it.
type AdmissionPolicy struct {
	Version int64
	Digest  string
	Teams   []string
	Fields  map[string]any
}

var policyDigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// subjectKinds are the agent subjects a policy may admit, in code-point order.
var subjectKinds = []string{"local_agent", "registered_agent"}

// ReadAdmissionPolicy reads team's admission policy from the request origin
// as the restricted requester. An answer that cannot be read is unknown
// (receipt_unavailable), never an absent policy; a refusal keeps the
// service's code; an answer that is not exactly this service's and team's
// read is handoff_result_invalid.
func ReadAdmissionPolicy(ctx context.Context, opts GovernanceOptions, serviceID, team string) (*AdmissionPolicyRead, error) {
	reply, err := readPolicyAnswer(ctx, opts, team, AdmissionPolicyPath(team))
	if err != nil {
		return nil, err
	}
	read, ok := decodeAdmissionPolicyRead(reply, serviceID, team)
	if !ok {
		return nil, invalidResult(fmt.Errorf("the answer is not team %s's admission policy", team))
	}
	return read, nil
}

// ReadAdmissionCounts reads this root's own admissions to team against its
// policy's bounds: the same read, asking for counts with include=admissions.
// A root the service has not endorsed has none (nil). A service that
// predates counts refuses the query, keeping its code.
func ReadAdmissionCounts(ctx context.Context, opts GovernanceOptions, serviceID, team string) (*AdmissionCounts, error) {
	reply, err := readPolicyAnswer(ctx, opts, team, AdmissionPolicyPath(team)+"&include=admissions")
	if err != nil {
		return nil, err
	}
	invalid := invalidResult(fmt.Errorf("the answer is not team %s's admission counts", team))
	answer, ok := decodeObject(reply)
	if !ok || !exactMembers(answer, []string{"service_id", "team_id", "mode", "policy", "admissions"}) {
		return nil, invalid
	}
	admissions := answer["admissions"]
	delete(answer, "admissions")
	plain, err := json.Marshal(answer)
	if err != nil {
		return nil, invalid
	}
	read, ok := decodeAdmissionPolicyRead(plain, serviceID, team)
	if !ok {
		return nil, invalid
	}
	if admissions == nil {
		return nil, nil
	}
	fields, _ := admissions.(map[string]any)
	if read.Policy == nil || !exactMembers(fields, []string{"active", "in_window", "next_at"}) {
		return nil, invalid
	}
	active, okActive := nonNegativeInteger(fields["active"])
	inWindow, okWindow := nonNegativeInteger(fields["in_window"])
	if !okActive || !okWindow {
		return nil, invalid
	}
	bounds := read.Policy.Fields["bounds"].(map[string]any)
	maxActive, _ := positiveInteger(bounds["max_active"])
	maxPerWindow, _ := positiveInteger(bounds["max_per_window"])
	window, _ := positiveInteger(bounds["rate_window_seconds"])
	counts := &AdmissionCounts{Active: int(active), MaxActive: int(maxActive), InWindow: int(inWindow),
		MaxPerWindow: int(maxPerWindow), WindowSeconds: int(window)}
	if next := fields["next_at"]; next != nil {
		text, _ := next.(string)
		at, err := time.Parse(time.RFC3339Nano, text)
		if err != nil {
			return nil, invalid
		}
		counts.NextAt = at.UTC()
	}
	return counts, nil
}

// readPolicyAnswer GETs a policy read at path. An answer that cannot be read
// is unknown (receipt_unavailable), never an absent policy; a refusal keeps
// the service's code.
func readPolicyAnswer(ctx context.Context, opts GovernanceOptions, team, path string) ([]byte, error) {
	target, err := url.Parse(opts.Request + path)
	if err != nil {
		return nil, err
	}
	unavailable := func(err error) error {
		return coded("receipt_unavailable", fmt.Errorf("the admission policy of team %s could not be read: %w", team, err))
	}
	resp, err := opts.Sign(ctx, http.MethodGet, target, nil)
	if ErrorCode(err) != "" {
		// Refused before anything was sent.
		return nil, err
	}
	if err != nil {
		return nil, unavailable(err)
	}
	reply, err := readReply(resp)
	if err != nil {
		return nil, unavailable(err)
	}
	switch {
	case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
		return nil, hinted(unavailable(refusal(resp.StatusCode, reply)), resp)
	case resp.StatusCode != http.StatusOK:
		return nil, refusal(resp.StatusCode, reply)
	}
	return reply, nil
}

// nonNegativeInteger is a safe integer of at least zero.
func nonNegativeInteger(value any) (int64, bool) {
	if number, ok := value.(json.Number); ok && string(number) == "0" {
		return 0, true
	}
	return positiveInteger(value)
}

func decodeAdmissionPolicyRead(raw []byte, serviceID, team string) (*AdmissionPolicyRead, bool) {
	answer, ok := decodeObject(raw)
	if !ok || !exactMembers(answer, []string{"service_id", "team_id", "mode", "policy"}) {
		return nil, false
	}
	read := &AdmissionPolicyRead{}
	read.ServiceID, _ = answer["service_id"].(string)
	read.TeamID, _ = answer["team_id"].(string)
	read.Mode, _ = answer["mode"].(string)
	if read.ServiceID != serviceID || read.TeamID != team || (read.Mode != "protected" && read.Mode != "legacy") {
		return nil, false
	}
	if answer["policy"] == nil {
		return read, true
	}
	fields, ok := answer["policy"].(map[string]any)
	if !ok {
		return nil, false
	}
	read.Policy, ok = decodeAdmissionPolicy(fields, serviceID, team)
	return read, ok
}

// decodeAdmissionPolicy accepts exactly the contract's policy for team at
// serviceID, whose digest is its own: SHA-256 over "aweb.admission-policy/1",
// LF and the canonical policy without its digest.
func decodeAdmissionPolicy(fields map[string]any, serviceID, team string) (*AdmissionPolicy, bool) {
	if !exactMembers(fields, []string{"version", "digest", "teams", "root_selector", "subject_kinds", "member_role", "bounds"}) {
		return nil, false
	}
	version, ok := positiveInteger(fields["version"])
	digest, _ := fields["digest"].(string)
	if !ok || !policyDigestPattern.MatchString(digest) || fields["member_role"] != "member" {
		return nil, false
	}
	teams, ok := orderedTexts(fields["teams"])
	if !ok || !slices.Contains(teams, team) {
		return nil, false
	}
	for _, listed := range teams {
		if domain, name, err := awid.ParseTeamID(listed); err != nil || name+":"+domain != listed {
			return nil, false
		}
	}
	selector, _ := fields["root_selector"].(map[string]any)
	if !exactMembers(selector, []string{"kind", "service_id"}) || selector["kind"] != "service_endorsed_root" || selector["service_id"] != serviceID {
		return nil, false
	}
	kinds, ok := orderedTexts(fields["subject_kinds"])
	if !ok {
		return nil, false
	}
	for _, kind := range kinds {
		if !slices.Contains(subjectKinds, kind) {
			return nil, false
		}
	}
	bounds, _ := fields["bounds"].(map[string]any)
	if !exactMembers(bounds, []string{"max_active", "rate_window_seconds", "max_per_window"}) {
		return nil, false
	}
	for _, bound := range bounds {
		if _, ok := positiveInteger(bound); !ok {
			return nil, false
		}
	}
	unsigned := maps.Clone(fields)
	delete(unsigned, "digest")
	canonical, err := awid.StrictCanonicalJSON(unsigned)
	if err != nil {
		return nil, false
	}
	sum := sha256.Sum256(append([]byte("aweb.admission-policy/1\n"), canonical...))
	if digest != "sha256:"+hex.EncodeToString(sum[:]) {
		return nil, false
	}
	return &AdmissionPolicy{Version: version, Digest: digest, Teams: teams, Fields: fields}, true
}

// orderedTexts is a nonempty list of distinct strings in code-point order.
func orderedTexts(value any) ([]string, bool) {
	items, _ := value.([]any)
	if len(items) == 0 {
		return nil, false
	}
	texts := make([]string, len(items))
	for i, item := range items {
		text, ok := item.(string)
		if !ok || (i > 0 && text <= texts[i-1]) {
			return nil, false
		}
		texts[i] = text
	}
	return texts, true
}

// errNoAdmissionPolicy is a protected team the service holds no policy for.
var errNoAdmissionPolicy = errors.New("the team is protected but the service holds no admission policy for it; the operator provisions or approves one")

// RequireAdmissionPolicy is read's policy, or admission_policy_missing for a
// protected team without one. A legacy team has no protected admission.
func (read *AdmissionPolicyRead) RequireAdmissionPolicy() (*AdmissionPolicy, error) {
	if read.Policy == nil && read.Mode == "protected" {
		return nil, coded("admission_policy_missing", errNoAdmissionPolicy)
	}
	return read.Policy, nil
}
