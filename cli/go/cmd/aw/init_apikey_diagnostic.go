package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
)

var workspaceInitRequestID = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// This is a display summary, not a transaction outcome or retry instruction.
// Do not echo arbitrary bodies, messages, unknown codes or request-ID text.
// Raw native output still needs protected operator capture outside this renderer.
// The code is a member of workspaceInitRefusalRemedies or "unknown".
func workspaceInitHTTPDiagnostic(resp *http.Response, body []byte, apiKey string) (diagnostic, code string) {
	type fields struct {
		Code      string `json:"code"`
		RequestID string `json:"request_id"`
		// A capacity refusal names its code in detail.error.
		Error string `json:"error"`
	}
	var envelope struct {
		fields
		Error  json.RawMessage `json:"error"`
		Detail json.RawMessage `json:"detail"`
	}
	code, requestID := "unknown", "unknown"
	var candidates, codes []string
	for name, values := range resp.Header {
		if strings.EqualFold(name, "X-Request-ID") {
			candidates = append(candidates, values...)
		}
	}
	// Struct decoding and Header.Get would discard duplicate/case-variant
	// evidence before comparison. Reject ambiguous JSON before decoding fields.
	ambiguousBody := json.Valid(body) && !workspaceInitUnambiguousJSON(body)
	if ambiguousBody {
		candidates = append(candidates, "ambiguous")
	}
	if !ambiguousBody && json.Unmarshal(body, &envelope) == nil {
		values := []fields{envelope.fields}
		// error and detail carry fields only as objects; a string or list
		// detail is server text, which is never shown.
		for _, nested := range []json.RawMessage{envelope.Error, envelope.Detail} {
			var value fields
			if json.Unmarshal(nested, &value) == nil {
				values = append(values, value)
			}
		}
		for _, value := range values {
			codes = append(codes, value.Code, value.Error)
			candidates = append(candidates, value.RequestID)
		}
	}
	// Fixed public vocabulary only. Unknown service codes remain private, and
	// codes that disagree leave the code unknown.
	for _, value := range codes {
		if value == "" {
			continue
		}
		if _, known := workspaceInitRefusalRemedies[value]; !known || (code != "unknown" && code != value) {
			code = "unknown"
			break
		}
		code = value
	}
	for _, value := range candidates {
		if value == "" {
			continue
		}
		if !workspaceInitRequestID.MatchString(value) || (apiKey != "" && strings.Contains(value, apiKey)) {
			requestID = "unknown"
			break
		}
		value = strings.ToLower(value)
		if requestID != "unknown" && requestID != value {
			requestID = "unknown"
			break
		}
		requestID = value
	}
	if apiKey != "" && strings.Contains(code, apiKey) {
		code = "unknown"
	}
	return fmt.Sprintf("category=hosted_http_failure status=%d error_code=%s request_id=%s (response body omitted; remote effects unknown)", resp.StatusCode, code, requestID), code
}

// Conservative display admission: duplicate object names (case-insensitive),
// including enclosing error/detail objects, make correlation metadata unknown.
// This does not change the service response or native bootstrap state contract.
func workspaceInitUnambiguousJSON(body []byte) bool {
	d := json.NewDecoder(bytes.NewReader(body))
	var value func(int) bool
	value = func(depth int) bool {
		if depth > 32 {
			return false
		}
		token, err := d.Token()
		if err != nil {
			return false
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return true
		}
		switch delimiter {
		case '{':
			var seen []string
			for d.More() {
				token, err := d.Token()
				if err != nil {
					return false
				}
				key, ok := token.(string)
				if !ok {
					return false
				}
				// encoding/json uses Unicode simple folding for struct fields,
				// not lowercasing (for example long s also matches ASCII s).
				for _, prior := range seen {
					if strings.EqualFold(prior, key) {
						return false
					}
				}
				seen = append(seen, key)
				if !value(depth + 1) {
					return false
				}
			}
			end, err := d.Token()
			return err == nil && end == json.Delim('}')
		case '[':
			for d.More() {
				if !value(depth + 1) {
					return false
				}
			}
			end, err := d.Token()
			return err == nil && end == json.Delim(']')
		default:
			return false
		}
	}
	if !value(0) {
		return false
	}
	_, err := d.Token()
	return err == io.EOF
}

// workspaceInitRefusal is what aw tells the caller about one coded refusal.
type workspaceInitRefusal struct {
	remedy string
	// changesContext is set when the remedy needs a different bootstrap
	// context (name, key, scope or setup command), which this attempt's
	// partial state refuses in its directory.
	changesContext bool
}

// workspaceInitRefusalRemedies is the public vocabulary of coded refusals of
// POST /api/v1/workspaces/init that aw shows, each with what the caller can
// do. The server's own messages are never shown.
var workspaceInitRefusalRemedies = map[string]workspaceInitRefusal{
	"INTERNAL_ERROR":                     {"The service failed. Retry; if it repeats, report it with the request ID.", false},
	"agent_limit_reached":                {"The team is at its plan's agent limit. Remove an agent or upgrade the plan, then retry.", false},
	"awid_certificate_conflict":          {"The registry refused the member certificate. Retry; if it repeats, contact support with the request ID.", false},
	"awid_namespace_controller_diverged": {"The organisation namespace has another controller at the registry. Choose a different namespace, or contact support.", true},
	"awid_refused":                       {"The registry is limiting requests. Retry in a few minutes.", false},
	"awid_team_controller_diverged":      {"The team has another controller at the registry. Contact support.", false},
	"awid_unavailable":                   {"The registry did not answer in time. Retry in a few seconds.", false},
	"certificate_generation_stale":       {"This identity's certificate is stale and needs its key's proof. Run aw init on the machine that holds the agent's key.", true},
	"certificate_projection_conflict":    {"The member or its certificate changed during the request. Retry; if it repeats, contact support.", false},
	"certificate_repair_pending":         {"A certificate repair is not yet confirmed. Retry before using this identity.", false},
	"creation_invitation_consumed":       {"This setup command was already used. Generate a new setup command in the dashboard.", true},
	"creation_invitation_mismatch":       {"The request does not match its setup command, or the command expired. Run the exact command as generated, or generate a new one.", true},
	"creator_human_root_replaced":        {"The issuing person's namespace root was replaced. Contact support.", false},
	"creator_must_sign":                  {"An agent's own key cannot create an organisation-root identity. A person with team role editor or higher must generate a setup command in the dashboard and run init with that setup key.", true},
	"custodial_reinit_forbidden":         {"The name belongs to an existing custodial agent. Run init with that workspace's own key, or choose a new name.", true},
	"hosted_removal_pending":             {"The workspace bound to this key is being removed. Wait for or cancel the removal, then run init again.", false},
	"human_chain_required":               {"The person who issued this command has not completed identity registration. They complete it, then generate a new command.", true},
	"human_identity_reinit_forbidden":    {"The name is a person's identity. Choose another name.", true},
	"id_authority_refused":               {"The person's public identity chain was refused. Contact support.", false},
	"id_child_binding_mismatch":          {"The signed request does not match the identity being created. Retry; if it repeats, report it.", false},
	"id_evidence_unavailable":            {"Registry evidence for the identity chain is unavailable. Retry.", false},
	"id_issuer_changed":                  {"The issuing key changed during the request. Retry.", false},
	"id_issuer_unavailable":              {"The namespace issuer is unavailable. Retry later; if it persists, contact support.", false},
	"id_parent_mismatch":                 {"The identity's parent is not this team's namespace or person; the team or its organisation may have changed. Generate a new setup command and run it.", true},
	"identity_key_mismatch":              {"The name is bound to a different identity key. Choose a new name, or run init on the machine that holds the original key.", true},
	"identity_scope_mismatch":            {"The name exists with the other identity scope (global or local). Use its existing scope, or choose a new name.", true},
	"invalid_creation_intent":            {"The name is not in its exact canonical form. Use the name exactly as the setup command gives it.", true},
	"invalid_id_tree_request":            {"The service did not accept this aw's identity request. Upgrade aw and retry.", false},
	"not_allowed":                        {"The person who generated this command can no longer add agents. Ask a team editor, admin or owner to generate the command.", true},
	"not_cloud_controlled":               {"This team's own controller manages its certificates, not the hosted service. Add the agent through the team's controller.", true},
	"personal_team_binding_unavailable":  {"The personal team's binding is inconsistent. Contact support.", false},
	"registry_unavailable":               {"The service has no registry available. Retry later.", false},
	"request_conflict":                   {"The request was already used for a different identity, or the identity already exists. Check the team for the identity before creating it again.", true},
	"self_custody_reinit_unproven":       {"The name belongs to a self-custody agent and no proof of its key was sent. Run init on the machine that holds that key, or choose a new name.", true},
	"team_server_configuration_invalid":  {"The hosted service is misconfigured. Retry later; this is an operator issue.", false},
	"validation_error":                   {"The service refused the identity request as invalid. Check the name and options; upgrade aw if it repeats.", true},
}

// partialInitGuidance is what to do with the partial state a failed attempt
// left in its directory. A refusal whose remedy changes the bootstrap context
// cannot be followed there, since the partial state refuses another context.
func partialInitGuidance(err error) string {
	if refusal, known := workspaceInitRefusalRemedies[errorCodeOf(err)]; known && refusal.changesContext {
		return "this attempt's state stays in .aw/partial-init.yaml (do not delete it); run the changed command in a new directory."
	}
	return "rerun the same command in this directory; do not delete .aw/partial-init.yaml"
}
