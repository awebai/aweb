package appmanifest

import (
	"encoding/json"
	"strings"
	"testing"
)

// secretsSessionActions is the corpus's valid session_actions_of_secrets
// owner_acts, decoded for editing.
func secretsSessionActions(t *testing.T) map[string]any {
	t.Helper()
	for _, tc := range ownerActManifestCases(t) {
		if tc.Name != "session_actions_of_secrets" {
			continue
		}
		var ownerActs map[string]any
		if err := json.Unmarshal(tc.OwnerActs, &ownerActs); err != nil {
			t.Fatal(err)
		}
		return ownerActs
	}
	t.Fatal("no session_actions_of_secrets case")
	return nil
}

func sessionActionCaseLoad(t *testing.T, edit func(ownerActs map[string]any, actions []any)) error {
	t.Helper()
	ownerActs := secretsSessionActions(t)
	edit(ownerActs, ownerActs["session_actions"].([]any))
	raw, err := json.Marshal(ownerActs)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Load(ownerActCaseManifest(t, "https://secrets.example.com", raw), nil)
	return err
}

func action(actions []any, name string) map[string]any {
	for _, item := range actions {
		if a := item.(map[string]any); a["name"] == name {
			return a
		}
	}
	panic("no action " + name)
}

func TestSessionActionsOfSecretsAreTheBaseOfTheseCases(t *testing.T) {
	if err := sessionActionCaseLoad(t, func(map[string]any, []any) {}); err != nil {
		t.Fatalf("Load: %v", err)
	}
}

func TestSessionActionsRefuseWhatTheCorpusDoesNotPin(t *testing.T) {
	for name, edit := range map[string]func(map[string]any, []any){
		"a repeated action name": func(o map[string]any, actions []any) {
			copied := map[string]any{}
			for k, v := range action(actions, "onepassword-token") {
				copied[k] = v
			}
			o["session_actions"] = append(actions, copied)
		},
		"a read with a body param and no body member": func(o map[string]any, actions []any) {
			read := action(actions, "change-set")
			read["params"] = append(read["params"].([]any), map[string]any{"name": "note", "in": "body"})
			read["input_schema"].(map[string]any)["properties"].(map[string]any)["note"] = map[string]any{"type": "string"}
			// The confirm declares the same input, so only the read's own rule refuses it.
			confirm := action(actions, "confirm")
			confirm["params"] = append(confirm["params"].([]any), map[string]any{"name": "note", "in": "body"})
			confirm["input_schema"].(map[string]any)["properties"].(map[string]any)["note"] = map[string]any{"type": "string"}
		},
		"a read that is a POST": func(o map[string]any, actions []any) {
			action(actions, "change-set")["method"] = "POST"
		},
		"a stage with a raw body": func(o map[string]any, actions []any) {
			action(actions, "onepassword-token")["body"] = map[string]any{"mode": "raw", "raw_param": "value", "content_type": "text/plain"}
		},
		"a completion read of another role": func(o map[string]any, actions []any) {
			o["roles"] = append(o["roles"].([]any), map[string]any{
				"name": "secrets.auditor", "label": "Auditor", "acts": []any{"human-role.designate"}, "notice_contact": false,
			})
			action(actions, "change-set")["role"] = "secrets.auditor"
		},
		"a percent-encoded path": func(o map[string]any, actions []any) {
			action(actions, "change-set")["path"] = "/installations/{installation_id}/change-sets/{change_id}/%2e"
		},
		"a predicate value that is a decimal integer spelling": func(o map[string]any, actions []any) {
			confirm := action(actions, "confirm")
			confirm["completion"].(map[string]any)["ready"] = map[string]any{"member": "can_confirm", "in": []any{json.Number("1.0")}}
		},
		"an action key in another case": func(o map[string]any, actions []any) {
			a := action(actions, "change-set")
			a["Kind"] = a["kind"]
			delete(a, "kind")
		},
		"a param key in another case": func(o map[string]any, actions []any) {
			param := action(actions, "onepassword-token")["params"].([]any)[1].(map[string]any)
			param["Protected"] = param["protected"]
			delete(param, "protected")
		},
		"a completion key in another case": func(o map[string]any, actions []any) {
			completion := action(actions, "confirm")["completion"].(map[string]any)
			completion["Ready"] = completion["ready"]
			delete(completion, "ready")
		},
		"a predicate key in another case": func(o map[string]any, actions []any) {
			completion := action(actions, "confirm")["completion"].(map[string]any)
			completion["ready"] = map[string]any{"Member": "can_confirm", "in": []any{true}}
		},
		"a body key in another case": func(o map[string]any, actions []any) {
			action(actions, "onepassword-token")["body"] = map[string]any{"Mode": "json"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			err := sessionActionCaseLoad(t, edit)
			if code := ErrorCode(err); code != CodeOwnerActsInvalid {
				t.Fatalf("code %q, err %v", code, err)
			}
		})
	}
}

func TestSessionActionsSeeTheValuesVersion2ValidationNormalizes(t *testing.T) {
	err := sessionActionCaseLoad(t, func(o map[string]any, actions []any) {
		action(actions, "change-set")["method"] = " get "
		action(actions, "confirm")["method"] = "post"
		action(actions, "onepassword-token")["params"].([]any)[1].(map[string]any)["in"] = " body"
		action(actions, "change-set")["params"].([]any)[0].(map[string]any)["in"] = "path "
		// An absent body is mode json, as it is for any version 2 tool.
		delete(action(actions, "onepassword-token"), "body")
		action(actions, "confirm")["body"] = map[string]any{"mode": " json "}
	})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
}

func TestSessionActionsResolveIntoOwnerActs(t *testing.T) {
	ownerActs := secretsSessionActions(t)
	raw, _ := json.Marshal(ownerActs)
	resolved, err := Load(ownerActCaseManifest(t, "https://secrets.example.com", raw), nil)
	if err != nil {
		t.Fatal(err)
	}
	actions := resolved.OwnerActs.SessionActions
	if len(actions) != 3 || actions[2].Kind != SessionActionConfirm || actions[2].Completion.Read != "change-set" {
		t.Fatalf("actions %#v", actions)
	}
	if !strings.HasPrefix(actions[2].TerminalOutput[0], "/runner_registrations/") {
		t.Fatalf("terminal_output %#v", actions[2].TerminalOutput)
	}
	if p := actions[1].Params[1]; p.Protected == nil || !*p.Protected {
		t.Fatalf("protected param %#v", p)
	}
}
