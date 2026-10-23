package main

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/awebai/aw/awid"
	"github.com/awebai/aw/internal/appmanifest"
)

func secretsRunManifest(t *testing.T) (*appmanifest.Resolved, *appmanifest.Tool) {
	t.Helper()
	data, err := os.ReadFile("../../../../naapp/secrets/src/aweb_secrets/aweb-app.json")
	if err != nil {
		t.Fatal(err)
	}
	// The committed v2 template declares key slots. A deployment supplies their
	// public keys; keep all tool/context fields from the committed artifact.
	var template map[string]any
	if err := json.Unmarshal(data, &template); err != nil {
		t.Fatal(err)
	}
	for _, entry := range template["app_keys"].([]any) {
		public, _, err := awid.GenerateKeypair()
		if err != nil {
			t.Fatal(err)
		}
		entry.(map[string]any)["did_key"] = awid.ComputeDIDKey(public)
	}
	data, err = json.Marshal(template)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := appmanifest.Load(data, nil)
	if err != nil {
		t.Fatal(err)
	}
	tool, err := installedAgentTool(resolved, "run")
	if err != nil {
		t.Fatal(err)
	}
	return resolved, tool
}

func TestSecretsRunManifestSelectorRequest(t *testing.T) {
	resolved, tool := secretsRunManifest(t)
	for _, selector := range []string{"", "issued-child"} {
		t.Run("selector="+selector, func(t *testing.T) {
			flags := []string{"--job", "nightly-backup", "--runner", "run_home001", "--request_id", "run-request-1", "--params", `{"database":"orders"}`}
			if selector != "" {
				flags = append(flags, "--secret", selector)
			}
			args, rawBody, err := parseManifestDispatchArgs(flags)
			if err != nil {
				t.Fatal(err)
			}
			if err := validateManifestDispatchArgs("secrets", tool, args); err != nil {
				t.Fatal(err)
			}
			spec, err := appmanifest.Interpret(appmanifest.InterpretRequest{Manifest: resolved.Manifest, Verb: "run", Args: args, RawBody: rawBody})
			if err != nil {
				t.Fatal(err)
			}
			if spec.Method != "POST" || spec.PathQuery != "/v1/jobs/nightly-backup/runs" || spec.Auth != "team-cert" {
				t.Fatalf("unexpected run routing/auth: %+v", spec)
			}
			var body map[string]any
			if err := json.Unmarshal(spec.Body, &body); err != nil {
				t.Fatal(err)
			}
			want := map[string]any{"runner": "run_home001", "request_id": "run-request-1", "params": map[string]any{"database": "orders"}}
			if selector != "" {
				want["secret"] = selector
			}
			if !reflect.DeepEqual(body, want) {
				t.Fatalf("run body = %#v, want %#v", body, want)
			}
		})
	}
}

func TestSecretsRunManifestSelectorHelpAndSchema(t *testing.T) {
	_, tool := secretsRunManifest(t)
	help := string(renderInstalledManifestVerbHelp("secrets", tool))
	if !strings.Contains(help, "--secret <string>  body.") || strings.Contains(help, "--secret <string>  body, required") {
		t.Fatalf("selector must render as optional body flag: %s", help)
	}
	props := tool.InputSchema["properties"].(map[string]any)
	if props["secret"].(map[string]any)["type"] != "string" {
		t.Fatal("tool schema must expose a string selector")
	}
	if !reflect.DeepEqual(tool.InputSchema["required"], []any{"job", "request_id", "runner"}) {
		t.Fatalf("required arguments changed: %v", tool.InputSchema["required"])
	}
	for _, override := range []string{"slot", "ordinal", "credentials"} {
		if err := validateManifestDispatchArgs("secrets", tool, map[string]any{override: "0"}); err == nil {
			t.Fatalf("undeclared %s override accepted", override)
		}
	}
}
