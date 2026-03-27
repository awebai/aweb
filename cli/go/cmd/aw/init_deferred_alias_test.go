package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/awebai/aw/awid"
)

func TestExecuteInitDeferredAliasCanReplaceInitialCreateProjectIdentity(t *testing.T) {
	var createBody map[string]any
	var initBody map[string]any
	var deregisterAuth string

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/create-project":
			if err := json.NewDecoder(r.Body).Decode(&createBody); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":         "ok",
				"project_id":     "proj-1",
				"project_slug":   "demo",
				"namespace_slug": "demo",
				"identity_id":    "identity-initial",
				"alias":          "alice",
				"api_key":        "aw_sk_initial",
				"created":        true,
				"did":            "did:key:z6MkInitial",
				"custody":        "self",
				"lifetime":       "ephemeral",
			})
		case "/v1/workspaces/init":
			if auth := r.Header.Get("Authorization"); auth != "Bearer aw_sk_initial" {
				t.Fatalf("init auth=%q", auth)
			}
			if err := json.NewDecoder(r.Body).Decode(&initBody); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":         "ok",
				"project_id":     "proj-1",
				"project_slug":   "demo",
				"namespace_slug": "demo",
				"identity_id":    "identity-final",
				"alias":          "bob",
				"api_key":        "aw_sk_final",
				"created":        true,
				"did":            "did:key:z6MkFinal",
				"custody":        "self",
				"lifetime":       "ephemeral",
			})
		case "/v1/agents/me":
			deregisterAuth = r.Header.Get("Authorization")
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))

	cfgPath := t.TempDir() + "/config.yaml"
	t.Setenv("AW_CONFIG_PATH", cfgPath)

	workingDir := t.TempDir()
	var promptOut bytes.Buffer
	result, err := executeInit(initOptions{
		Flow:                      flowHeadless,
		WorkingDir:                workingDir,
		PromptIn:                  strings.NewReader("bob\n"),
		PromptOut:                 &promptOut,
		BaseURL:                   server.URL,
		ServerName:                "local",
		ProjectSlug:               "demo",
		NamespaceSlug:             "demo",
		HumanName:                 "Tester",
		AgentType:                 "agent",
		SaveConfig:                false,
		WriteContext:              false,
		PromptAliasAfterBootstrap: true,
		Lifetime:                  awid.LifetimeEphemeral,
	})
	if err != nil {
		t.Fatalf("executeInit returned error: %v", err)
	}
	if _, ok := createBody["alias"]; ok {
		t.Fatalf("create-project alias should be omitted, got %+v", createBody)
	}
	if initBody["alias"] != "bob" {
		t.Fatalf("replacement init alias=%v", initBody["alias"])
	}
	if deregisterAuth != "Bearer aw_sk_initial" {
		t.Fatalf("deregister auth=%q", deregisterAuth)
	}
	if result.Response == nil || result.Response.Alias != "bob" || result.Response.APIKey != "aw_sk_final" {
		t.Fatalf("unexpected result response: %+v", result.Response)
	}
	if !strings.Contains(result.SigningKeyPath, "bob") {
		t.Fatalf("expected signing key path to track final alias, got %q", result.SigningKeyPath)
	}
}

func TestExecuteInitDeferredAliasAcceptsServerDefaultWithoutReplacement(t *testing.T) {
	var createBody map[string]any
	var initCalls int
	var deregisterCalls int

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/create-project":
			if err := json.NewDecoder(r.Body).Decode(&createBody); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":         "ok",
				"project_id":     "proj-1",
				"project_slug":   "demo",
				"namespace_slug": "demo",
				"identity_id":    "identity-initial",
				"alias":          "alice",
				"api_key":        "aw_sk_initial",
				"created":        true,
				"did":            "did:key:z6MkInitial",
				"custody":        "self",
				"lifetime":       "ephemeral",
			})
		case "/v1/workspaces/init":
			initCalls++
			t.Fatalf("replacement init should not run when default alias is accepted")
		case "/v1/agents/me":
			deregisterCalls++
			t.Fatalf("deregister should not run when default alias is accepted")
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))

	cfgPath := t.TempDir() + "/config.yaml"
	t.Setenv("AW_CONFIG_PATH", cfgPath)

	workingDir := t.TempDir()
	var promptOut bytes.Buffer
	result, err := executeInit(initOptions{
		Flow:                      flowHeadless,
		WorkingDir:                workingDir,
		PromptIn:                  strings.NewReader("\n"),
		PromptOut:                 &promptOut,
		BaseURL:                   server.URL,
		ServerName:                "local",
		ProjectSlug:               "demo",
		NamespaceSlug:             "demo",
		HumanName:                 "Tester",
		AgentType:                 "agent",
		SaveConfig:                false,
		WriteContext:              false,
		PromptAliasAfterBootstrap: true,
		Lifetime:                  awid.LifetimeEphemeral,
	})
	if err != nil {
		t.Fatalf("executeInit returned error: %v", err)
	}
	if _, ok := createBody["alias"]; ok {
		t.Fatalf("create-project alias should be omitted, got %+v", createBody)
	}
	if initCalls != 0 || deregisterCalls != 0 {
		t.Fatalf("unexpected replacement calls: init=%d deregister=%d", initCalls, deregisterCalls)
	}
	if result.Response == nil || result.Response.Alias != "alice" || result.Response.APIKey != "aw_sk_initial" {
		t.Fatalf("unexpected result response: %+v", result.Response)
	}
	if !strings.Contains(result.SigningKeyPath, "alice") {
		t.Fatalf("expected signing key path to track initial alias, got %q", result.SigningKeyPath)
	}
}
