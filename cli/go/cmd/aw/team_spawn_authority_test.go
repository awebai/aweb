package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

func TestTeamSpawnAuthorityUsesSelectedIdentityTeamAuth(t *testing.T) {
	oldTeamID, oldJSON := teamSpawnAuthorityTeamID, jsonFlag
	teamSpawnAuthorityTeamID = ""
	jsonFlag = true
	t.Cleanup(func() {
		teamSpawnAuthorityTeamID = oldTeamID
		jsonFlag = oldJSON
	})

	var gotPath, gotQuery, gotAuth, gotCert string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/spawn/authority" && r.URL.Path != "/v1/spawn/authority" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		gotPath = r.URL.Path
		gotQuery = r.URL.RawQuery
		gotAuth = r.Header.Get("Authorization")
		gotCert = r.Header.Get("X-AWID-Team-Certificate")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"team_id":        "backend:demo",
			"actor_agent_id": "agent-123",
			"auth_kind":      "team_key",
			"live_agent":     true,
			"can_spawn":      true,
		})
	}))
	defer server.Close()

	wd := t.TempDir()
	writeDefaultWorkspaceBindingForTest(t, wd, server.URL)
	t.Chdir(wd)

	var out bytes.Buffer
	cmd := &cobra.Command{Use: "test"}
	cmd.SetOut(&out)
	if err := runTeamSpawnAuthority(context.Background(), cmd); err != nil {
		t.Fatalf("runTeamSpawnAuthority: %v", err)
	}
	if gotPath == "" || gotQuery == "" || !strings.Contains(gotQuery, "team_id=backend%3Ademo") {
		t.Fatalf("path=%q query=%q", gotPath, gotQuery)
	}
	if !strings.HasPrefix(gotAuth, "DIDKey ") || gotCert == "" {
		t.Fatalf("auth=%q cert=%q", gotAuth, gotCert)
	}
	var decoded map[string]any
	if err := json.Unmarshal(out.Bytes(), &decoded); err != nil {
		t.Fatalf("json output: %v\n%s", err, out.String())
	}
	if decoded["can_spawn"] != true || decoded["auth_kind"] != "team_key" {
		t.Fatalf("output=%v", decoded)
	}
}

func TestTeamSpawnAuthorityMapsActionableTypedHTTPFailures(t *testing.T) {
	oldTeamID := teamSpawnAuthorityTeamID
	teamSpawnAuthorityTeamID = "backend:demo"
	t.Cleanup(func() { teamSpawnAuthorityTeamID = oldTeamID })

	for _, tc := range []struct {
		status int
		want   string
	}{
		{status: http.StatusUnprocessableEntity, want: "canonical <name>:<domain>"},
		{status: http.StatusForbidden, want: "selected identity belongs to the requested team"},
	} {
		t.Run(http.StatusText(tc.status), func(t *testing.T) {
			const rawDetail = "private fixture detail must not be displayed"
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				_ = json.NewEncoder(w).Encode(map[string]string{"detail": rawDetail})
			}))
			defer server.Close()

			wd := t.TempDir()
			writeDefaultWorkspaceBindingForTest(t, wd, server.URL)
			t.Chdir(wd)
			cmd := &cobra.Command{Use: "test"}
			var stdout bytes.Buffer
			cmd.SetOut(&stdout)
			err := runTeamSpawnAuthority(context.Background(), cmd)
			if err == nil {
				t.Fatal("expected HTTP error")
			}
			if got := err.Error(); !strings.Contains(got, tc.want) || strings.Contains(got, rawDetail) {
				t.Fatalf("error is not actionable and bounded: %q", got)
			}
			if status, ok := awid.HTTPStatusCode(err); !ok || status != tc.status {
				t.Fatalf("HTTPStatusCode(err)=(%d,%t), want %d", status, ok, tc.status)
			}
			var mappedErr *teamSpawnAuthorityRequestError
			if !errors.As(err, &mappedErr) || mappedErr.status != tc.status {
				t.Fatalf("mapped error=%#v, want status %d", mappedErr, tc.status)
			}
			var apiErr *awid.APIError
			if !errors.As(err, &apiErr) || apiErr.StatusCode != tc.status {
				t.Fatalf("wrapped API error=%#v, want status %d", apiErr, tc.status)
			}
			if body, ok := awid.HTTPErrorBody(err); !ok || !strings.Contains(body, rawDetail) {
				t.Fatalf("bounded mapping did not preserve typed API body: body=%q ok=%t", body, ok)
			}
		})
	}
}

func TestTeamSpawnAuthorityHelpAndHTTPFailuresInRealCLI(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	root := t.TempDir()
	bin := filepath.Join(root, "aw")
	buildAwBinary(t, ctx, bin)

	command := exec.CommandContext(ctx, bin, "team", "spawn-authority", "--help")
	command.Dir = root
	command.Env = append(testCommandEnv(filepath.Join(root, "home")), "AW_NO_UPDATE_CHECK=1")
	help, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("spawn-authority help: %v\n%s", err, help)
	}
	for _, want := range []string{"--team-id", "<name>:<domain>", "defaults to selected team"} {
		if !strings.Contains(string(help), want) {
			t.Fatalf("help missing %q:\n%s", want, help)
		}
	}
	if strings.Contains(string(help), "Canonical team id to check") {
		t.Fatalf("help retains ambiguous team ID description:\n%s", help)
	}

	for _, tc := range []struct {
		status int
		want   string
	}{
		{status: http.StatusUnprocessableEntity, want: "canonical <name>:<domain>"},
		{status: http.StatusForbidden, want: "authorized to check its spawn authority"},
	} {
		t.Run(http.StatusText(tc.status), func(t *testing.T) {
			const rawDetail = "private fixture validation format must not leak"
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/v1/spawn/authority" {
					t.Errorf("unexpected request %s", r.URL.String())
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				_ = json.NewEncoder(w).Encode(map[string]string{"detail": rawDetail})
			}))
			defer server.Close()

			cwd := t.TempDir()
			home := filepath.Join(t.TempDir(), "home")
			writeDefaultWorkspaceBindingForTest(t, cwd, server.URL)
			command := exec.CommandContext(ctx, bin, "team", "spawn-authority", "--team-id", "backend:demo")
			command.Dir = cwd
			command.Env = append(testCommandEnv(home), "AW_NO_UPDATE_CHECK=1", "AWEB_URL=", "AWID_REGISTRY_URL=")
			output, err := command.CombinedOutput()
			if err == nil {
				t.Fatalf("expected exit failure, output=%s", output)
			}
			if !strings.Contains(string(output), tc.want) || !strings.Contains(string(output), "HTTP "+strconv.Itoa(tc.status)) {
				t.Fatalf("CLI error lacks status/action: %s", output)
			}
			if strings.Contains(string(output), rawDetail) {
				t.Fatalf("CLI leaked server response detail: %s", output)
			}
		})
	}
}
