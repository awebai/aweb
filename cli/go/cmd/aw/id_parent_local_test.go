package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

// An OATS child exports its request from an external local identity home.
// Verify the exact signed file through the SDK, not a flag-parser mock.
func TestParentRequestBinaryAcceptsLocalParentForLocalChild(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	bin := filepath.Join(t.TempDir(), "aw")
	buildAwBinary(t, ctx, bin)
	parentPub, _, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	localParent := awid.ComputeDIDKey(parentPub)
	globalParent := awid.ComputeStableID(parentPub)
	for _, tc := range []struct {
		name, parent string
		globalChild  bool
		wantError    string
	}{
		{name: "local-parent-local-child", parent: localParent},
		{name: "global-parent-local-child", parent: globalParent},
		{name: "local-parent-global-child", parent: localParent, globalChild: true, wantError: "local did:key parent"},
		{name: "malformed-local-parent", parent: "did:key:znot-ed25519", wantError: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			identityHome := filepath.Join(root, "principal")
			pub, key, err := awid.GenerateKeypair()
			if err != nil {
				t.Fatal(err)
			}
			identity := &awconfig.WorktreeIdentity{DID: awid.ComputeDIDKey(pub), Custody: awid.CustodySelf, IdentityScope: awid.IdentityModeLocal}
			if tc.globalChild {
				identity.StableID = awid.ComputeStableID(pub)
				identity.IdentityScope = awid.IdentityModeGlobal
			}
			if err := awconfig.SaveWorktreeIdentityTo(filepath.Join(identityHome, "identity.yaml"), identity); err != nil {
				t.Fatal(err)
			}
			if err := awid.SaveSigningKey(filepath.Join(identityHome, "signing.key"), key); err != nil {
				t.Fatal(err)
			}
			outputPath := filepath.Join(root, "request.json")
			cmd := exec.CommandContext(ctx, bin, "--identity-home", identityHome, "id", "parent", "request", "--domain", "example.com", "--invitation-id", "11111111-1111-4111-8111-111111111111", "--parent", tc.parent, "--out", outputPath)
			cmd.Dir = root
			cmd.Env = append(os.Environ(), "HOME="+root, "AW_CONFIG_PATH=", "AW_NO_UPDATE_CHECK=1")
			output, runErr := cmd.CombinedOutput()
			if tc.globalChild || tc.name == "malformed-local-parent" {
				if runErr == nil {
					t.Fatalf("invalid request exported: %s", output)
				}
				if tc.wantError != "" && !strings.Contains(string(output), tc.wantError) {
					t.Fatalf("wrong refusal: %s", output)
				}
				if _, err := os.Stat(outputPath); !os.IsNotExist(err) {
					t.Fatalf("refused request file exists: %v", err)
				}
				if entries, err := os.ReadDir(awconfig.IdentityRequestsDir(identityHome)); !os.IsNotExist(err) || len(entries) != 0 {
					t.Fatalf("refused request recorded: %v %v", entries, err)
				}
				return
			}
			if runErr != nil {
				t.Fatalf("request failed: %v\n%s", runErr, output)
			}
			raw, err := os.ReadFile(outputPath)
			if err != nil {
				t.Fatal(err)
			}
			signed, err := awid.ParseIDCertificateRequest(raw)
			if err != nil {
				t.Fatal(err)
			}
			request := signed["request"].(map[string]any)
			parent := request["parent"].(map[string]any)
			if parent["kind"] != "identity" || parent["id"] != tc.parent || request["id"] != identity.DID || request["subject_key"] != identity.DID || request["kind"] != "agent" {
				t.Fatalf("wrong binding: %+v", request)
			}
			stored, err := (awconfig.IDRequestFileStore{Dir: awconfig.IdentityRequestsDir(identityHome)}).Request(request["request_id"].(string))
			if err != nil || stored == nil || stored.Request != string(raw) {
				t.Fatalf("outstanding request differs: %+v %v", stored, err)
			}
		})
	}
}

func TestParentRequestLocalParentCannotAdmitHuman(t *testing.T) {
	p := newParentRun(t, "https://registry.example.com")
	parentPub, _, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = executeIDParentRequest(p.opts(), "11111111-1111-4111-8111-111111111111", awid.ComputeDIDKey(parentPub), false)
	if exitCode(err) != 2 || !strings.Contains(err.Error(), "local did:key parent") {
		t.Fatalf("human request not refused: %v", err)
	}
	if p.prompts != 0 {
		t.Fatalf("refused human was asked to sign %d times", p.prompts)
	}
	if entries, err := os.ReadDir(p.requests(t).Dir); !os.IsNotExist(err) || len(entries) != 0 {
		t.Fatalf("refused human request recorded: %v %v", entries, err)
	}
}
