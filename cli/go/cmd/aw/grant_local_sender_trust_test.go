package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

// A local-resident grant has no address. Its received local senders must still
// be checked against the live team roster, exactly as a root local client does.
func TestLocalResidentGrantRosterChecksBareSenderAlias(t *testing.T) {
	resetGrantCommandGlobals(t)
	tmp := t.TempDir()
	t.Chdir(tmp)
	setGrantTestEnv(t, tmp)

	senderPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	senderDID := awid.ComputeDIDKey(senderPub)
	rosterReads := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/agents" {
			// The registry also answers here; it knows no team-local alias.
			http.NotFound(w, r)
			return
		}
		rosterReads++
		_ = json.NewEncoder(w).Encode(awid.ListAgentsResponse{
			TeamID: "backend:acme.com",
			Agents: []awid.AgentView{{Alias: "carol", DIDKey: senderDID, IdentityScope: awid.IdentityModeLocal}},
		})
	}))
	t.Cleanup(server.Close)
	t.Setenv("AWID_REGISTRY_URL", server.URL)

	root := filepath.Join(tmp, ".aw")
	_, grant := writeGrantHomeForTest(t, root, server.URL)
	grant.Subject = awconfig.GrantSubject{DIDKey: "did:key:zRootAlice", Alias: "alice"}
	if err := awconfig.SaveGrantHomeTo(awconfig.GrantHomeStatePath(root), grant); err != nil {
		t.Fatal(err)
	}

	client, _, err := resolveClientSelectionForDir(tmp)
	if err != nil {
		t.Fatalf("resolveClientSelectionForDir: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if got, _ := client.NormalizeReceivedSenderTrust(ctx, awid.Verified, "", "carol", senderDID, "", nil, nil, nil, nil); got != awid.Verified {
		t.Fatalf("current member status=%q, want %q", got, awid.Verified)
	}
	if got, _ := client.NormalizeReceivedSenderTrust(ctx, awid.Verified, "", "dave", senderDID, "", nil, nil, nil, nil); got != awid.IdentityMismatch {
		t.Fatalf("removed member status=%q, want %q", got, awid.IdentityMismatch)
	}
	if rosterReads != 2 {
		t.Fatalf("roster reads=%d, want 2 fresh reads", rosterReads)
	}
}
