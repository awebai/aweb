package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

func TestHostedInviteOwnChainSeparatesMembershipFromParentage(t *testing.T) {
	for _, scope := range []string{"local", "global"} {
		t.Run(scope, func(t *testing.T) {
			v := loadWhoVectors(t)
			home := t.TempDir()
			name := "coordinator"
			if scope == "global" {
				name = "global_agent"
			}
			seed, _ := hex.DecodeString(v.Keys[name].SeedHex)
			key := ed25519.NewKeyFromSeed(seed)
			bundle := map[string]any{"v": 1, "type": "aweb.id-chain", "certificates": []any{v.Certificates["alice"].Signed, v.Certificates[strings.ReplaceAll(name, "_", "-")].Signed}}
			if err := awconfig.SaveInstalledIDChain(home, bundle); err != nil {
				t.Fatal(err)
			}
			server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				json.NewEncoder(w).Encode(map[string]any{"invite_id": "11111111-1111-4111-8111-111111111111", "canonical_team_id": "backend:example.com", "status": "active", "identity_scope": "unknown", "server_url": "http://" + r.Host, "for_human": v.Keys["alice"].DIDAW, "id_tree": map[string]any{"v": 1, "issuer_id": v.Keys["seat"].DIDKey, "domain": "example.com", "child_kind": "agent", "mode": "self_custodial"}})
			}))
			defer server.Close()
			material := workspaceTeamIdentityMaterial{SigningKey: key, DIDKey: v.Keys[name].DIDKey, IdentityScope: scope}
			if scope == "global" {
				material.StableID = v.Keys[name].DIDAW
			}
			state, err := prepareHostedInviteCreation(context.Background(), nil, "aw_inv_independent", server.URL, "child", "", false, material)
			if err != nil {
				t.Fatalf("own chain rejected by invite issuer: %v", err)
			}
			request, err := state.prepareRequest(home, material)
			if err != nil || request != nil {
				t.Fatalf("membership asked issuer for parentage: %+v %v", request, err)
			}
		})
	}
}

func TestHostedAcceptReusesAnUnjoinedKeyAndChain(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	home := t.TempDir()
	wd := t.TempDir()
	v := loadWhoVectors(t)
	seed, _ := hex.DecodeString(v.Keys["coordinator"].SeedHex)
	key := ed25519.NewKeyFromSeed(seed)
	if err := awid.SaveSigningKey(filepath.Join(home, "signing.key"), key); err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveInstalledIDChain(home, map[string]any{"v": 1, "type": "aweb.id-chain", "certificates": []any{v.Certificates["alice"].Signed, v.Certificates["coordinator"].Signed}}); err != nil {
		t.Fatal(err)
	}
	_, got, err := hostedAcceptSigningKeyAt(wd, home)
	if err != nil {
		t.Fatalf("prepared chain home cannot join: %v", err)
	}
	if !got.Equal(key) {
		t.Fatal("replaced prepared identity key")
	}
	if _, err := os.Stat(hostedAcceptPendingMarkerPath(wd, home)); !os.IsNotExist(err) {
		t.Fatalf("membership-only join manufactured pending creation: %v", err)
	}
}

func TestOtherHumanInviteWithoutAChainNamesOwnParentExchange(t *testing.T) {
	home := t.TempDir()
	_, key, _ := awid.GenerateKeypair()
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"invite_id": "11111111-1111-4111-8111-111111111111", "canonical_team_id": "backend:example.com", "status": "active", "identity_scope": "unknown", "server_url": "http://" + r.Host, "for_human": "did:aw:other-person", "id_tree": nil})
	}))
	defer server.Close()
	material := workspaceTeamIdentityMaterial{SigningKey: key, DIDKey: awid.ComputeDIDKey(key.Public().(ed25519.PublicKey)), IdentityScope: "local"}
	state, err := prepareHostedInviteCreation(context.Background(), nil, "aw_inv_other", server.URL, "child", "", false, material)
	if err != nil {
		t.Fatal(err)
	}
	_, err = state.prepareRequest(home, material)
	if err == nil || !strings.Contains(err.Error(), "id parent request") || !strings.Contains(err.Error(), "--parent") {
		t.Fatalf("missing creator exchange guidance: %v", err)
	}
}
