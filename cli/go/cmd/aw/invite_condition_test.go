package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
			state, err := prepareHostedInviteCreation(context.Background(), nil, "aw_inv_independent", server.URL, "child", "", false, material, false, true, "", "")
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
	if _, err := os.Stat(filepath.Join(home, acceptanceKeyMarkerName)); !os.IsNotExist(err) {
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
	state, err := prepareHostedInviteCreation(context.Background(), nil, "aw_inv_other", server.URL, "child", "", false, material, false, false, "", "")
	if err != nil {
		t.Fatal(err)
	}
	_, err = state.prepareRequest(home, material)
	if err == nil || !strings.Contains(err.Error(), "id parent request") || !strings.Contains(err.Error(), "--parent") {
		t.Fatalf("missing creator exchange guidance: %v", err)
	}
}

func TestLocalInviteConditionPrecedesMembershipEffect(t *testing.T) {
	for _, scenario := range []string{"current human", "other human", "revoked human", "replaced human", "status unavailable"} {
		t.Run(scenario, func(t *testing.T) {
			t.Setenv("HOME", t.TempDir())
			t.Setenv("APP_ENV", "development")
			v := loadWhoVectors(t)
			status := v.Statuses["normal"]
			if scenario == "revoked human" {
				status = v.Statuses["alice-revoked-now"]
			}
			if scenario == "replaced human" {
				status = v.Statuses["lost-human-replaced"]
			}
			registrations := 0
			registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/id-certificates/status" {
					if scenario == "status unavailable" {
						http.Error(w, "temporarily unavailable", 503)
						return
					}
					json.NewEncoder(w).Encode(status)
					return
				}
				if strings.HasSuffix(r.URL.Path, "/certificates") && r.Method == http.MethodPost {
					registrations++
					json.NewEncoder(w).Encode(map[string]any{"status": "registered"})
					return
				}
				t.Errorf("unexpected registry effect %s %s", r.Method, r.URL.Path)
				http.NotFound(w, r)
			}))
			defer registry.Close()
			origin := strings.Replace(registry.URL, "127.0.0.1", "registry.example", 1)
			t.Setenv("AWID_REGISTRY_URL", origin)
			serveRosterTXT(t, idCreateDNSRecordValue(v.Keys["root"].DIDKey, origin))
			home := t.TempDir()
			wd := t.TempDir()
			seed, _ := hex.DecodeString(v.Keys["coordinator"].SeedHex)
			if err := awid.SaveSigningKey(filepath.Join(home, "signing.key"), ed25519.NewKeyFromSeed(seed)); err != nil {
				t.Fatal(err)
			}
			if err := awconfig.SaveInstalledIDChain(home, map[string]any{"v": 1, "type": "aweb.id-chain", "certificates": []any{v.Certificates["alice"].Signed, v.Certificates["coordinator"].Signed}}); err != nil {
				t.Fatal(err)
			}
			_, teamKey, _ := awid.GenerateKeypair()
			if err := awconfig.SaveTeamKey("example.com", "backend", teamKey); err != nil {
				t.Fatal(err)
			}
			human := v.Keys["alice"].DIDAW
			if scenario == "other human" {
				human = v.Keys["bob"].DIDAW
			}
			id, _ := awid.GenerateUUID4()
			invite := &awconfig.TeamInvite{InviteID: id, Domain: "example.com", TeamName: "backend", Secret: "fixture", RegistryURL: origin, ForHuman: &human, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano)}
			if err := awconfig.SaveTeamInvite(invite); err != nil {
				t.Fatal(err)
			}
			token, err := awconfig.EncodeInviteToken(invite)
			if err != nil {
				t.Fatal(err)
			}
			accepted, err := acceptTeamInviteWithDetails(teamInviteAcceptanceRequest{
				WorkingDir: wd,
				Token:      token,
				Options:    teamAcceptInviteOptions{IdentityHome: home, Name: "child", Scope: "local"},
			})
			certPath, _ := awconfig.TeamCertificatePathFromIdentityHome(home, "backend:example.com")
			if scenario == "current human" {
				if err != nil || accepted == nil || registrations != 1 {
					t.Fatalf("valid neighbor: accepted=%+v registrations=%d err=%v", accepted, registrations, err)
				}
				if _, err := os.Stat(certPath); err != nil {
					t.Fatal(err)
				}
			} else {
				if err == nil || registrations != 0 {
					t.Fatalf("refusal admitted membership: registrations=%d err=%v", registrations, err)
				}
				if scenario == "status unavailable" && !strings.Contains(err.Error(), "evidence_unavailable") {
					t.Fatalf("lost unavailable diagnosis: %v", err)
				}
				if _, err := os.Stat(certPath); !os.IsNotExist(err) {
					t.Fatalf("refusal wrote certificate: %v", err)
				}
				if _, err := awconfig.LoadTeamInvite(id); err != nil {
					t.Fatalf("refusal consumed invite: %v", err)
				}
			}
		})
	}
}

func TestPendingOtherHumanJoinAllowsOnlyItsOwnParentExchange(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	home := t.TempDir()
	_, key, _ := awid.GenerateKeypair()
	if err := awid.SaveSigningKey(filepath.Join(home, "signing.key"), key); err != nil {
		t.Fatal(err)
	}
	tree, err := newHostedIDTreeRecovery(hostedIdentityContext{})
	if err != nil {
		t.Fatal(err)
	}
	human := "did:aw:another-person"
	state := &hostedInviteCreation{Scope: "local", DIDKey: awid.ComputeDIDKey(key.Public().(ed25519.PublicKey)), Tree: tree, TokenHash: "retained", ForHuman: &human}
	if err := state.save(filepath.Join(home, hostedInviteRecoveryFile)); err != nil {
		t.Fatal(err)
	}
	requester, err := pendingHostedInviteRequester(idParentOptions{IdentityHome: home, Domain: "creator.example"})
	if err != nil || requester.domain != "creator.example" || requester.expectedParent != nil {
		t.Fatalf("own creator replaced by invite issuer: %+v %v", requester, err)
	}
	if _, err := pendingHostedInviteRequester(idParentOptions{IdentityHome: home}); err == nil {
		t.Fatal("missing creator domain accepted")
	}
}

func TestLocalInviteStoresTheVerifiedDefaultOrExplicitCondition(t *testing.T) {
	for _, scenario := range []string{"default", "explicit other", "explicit same"} {
		t.Run(scenario, func(t *testing.T) {
			v := loadWhoVectors(t)
			wd := whoIdentity(t, v, true, false)
			t.Setenv("APP_ENV", "development")
			registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1/id-certificates/status" {
					t.Errorf("unexpected registry operation: %s", r.URL.Path)
					http.NotFound(w, r)
					return
				}
				json.NewEncoder(w).Encode(v.Statuses["normal"])
			}))
			defer registry.Close()
			origin := strings.Replace(registry.URL, "127.0.0.1", "registry.example", 1)
			t.Setenv("AWID_REGISTRY_URL", origin)
			serveRosterTXT(t, idCreateDNSRecordValue(v.Keys["root"].DIDKey, origin))
			_, key, err := awid.GenerateKeypair()
			if err != nil {
				t.Fatal(err)
			}
			if err := awconfig.SaveTeamKey("example.com", "backend", key); err != nil {
				t.Fatal(err)
			}
			var requested *string
			want := v.Keys["alice"].DIDAW
			if scenario == "explicit other" {
				want = v.Keys["bob"].DIDAW
				requested = &want
			}
			if scenario == "explicit same" {
				requested = &want
			}
			created, err := mintPlannedTeamInvite(teamInviteMintRequest{Plan: teamInvitePlan{Kind: inviteAuthorityController, Source: teamInviteSource{WorkingDir: wd, Home: awconfig.IdentityHome{Root: filepath.Join(wd, ".aw"), Source: awconfig.IdentityHomeFlag}, Domain: "example.com", Team: "backend", RegistryURL: origin, AwebURL: "https://service.example"}}, Scope: inviteMemberLocal, ForHuman: requested})
			id, token := created.InviteID, created.Token
			if err != nil {
				t.Fatal(err)
			}
			saved, err := awconfig.LoadTeamInvite(id)
			if err != nil || saved.ForHuman == nil || *saved.ForHuman != want {
				t.Fatalf("stored condition: %+v %v", saved, err)
			}
			if (saved.IDChild == nil) != (scenario == "explicit other") {
				t.Fatalf("issuer parentage offered for another human: %+v", saved.IDChild)
			}
			decoded, err := awconfig.DecodeInviteToken(token)
			if err != nil {
				t.Fatal(err)
			}
			raw, _ := json.Marshal(decoded)
			if strings.Contains(string(raw), "for_human") {
				t.Fatal("bearer token carries authority for condition")
			}
		})
	}
}

func TestExplicitParentNeverChangesAnExistingChain(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	home := t.TempDir()
	v := loadWhoVectors(t)
	seed, _ := hex.DecodeString(v.Keys["coordinator"].SeedHex)
	if err := awid.SaveSigningKey(filepath.Join(home, "signing.key"), ed25519.NewKeyFromSeed(seed)); err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveInstalledIDChain(home, map[string]any{"v": 1, "type": "aweb.id-chain", "certificates": []any{v.Certificates["alice"].Signed, v.Certificates["coordinator"].Signed}}); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(home, "id-chain.json"))
	if err != nil {
		t.Fatal(err)
	}
	err = completeExplicitInviteParent(context.Background(), t.TempDir(), home, "aw_inv_existing", t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "already has one") {
		t.Fatalf("--parent did not refuse existing identity: %v", err)
	}
	after, _ := os.ReadFile(filepath.Join(home, "id-chain.json"))
	if string(before) != string(after) {
		t.Fatal("reparented existing identity")
	}
	if _, err := os.Stat(filepath.Join(home, "identity.yaml")); !os.IsNotExist(err) {
		t.Fatalf("refusal changed identity metadata: %v", err)
	}
}

func TestInitIndependentInviteFlagsKeepOutcomesSeparate(t *testing.T) {
	oldInvite, oldParent, oldFrom, oldAdmission, oldWorkspace, oldNewAccount, oldNewTeam := initInvite, initParent, initJoinFrom, initAdmissionTeamID, initWorkspaceTeam, initNewAccount, initNewTeam
	oldHome := activeIdentityHome
	t.Cleanup(func() {
		initInvite, initParent, initJoinFrom, initAdmissionTeamID, initWorkspaceTeam, initNewAccount, initNewTeam = oldInvite, oldParent, oldFrom, oldAdmission, oldWorkspace, oldNewAccount, oldNewTeam
		activeIdentityHome = oldHome
	})
	initInvite, initParent, initJoinFrom, initAdmissionTeamID, initWorkspaceTeam, initNewAccount, initNewTeam = "aw_inv_selected", "/creator", "", "", false, false, false
	activeIdentityHome = awconfig.IdentityHome{}
	if err := validateInitOutcomeFlags(initInviteInput{}); err != nil {
		t.Fatal(err)
	}
	initJoinFrom = "/other"
	if err := validateInitOutcomeFlags(initInviteInput{}); err == nil {
		t.Fatal("two membership sources accepted")
	}
	initJoinFrom, initInvite = "", ""
	if err := validateInitOutcomeFlags(initInviteInput{}); err == nil {
		t.Fatal("parent accepted without invite")
	}
}
