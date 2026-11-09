package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/zalando/go-keyring"
)

// Frozen authority facts are independent verifier inputs, never client-carried
// claims. The installed chain and encrypted key are precisely the public Alice
// vector; no human marker or server row is fabricated.
func humanParticipationFixture(t *testing.T) (*humanParticipation, *[]string, *awid.IDChainEvidence, ed25519.PrivateKey) {
	t.Helper()
	keyring.MockInit()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("AWEB_IDENTITY_HOME", "")
	t.Setenv("AWEB_URL", "")
	t.Setenv("AW_CONFIG_PATH", "")
	t.Setenv("AW_HOME", t.TempDir())
	old, oldFlag, oldDomain, oldHome, oldTeam := activeHuman, humanFlag, humanDomainFlag, identityHomeFlag, teamFlag
	activeHuman = nil
	humanFlag = ""
	humanDomainFlag = ""
	identityHomeFlag = ""
	teamFlag = ""
	t.Cleanup(func() {
		activeHuman = old
		humanFlag = oldFlag
		humanDomainFlag = oldDomain
		identityHomeFlag = oldHome
		teamFlag = oldTeam
	})
	data, err := os.ReadFile("../../../../docs/vectors/id-certificates-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]any
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&v); err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, 32))
	root := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32))
	did := awid.ComputeDIDKey(key.Public().(ed25519.PublicKey))
	id := awid.ComputeStableID(key.Public().(ed25519.PublicKey))
	rec := &awconfig.HumanRecord{StableID: id, DIDKey: did, Domain: "example.com", State: awconfig.HumanRegistered}
	if err := awconfig.SaveHumanRecord(rec); err != nil {
		t.Fatal(err)
	}
	dir, _ := awconfig.HumanRecordDir(rec.Domain, id)
	chain := map[string]any{"v": 1, "type": "aweb.id-chain", "certificates": []any{v["certificates"].(map[string]any)["alice"].(map[string]any)["signed"]}}
	if err := awconfig.SaveInstalledIDChain(dir, chain); err != nil {
		t.Fatal(err)
	}
	if err := awid.InstallHumanKey(awconfig.HumanKeychain{}, id, key, []byte(humanPassphrase)); err != nil {
		t.Fatal(err)
	}
	prompts := []string{}
	h, err := loadHumanParticipation(id, rec.Domain, awconfig.HumanKeychain{}, func(text string) ([]byte, error) {
		prompts = append(prompts, text)
		return []byte(humanPassphrase), nil
	}, func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	age := 0.0
	evidence := &awid.IDChainEvidence{Status: v["status_fixtures"].(map[string]any)["normal"].(map[string]any), NamespaceAuthority: map[string]any{"domain": "example.com", "dns_name": "_awid.example.com", "inherited": false, "controller_key": awid.ComputeDIDKey(root.Public().(ed25519.PublicKey))}, AgeSeconds: &age}
	result := awid.VerifyIDChain(h.chain, awid.IDChainSubject{ID: id, DIDKey: did}, evidence, rec.Domain)
	if result.IdentityValid == nil || !*result.IdentityValid || result.Kind == nil || *result.Kind != "human" {
		t.Fatalf("fixture not verified human: %+v", result)
	}
	activeHuman = h
	return h, &prompts, evidence, key
}

func TestHumanParticipationFetchConnectMailAndManifest(t *testing.T) {
	h, prompts, evidence, key := humanParticipationFixture(t)
	cwd := t.TempDir()
	_, decoy, _ := awid.GenerateKeypair()
	writeSelectionFixtureForTest(t, cwd, testSelectionFixture{AwebURL: "https://decoy.invalid", TeamID: "decoy:elsewhere.example", Alias: "decoy", SigningKey: decoy})
	t.Chdir(cwd)
	beforeWorkspace := snapshotJoinFiles(t, cwd)
	_, controller, _ := awid.GenerateKeypair()
	cert, err := awid.SignTeamCertificate(controller, awid.TeamCertificateFields{Team: "demo:example.com", Alias: "alice", MemberDIDKey: h.record.DIDKey, MemberDIDAW: h.record.StableID, IdentityScope: awid.IdentityModeLocal})
	if err != nil {
		t.Fatal(err)
	}
	certHeader, _ := awid.EncodeTeamCertificateHeader(cert)
	messages := 0
	var connectNames []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/v1/") {
			http.NotFound(w, r)
			return
		}
		auth := strings.Fields(r.Header.Get("Authorization"))
		if len(auth) != 3 || auth[1] != h.record.DIDKey {
			t.Errorf("wrong identity on %s", r.URL.Path)
			http.Error(w, "auth", 401)
			return
		}
		sig, _ := base64.RawStdEncoding.DecodeString(auth[2])
		if strings.Contains(r.URL.Path, "/certificates/") {
			payload := r.Header.Get("X-AWEB-Timestamp") + "\nGET\n" + r.URL.Path
			if !ed25519.Verify(key.Public().(ed25519.PublicKey), []byte(payload), sig) {
				t.Error("invalid member fetch signature")
			}
			json.NewEncoder(w).Encode(map[string]any{"certificate": certHeader})
			return
		}
		body, _ := io.ReadAll(r.Body)
		payload, _ := base64.RawURLEncoding.DecodeString(r.Header.Get("X-AWEB-Signed-Payload"))
		var fields map[string]any
		json.Unmarshal(payload, &fields)
		sum := sha256.Sum256(body)
		if !ed25519.Verify(key.Public().(ed25519.PublicKey), payload, sig) || fields["method"] != r.Method || fields["path"] != r.URL.RequestURI() || fields["body_sha256"] != fmt.Sprintf("%x", sum) || fields["team_id"] != cert.Team {
			t.Errorf("invalid v2 request %s: %s", r.URL.Path, payload)
		}
		got, err := awid.DecodeTeamCertificateHeader(r.Header.Get("X-AWID-Team-Certificate"))
		if err != nil || awid.VerifyTeamCertificate(got, controller.Public().(ed25519.PublicKey)) != nil {
			t.Error("bad team cert")
		}
		bundle, err := awid.DecodeIDChainHeader(r.Header.Get("X-AWID-ID-Chain"))
		if err != nil {
			t.Error(err)
			http.Error(w, "chain", 403)
			return
		}
		result := awid.VerifyIDChain(bundle, awid.IDChainSubject{ID: h.record.StableID, DIDKey: auth[1], TeamMemberDIDAW: cert.MemberDIDAW, TeamMemberDIDKey: cert.MemberDIDKey}, evidence, "example.com")
		if result.IdentityValid == nil || !*result.IdentityValid || result.Kind == nil || *result.Kind != "human" {
			http.Error(w, result.Reason, 403)
			return
		}
		switch r.URL.Path {
		case "/v1/connect":
			var request connectRequest
			if err := json.Unmarshal(body, &request); err != nil {
				t.Error(err)
			}
			connectNames = append(connectNames, request.HumanName)
			json.NewEncoder(w).Encode(map[string]any{"agent_type": "human", "team_id": cert.Team, "alias": "alice"})
		case "/v1/messages":
			var m map[string]any
			json.Unmarshal(body, &m)
			msig, _ := base64.RawStdEncoding.DecodeString(m["signature"].(string))
			signed := m["signed_payload"].(string)
			if !ed25519.Verify(key.Public().(ed25519.PublicKey), []byte(signed), msig) {
				t.Error("mail not signed by human")
			}
			messages++
			json.NewEncoder(w).Encode(map[string]any{"message_id": "m1", "conversation_id": m["conversation_id"], "status": "sent"})
		case "/v1/messages/incoming":
			json.NewEncoder(w).Encode(map[string]any{"message_id": "incoming", "conversation_id": "c1", "from_alias": "bob", "to_alias": "alice", "subject": "Review", "body": "Original", "read_at": "2026-11-09T00:00:00Z"})
		case "/v1/messages/incoming/ack":
			json.NewEncoder(w).Encode(map[string]any{"message_id": "incoming", "acknowledged_at": "2026-11-09T00:00:00Z"})
		case "/v1/messages/inbox", "/v1/messages/conversations/c1":
			json.NewEncoder(w).Encode(map[string]any{"messages": []any{map[string]any{"message_id": "incoming", "conversation_id": "c1", "from_alias": "bob", "to_alias": "alice", "subject": "Review", "body": "Original", "read_at": "2026-11-09T00:00:00Z"}}})
		case "/v1/conversations":
			json.NewEncoder(w).Encode(map[string]any{"conversations": []any{map[string]any{"conversation_id": "c1", "conversation_type": "mail", "participants": []string{"alice", "bob"}}}})
		case "/v1/agents":
			json.NewEncoder(w).Encode(map[string]any{"agents": []any{map[string]any{"alias": "bob", "agent_id": "bob", "agent_type": "agent"}}})
		case "/v1/request":
			w.Write([]byte(`{"ok":true}`))
		default:
			t.Errorf("unexpected request %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	t.Setenv("AWID_REGISTRY_URL", srv.URL)
	h.record.RegistryURL = srv.URL
	oldNamespace, oldTeam, oldCert, oldRegistry := teamFetchCertNamespace, teamFetchCertTeam, teamFetchCertID, teamFetchCertRegistry
	oldURL, oldInitTeam, oldHumanName := initURL, initTeam, initHumanName
	t.Cleanup(func() {
		teamFetchCertNamespace = oldNamespace
		teamFetchCertTeam = oldTeam
		teamFetchCertID = oldCert
		teamFetchCertRegistry = oldRegistry
		initURL = oldURL
		initTeam = oldInitTeam
		initHumanName = oldHumanName
	})
	teamFetchCertNamespace = "example.com"
	teamFetchCertTeam = "demo"
	teamFetchCertID = cert.CertificateID
	teamFetchCertRegistry = srv.URL
	if err := runHumanFetchCert(teamFetchCertCmd); err != nil {
		t.Fatal(err)
	}
	if len(*prompts) != 1 {
		t.Fatalf("fetch prompts=%d", len(*prompts))
	}
	initURL = srv.URL
	initTeam = cert.Team
	t.Setenv("AWEB_HUMAN", "Default Human")
	for _, tc := range []struct{ name, value, want string }{
		{"default name", "", "Default Human"},
		{"explicit name", "  Chosen Human  ", "Chosen Human"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			initHumanName = tc.value
			beforePrompts, beforeConnects := len(*prompts), len(connectNames)
			if err := runHumanConnect(initCmd); err != nil {
				t.Fatal(err)
			}
			if got := len(*prompts) - beforePrompts; got != 1 {
				t.Fatalf("connect prompts=%d, want 1", got)
			}
			if got := len(connectNames) - beforeConnects; got != 1 {
				t.Fatalf("connect requests=%d, want 1", got)
			}
			if got := connectNames[beforeConnects]; got != tc.want {
				t.Fatalf("connect human_name=%q, want %q", got, tc.want)
			}
		})
	}
	c, _, err := h.client(cert.Team, "")
	if err != nil {
		t.Fatal(err)
	}
	c.SetResolver(nil) // bare alias mail needs no remote identity lookup
	before := len(*prompts)
	if _, err := c.SendMessage(context.Background(), &awid.SendMessageRequest{ToAlias: "bob", Subject: "Review", Body: "Please review"}); err != nil {
		t.Fatal(err)
	}
	if messages != 1 || len(*prompts)-before != 2 {
		t.Fatalf("send messages=%d prompts=%d", messages, len(*prompts)-before)
	}
	for _, p := range (*prompts)[before:] {
		if !strings.Contains(p, "bob") || !strings.Contains(p, "Review") || !strings.Contains(p, "sha256") || !strings.Contains(p, "signature ") {
			t.Fatalf("unrecognizable mail prompt %s", p)
		}
	}
	if _, err := c.Inbox(context.Background(), awid.InboxParams{}); err != nil {
		t.Fatal(err)
	}
	// Exercise the same installed manifest dispatch as aw secrets request.
	dir, _ := pluginDir()
	path := manifestPluginManifestPath(dir, "secrets")
	os.MkdirAll(filepath.Dir(path), 0700)
	manifest := fmt.Sprintf(`{"manifest_version":1,"app":{"id":"secrets","version":"1.0.0","origin":%q},"tools":[{"name":"request","method":"POST","path":"/v1/request","input_schema":{"type":"object","properties":{}},"params":[],"body":{"mode":"json"}}]}`, srv.URL)
	if err := os.WriteFile(path, []byte(manifest), 0600); err != nil {
		t.Fatal(err)
	}
	before = len(*prompts)
	result, handled, err := executeInstalledManifestTool("secrets", []string{"request"})
	if err != nil || !handled || result.Status != 200 {
		t.Fatalf("manifest: %v %v %+v", err, handled, result)
	}
	if len(*prompts)-before != 1 {
		t.Fatalf("manifest prompts=%d", len(*prompts)-before)
	}
	if _, err := os.Stat(filepath.Join(h.dir, "signing.key")); !os.IsNotExist(err) {
		t.Fatal("human key exported")
	}

	// Exercise real CLI handlers, including source reads and reply target recovery.
	oldSendTo, oldSendSubject, oldSendBody := mailSendTo, mailSendSubject, mailSendBody
	oldReplyBody, oldShowID := mailReplyBody, mailShowMessageID
	t.Cleanup(func() {
		mailSendTo = oldSendTo
		mailSendSubject = oldSendSubject
		mailSendBody = oldSendBody
		mailReplyBody = oldReplyBody
		mailShowMessageID = oldShowID
	})
	mailSendTo = "bob"
	mailSendSubject = "Review"
	mailSendBody = "Please review"
	before = len(*prompts)
	if err := mailSendCmd.RunE(mailSendCmd, nil); err != nil {
		t.Fatal(err)
	}
	if len(*prompts)-before != 3 {
		t.Fatalf("CLI send prompt count=%d, want lookup+envelope+request", len(*prompts)-before)
	}
	before = len(*prompts)
	if err := mailInboxCmd.RunE(mailInboxCmd, nil); err != nil {
		t.Fatal(err)
	}
	if len(*prompts)-before != 1 {
		t.Fatalf("CLI inbox prompts=%d", len(*prompts)-before)
	}
	mailShowMessageID = "incoming"
	before = len(*prompts)
	if err := mailShowCmd.RunE(mailShowCmd, nil); err != nil {
		t.Fatal(err)
	}
	if len(*prompts)-before != 1 {
		t.Fatalf("CLI show prompts=%d", len(*prompts)-before)
	}
	mailReplyBody = "Reply body"
	before = len(*prompts)
	if err := mailReplyCmd.RunE(mailReplyCmd, []string{"incoming"}); err != nil {
		t.Fatal(err)
	}
	if len(*prompts)-before != 5 {
		t.Fatalf("CLI reply prompts=%d, want source+participants+envelope+request+ack", len(*prompts)-before)
	}
	for _, prompt := range (*prompts)[len(*prompts)-2:] {
		if !strings.Contains(prompt, "bob") || !strings.Contains(prompt, "Review") || !strings.Contains(prompt, "sha256") {
			t.Fatalf("reply prompt=%s", prompt)
		}
	}

	if !reflect.DeepEqual(beforeWorkspace, snapshotJoinFiles(t, cwd)) {
		t.Fatal("human operation changed adjacent agent workspace")
	}
	_, sel, err := h.client(cert.Team, "")
	if err != nil {
		t.Fatal(err)
	}
	before = len(*prompts)
	if err := configureClientE2EE(context.Background(), c, sel, true); err == nil {
		t.Fatal("human encrypted send accepted without custody")
	}
	if len(*prompts) != before || !reflect.DeepEqual(beforeWorkspace, snapshotJoinFiles(t, cwd)) {
		t.Fatal("encrypted refusal touched agent custody")
	}
	// Real verifier negative: unavailable current evidence refuses the same client.
	evidence.AgeSeconds = nil
	_, err = c.Inbox(context.Background(), awid.InboxParams{})
	if err == nil {
		t.Fatal("unavailable evidence accepted")
	}
}

func TestHumanParticipationRefusesConflictingMissingAndMismatchedEvidence(t *testing.T) {
	h, prompts, _, key := humanParticipationFixture(t)
	load := func() error {
		_, err := loadHumanParticipation(h.record.StableID, h.record.Domain, awconfig.HumanKeychain{}, func(string) ([]byte, error) { t.Fatal("refusal prompted"); return nil, nil }, func() error { return nil })
		return err
	}
	t.Setenv("AWEB_IDENTITY_HOME", t.TempDir())
	if err := load(); err == nil {
		t.Fatal("agent home silently replaced")
	}
	t.Setenv("AWEB_IDENTITY_HOME", "")
	if err := os.Remove(filepath.Join(h.dir, "id-chain.json")); err != nil {
		t.Fatal(err)
	}
	if err := load(); err == nil {
		t.Fatal("missing chain accepted")
	}
	if err := awconfig.SaveInstalledIDChain(h.dir, h.chain); err != nil {
		t.Fatal(err)
	}
	h.record.State = awconfig.HumanPrepared
	awconfig.SaveHumanRecord(h.record)
	if err := load(); err == nil {
		t.Fatal("unregistered local record accepted")
	}
	_, controller, _ := awid.GenerateKeypair()
	_, other, _ := awid.GenerateKeypair()
	for _, tc := range []struct{ name, did, id string }{{"wrong-key", awid.ComputeDIDKey(other.Public().(ed25519.PublicKey)), h.record.StableID}, {"wrong-id", h.record.DIDKey, awid.ComputeStableID(other.Public().(ed25519.PublicKey))}} {
		cert, err := awid.SignTeamCertificate(controller, awid.TeamCertificateFields{Team: "demo:example.com", Alias: "alice", MemberDIDKey: tc.did, MemberDIDAW: tc.id, IdentityScope: awid.IdentityModeLocal})
		if err != nil {
			t.Fatal(err)
		}
		path, err := awconfig.SaveTeamCertificateForTeamToIdentityHome(h.dir, cert.Team, cert)
		if err != nil {
			t.Fatal(err)
		}
		awconfig.SaveTeamStateToIdentityHome(h.dir, &awconfig.TeamState{ActiveTeam: cert.Team, Memberships: []awconfig.TeamMembership{{TeamID: cert.Team, CertPath: path}}})
		if _, _, _, err := h.membership(cert.Team); err == nil {
			t.Fatalf("%s accepted", tc.name)
		}
	}
	if len(*prompts) != 0 {
		t.Fatal("local mismatch asked for key")
	}
	// Cancellation and a stale keychain item cannot transmit an ordinary request.
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.Write([]byte(`{}`)) }))
	defer srv.Close()
	for _, sign := range []awid.InteractiveSigner{
		func([]byte, string) (string, []byte, error) { return "", nil, fmt.Errorf("cancelled") },
		func(p []byte, _ string) (string, []byte, error) {
			return awid.ComputeDIDKey(other.Public().(ed25519.PublicKey)), ed25519.Sign(other, p), nil
		},
	} {
		client, err := awid.NewWithInteractiveSigner(srv.URL, awid.ComputeDIDKey(key.Public().(ed25519.PublicKey)), nil, sign)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := client.DoRaw(context.Background(), "GET", "/v1/messages/inbox", "application/json", nil); err == nil {
			t.Fatal("invalid signature transmitted")
		}
	}
	if calls != 0 {
		t.Fatalf("refused signature transmitted %d requests", calls)
	}
}
