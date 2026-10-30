package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

// Presented ancestry must never be discarded when current evidence is absent.
func TestTeamInviteRefusesUnavailableChainedIssuer(t *testing.T) {
	v := loadWhoVectors(t)
	dir := whoIdentity(t, v, true, false)
	t.Chdir(dir)
	_, key, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveTeamKey("example.com", "backend", key); err != nil {
		t.Fatal(err)
	}
	_, err = prepareTeamInviteIDChild(context.Background(), idChildOptions{WorkingDir: dir, RegistryURL: "http://127.0.0.1:1", TXTResolver: staticTXTResolver{}, Now: time.Now})
	if err == nil {
		t.Fatal("chained inviter created a chainless invite without current evidence")
	}
	invites, err := awconfig.DefaultTeamInvitesDir()
	if err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(invites)
	if len(entries) != 0 {
		t.Fatal("refusal left a usable invite")
	}
}

// Local parents are ordinary identity parents; their did:key is their ID.
func TestInviteChildRequestCanNameALocalIDParent(t *testing.T) {
	v := loadWhoVectors(t)
	dir := whoIdentity(t, v, false, false)
	id, err := newInvitationID()
	if err != nil {
		t.Fatal(err)
	}
	out, raw, err := executeIDParentRequest(idParentOptions{WorkingDir: dir, Domain: "example.com"}, id, v.Keys["alice"].DIDKey, false)
	if err != nil {
		t.Fatal(err)
	}
	request, err := awid.ParseIDCertificateRequest(raw)
	if err != nil {
		t.Fatal(err)
	}
	if request["request"].(map[string]any)["parent"].(map[string]any)["id"] != v.Keys["alice"].DIDKey {
		t.Fatal("lost local parent")
	}
	stored, err := (awconfig.IDRequestFileStore{Dir: awconfig.IdentityRequestsDir(filepath.Join(dir, ".aw"))}).ForInvitation(id)
	if err != nil || stored == nil || stored.RequestID != out.RequestID || stored.Request != string(raw) {
		t.Fatalf("lost exact retry request: %+v %v", stored, err)
	}
}

func TestInviteResumeRequiresTheSameRecipientAndKey(t *testing.T) {
	v := loadWhoVectors(t)
	dir := whoIdentity(t, v, false, false)
	home := filepath.Join(dir, ".aw")
	id, _ := newInvitationID()
	invite := &awconfig.TeamInvite{InviteID: id, Domain: "example.com", TeamName: "backend", Secret: "fixture",
		IDChild: &awconfig.TeamInviteIDChild{ChildHome: home, ChildDIDKey: v.Keys["coordinator"].DIDKey, InvitationID: id, IssuerHome: "/private/issuer"}}
	if err := awconfig.SaveTeamInvite(invite); err != nil {
		t.Fatal(err)
	}
	token, err := awconfig.EncodeInviteToken(invite)
	if err != nil {
		t.Fatal(err)
	}
	if !canResumeTeamInviteIDChild(token, home) {
		t.Fatal("same recipient cannot resume")
	}
	if canResumeTeamInviteIDChild(token, filepath.Join(t.TempDir(), ".aw")) {
		t.Fatal("different home can resume")
	}
	raw, _ := json.Marshal(invite)
	public, _ := base64.RawURLEncoding.DecodeString(token)
	if !strings.Contains(string(raw), "issuer_home") || strings.Contains(string(public), "issuer_home") || strings.Contains(string(public), "id_child") {
		t.Fatalf("private linkage leaked into token: %s", public)
	}
	if err := os.Remove(filepath.Join(home, "signing.key")); err != nil {
		t.Fatal(err)
	}
	if canResumeTeamInviteIDChild(token, home) {
		t.Fatal("missing original key can resume")
	}
	if _, err := bindTeamInviteIDChild(context.Background(), invite, home); err == nil {
		t.Fatal("missing key could mint a different recipient on retry")
	}
}

func TestExistingLocalIdentityDoesNotAcquireAnInviteParent(t *testing.T) {
	v := loadWhoVectors(t)
	dir := whoIdentity(t, v, false, false)
	invite := &awconfig.TeamInvite{IDChild: &awconfig.TeamInviteIDChild{IssuerHome: "unavailable"}}
	issue, err := bindTeamInviteIDChild(context.Background(), invite, filepath.Join(dir, ".aw"))
	if err != nil || issue {
		t.Fatalf("existing identity changed parent: %v %v", issue, err)
	}
}

// This is the real registry's revoke endpoint and status, not a status mock.
// DNS is injected locally; only the CoreDNS journey performs external DNS.
func TestTeamInviteRefusesARevokedIssuerWithRealAWID(t *testing.T) {
	f := newRotateKeyFixture(t, "example.com")
	resolver := staticTXTResolver{"_awid.example.com": {idCreateDNSRecordValue(awid.ComputeDIDKey(f.controllerKey.Public().(ed25519.PublicKey)), "")}}
	dir := t.TempDir()
	created, err := executeIDCreate(dir, idCreateOptions{Name: "inviter", Domain: f.domain, RegistryURL: f.registryURL, SkipDNSVerify: true, RootParent: true, TXTResolver: resolver, Now: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	opts := idChildOptions{WorkingDir: dir, RegistryURL: f.registryURL, TXTResolver: resolver, Now: time.Now}
	link, err := prepareTeamInviteIDChild(context.Background(), opts)
	if err != nil || link == nil {
		t.Fatalf("valid neighboring issuer refused: %+v %v", link, err)
	}
	chain, err := awconfig.LoadInstalledIDChain(filepath.Join(dir, ".aw"))
	if err != nil {
		t.Fatal(err)
	}
	certs := chain.Bundle["certificates"].([]any)
	head, err := awid.IDCertificateID(certs[len(certs)-1].(map[string]any)["certificate"].(map[string]any))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.registry.RevokeIDCertificateAt(context.Background(), f.registryURL, f.domain, created.DIDAW, awid.KeySigner(f.controllerKey), &head, nil); err != nil {
		t.Fatal(err)
	}
	// The exact outstanding invitation and a newly issued one both refuse.
	issuer, err := selectChildIssuer(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkSelectedTeamInviteIssuer(context.Background(), issuer); err == nil || !strings.Contains(err.Error(), "revoked_identity") {
		t.Fatalf("revoked outstanding issuer: %v", err)
	}
	if next, err := prepareTeamInviteIDChild(context.Background(), opts); err == nil || next != nil || !strings.Contains(err.Error(), "revoked_identity") {
		t.Fatalf("revoked new issuer: %+v %v", next, err)
	}
	entries, err := os.ReadDir(awconfig.IdentityIssuanceDir(filepath.Join(dir, ".aw")))
	if !os.IsNotExist(err) && err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatal("revoked inviter issued a child")
	}
}
