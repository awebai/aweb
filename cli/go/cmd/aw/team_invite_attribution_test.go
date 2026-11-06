package main

import (
	"context"
	"encoding/base64"
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
		IDChild: &awconfig.TeamInviteIDChild{ChildHome: home, ChildDIDKey: v.Keys["coordinator"].DIDKey, InvitationID: id, IssuerHome: "/private/issuer", RegistryURL: "https://issuer-registry.example"}}
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
	if !strings.Contains(string(raw), "issuer_home") || strings.Contains(string(public), "issuer_home") || strings.Contains(string(public), "id_child") || strings.Contains(string(public), "issuer-registry.example") {
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

// Enrollment is carried on key resolution even when the domain has no tree
// root. The external registry boundary is HTTP; no TXT or status is supplied.
func TestTeamInviteChainlessGlobalEnrollmentWithoutTreeRoot(t *testing.T) {
	for _, tc := range []struct {
		name    string
		tree    any
		omit    bool
		allowed bool
	}{
		{name: "not enrolled", tree: map[string]any{"enrolled": false}, allowed: true},
		{name: "unknown", omit: true},
		{name: "malformed", tree: map[string]any{"enrolled": "false"}},
		{name: "enrolled", tree: map[string]any{"enrolled": true, "domain": "example.com"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := loadWhoVectors(t)
			dir := whoIdentity(t, v, false, true)
			keyReads := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.Path != "/v1/did/"+v.Keys["coordinator"].DIDAW+"/key" {
					t.Errorf("unexpected authority request: %s %s", r.Method, r.URL.Path)
					http.NotFound(w, r)
					return
				}
				keyReads++
				response := map[string]any{"did_aw": v.Keys["coordinator"].DIDAW, "current_did_key": v.Keys["coordinator"].DIDKey}
				if !tc.omit {
					response["id_tree"] = tc.tree
				}
				_ = json.NewEncoder(w).Encode(response)
			}))
			defer server.Close()
			path := filepath.Join(dir, ".aw", "identity.yaml")
			identity, err := awconfig.LoadWorktreeIdentityFrom(path)
			if err != nil {
				t.Fatal(err)
			}
			identity.RegistryURL = server.URL
			if err := awconfig.SaveWorktreeIdentityTo(path, identity); err != nil {
				t.Fatal(err)
			}
			link, err := prepareTeamInviteIDChild(context.Background(), idChildOptions{WorkingDir: dir, TXTResolver: staticTXTResolver{}, Now: time.Now})
			if (err == nil) != tc.allowed || link != nil {
				t.Fatalf("allowed=%v: link=%+v err=%v", tc.allowed, link, err)
			}
			if keyReads != 1 {
				t.Fatalf("key reads=%d, want 1", keyReads)
			}
			if _, err := os.Stat(awconfig.IdentityInvitationsDir(filepath.Join(dir, ".aw"))); !os.IsNotExist(err) {
				t.Fatalf("chainless refusal or membership-only path created an ID invitation: %v", err)
			}
		})
	}
}

// A membership registry is an operation fallback, not a replacement for the
// selected parent's home registry. Exercise the actual invitation call site.
func TestLocalTeamInviteKeepsTheInvitersRegistry(t *testing.T) {
	for _, scenario := range []string{"discovered", "own pin wins", "other namespace", "contradictory authority", "stale key", "unknown enrollment"} {
		t.Run(scenario, func(t *testing.T) {
			v := loadWhoVectors(t)
			dir := whoIdentity(t, v, false, true)
			t.Setenv("APP_ENV", "development")
			t.Setenv("AWID_REGISTRY_URL", "")
			keyReads := 0
			registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1/did/"+v.Keys["coordinator"].DIDAW+"/key" {
					t.Errorf("unexpected request %s", r.URL.Path)
					http.NotFound(w, r)
					return
				}
				keyReads++
				key := v.Keys["coordinator"].DIDKey
				if scenario == "stale key" {
					key = v.Keys["alice"].DIDKey
				}
				response := map[string]any{"did_aw": v.Keys["coordinator"].DIDAW, "current_did_key": key}
				if scenario != "unknown enrollment" {
					response["id_tree"] = map[string]any{"enrolled": false}
				}
				json.NewEncoder(w).Encode(response)
			}))
			defer registry.Close()
			trapReads := 0
			trap := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				trapReads++
				http.Error(w, "wrong parent registry", 500)
			}))
			defer trap.Close()
			path := filepath.Join(dir, ".aw", "identity.yaml")
			identity, err := awconfig.LoadWorktreeIdentityFrom(path)
			if err != nil {
				t.Fatal(err)
			}
			identity.RegistryURL = ""
			operationRegistry := registry.URL
			teamDomain := "example.com"
			if scenario == "own pin wins" {
				identity.RegistryURL = registry.URL
				operationRegistry = trap.URL
			}
			if scenario == "other namespace" {
				teamDomain = "other.example.com"
				operationRegistry = trap.URL
			}
			if err := awconfig.SaveWorktreeIdentityTo(path, identity); err != nil {
				t.Fatal(err)
			}
			dnsRegistry := ""
			if scenario == "other namespace" || scenario == "contradictory authority" {
				dnsRegistry = strings.Replace(registry.URL, "127.0.0.1", "registry.example", 1)
			}
			if scenario == "contradictory authority" {
				operationRegistry = trap.URL
			}
			serveRosterTXT(t, idCreateDNSRecordValue(v.Keys["root"].DIDKey, dnsRegistry))
			_, teamKey, err := awid.GenerateKeypair()
			if err != nil {
				t.Fatal(err)
			}
			if err := awconfig.SaveTeamKey(teamDomain, "backend", teamKey); err != nil {
				t.Fatal(err)
			}
			_, token, err := createTeamInviteTokenAt(teamDomain, "backend", operationRegistry, "https://service.example", true, "", dir, "")
			refused := scenario == "contradictory authority" || scenario == "stale key" || scenario == "unknown enrollment"
			if refused {
				if err == nil || token != "" {
					t.Fatalf("refusal produced invitation: %v", err)
				}
				if scenario == "contradictory authority" && !strings.Contains(err.Error(), "contradicts") {
					t.Fatalf("wrong refusal: %v", err)
				}
			} else if err != nil || token == "" {
				t.Fatalf("lost parent registry: %v", err)
			}
			wantReads := 1
			if scenario == "contradictory authority" {
				wantReads = 0
			}
			if keyReads != wantReads || trapReads != 0 {
				t.Fatalf("own reads=%d want=%d wrong registry=%d", keyReads, wantReads, trapReads)
			}
		})
	}
}

func TestLinkedInviteRetainsIssuerRegistryForRechecksAndExchange(t *testing.T) {
	v := loadWhoVectors(t)
	dir := whoIdentity(t, v, true, false)
	t.Setenv("AWID_REGISTRY_URL", "")
	statusReads := 0
	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/id-certificates/status" {
			t.Errorf("unexpected request %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		statusReads++
		json.NewEncoder(w).Encode(v.Statuses["normal"])
	}))
	defer registry.Close()
	serveRosterTXT(t, idCreateDNSRecordValue(v.Keys["root"].DIDKey, ""))
	path := filepath.Join(dir, ".aw", "identity.yaml")
	identity, err := awconfig.LoadWorktreeIdentityFrom(path)
	if err != nil {
		t.Fatal(err)
	}
	identity.RegistryURL = registry.URL
	if err := awconfig.SaveWorktreeIdentityTo(path, identity); err != nil {
		t.Fatal(err)
	}
	link, err := prepareTeamInviteIDChild(context.Background(), idChildOptions{WorkingDir: dir, Now: time.Now})
	if err != nil || link == nil {
		t.Fatalf("prepare: %v", err)
	}
	identity.RegistryURL = ""
	if err := awconfig.SaveWorktreeIdentityTo(path, identity); err != nil {
		t.Fatal(err)
	}
	if err := checkTeamInviteIssuer(context.Background(), link); err != nil {
		t.Fatalf("recheck lost issuer registry: %v", err)
	}
	// The retained route is used through receive, approve and import too.
	child := t.TempDir()
	pub, key, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(child, ".aw")
	if err := awid.SaveSigningKey(filepath.Join(home, "signing.key"), key); err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveWorktreeIdentityTo(filepath.Join(home, "identity.yaml"), &awconfig.WorktreeIdentity{DID: awid.ComputeDIDKey(pub), Custody: awid.CustodySelf, IdentityScope: awid.IdentityModeLocal}); err != nil {
		t.Fatal(err)
	}
	if err := completeTeamInviteIDChild(context.Background(), &awconfig.TeamInvite{IDChild: link}, child, home); err != nil {
		t.Fatal(err)
	}
	installed, err := awconfig.LoadInstalledIDChain(home)
	if err != nil || installed == nil {
		t.Fatalf("child import: %v", err)
	}
	if statusReads < 3 {
		t.Fatalf("linked exchange skipped live rechecks: %d", statusReads)
	}
}

// The linked route is not authority to override a newly selected home or a
// contradictory namespace record.
func TestLinkedInviteRegistryHonorsCurrentHomeAndNamespace(t *testing.T) {
	v := loadWhoVectors(t)
	dir := whoIdentity(t, v, true, false)
	t.Setenv("AWID_REGISTRY_URL", "")
	reads := 0
	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reads++
		if r.URL.Path != "/v1/id-certificates/status" {
			t.Errorf("unexpected request %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		json.NewEncoder(w).Encode(v.Statuses["normal"])
	}))
	defer registry.Close()
	serveRosterTXT(t, idCreateDNSRecordValue(v.Keys["root"].DIDKey, ""))
	path := filepath.Join(dir, ".aw", "identity.yaml")
	identity, err := awconfig.LoadWorktreeIdentityFrom(path)
	if err != nil {
		t.Fatal(err)
	}
	identity.RegistryURL = registry.URL
	if err := awconfig.SaveWorktreeIdentityTo(path, identity); err != nil {
		t.Fatal(err)
	}
	link, err := prepareTeamInviteIDChild(context.Background(), idChildOptions{WorkingDir: dir, Now: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	oldRoute := link.RegistryURL
	// A different saved home wins over a retained operation route.
	link.RegistryURL = "http://127.0.0.1:1"
	before := reads
	if err := checkTeamInviteIssuer(context.Background(), link); err != nil || reads <= before {
		t.Fatalf("own home not used: %v", err)
	}
	identity.RegistryURL = ""
	if err := awconfig.SaveWorktreeIdentityTo(path, identity); err != nil {
		t.Fatal(err)
	}
	link.RegistryURL = oldRoute
	serveRosterTXT(t, idCreateDNSRecordValue(v.Keys["root"].DIDKey, "https://other.example"))
	before = reads
	if err := checkTeamInviteIssuer(context.Background(), link); err == nil || !strings.Contains(err.Error(), "contradicts") {
		t.Fatalf("namespace conflict not refused: %v", err)
	}
	if reads != before {
		t.Fatal("queried contradicted retained route")
	}
}
