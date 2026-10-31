package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

func TestHostedLocalCreationVerifiesBeforeInstallWithoutPublishingLeaf(t *testing.T) {
	raw, err := os.ReadFile("../../../../docs/vectors/id-certificates-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Keys map[string]struct {
			Seed   string `json:"seed_hex"`
			DIDKey string `json:"did_key"`
		}
		Certificates map[string]struct{ Signed map[string]any }
		Statuses     map[string]map[string]any `json:"status_fixtures"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&vectors); err != nil {
		t.Fatal(err)
	}
	seed, _ := hex.DecodeString(vectors.Keys["root_agent"].Seed)
	key := ed25519.NewKeyFromSeed(seed)
	material := workspaceTeamIdentityMaterial{SigningKey: key, DIDKey: vectors.Keys["root_agent"].DIDKey, IdentityScope: awid.IdentityModeLocal}
	for _, tt := range []struct {
		name, parent string
		register     bool
		ok           bool
	}{
		{"local-root", "example.com", false, true},
		{"unselected-parent", "other.test", false, false},
		{"local-publication-refused", "example.com", true, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			reads, writes := 0, 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "POST" || r.URL.Path != "/v1/id-certificates/status" {
					writes++
					http.Error(w, "unexpected write", 500)
					return
				}
				reads++
				json.NewEncoder(w).Encode(vectors.Statuses["normal"])
			}))
			defer server.Close()
			resolver := staticTXTResolver{"_awid.example.com": {idCreateDNSRecordValue(vectors.Keys["root"].DIDKey, "https://registry.example.test")}}
			transport := server.Client().Transport.(*http.Transport).Clone()
			transport.TLSClientConfig.ServerName = "127.0.0.1"
			transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
			}
			registry := awid.NewAWIDRegistryClient(&http.Client{Transport: transport}, resolver)
			tree := &hostedIDTreeRecovery{Domain: "example.com", Parent: map[string]any{"kind": "namespace", "id": tt.parent}}
			chain := awid.ReceivedIDChain{"v": 1, "type": "aweb.id-chain", "certificates": []any{vectors.Certificates["root-agent"].Signed}}
			response := awid.IDTreeCreationResponse{IDChain: chain}
			if tt.register {
				response.RegistrationRequest = &awid.IDTreeRegistrationRequest{}
			}
			verdict, err := finishHostedIDTree(context.Background(), tree, response, material, root, registry, resolver)
			if (err == nil) != tt.ok {
				t.Fatalf("verdict %+v error %v", verdict, err)
			}
			installed, loadErr := awconfig.LoadInstalledIDChain(root)
			if loadErr != nil {
				t.Fatal(loadErr)
			}
			if tt.ok {
				if installed == nil || verdict == nil || verdict.Outcome != "no_human" || reads != 1 {
					t.Fatalf("installation lacks fresh verification: %+v reads %d", verdict, reads)
				}
			} else if installed != nil {
				t.Fatal("refused chain installed")
			}
			if writes != 0 {
				t.Fatalf("local identity caused %d registry writes", writes)
			}
			if _, err := os.Stat(filepath.Join(root, "identity.yaml")); !os.IsNotExist(err) {
				t.Fatal("chain install fabricated a DID mapping")
			}
		})
	}
}

func TestHostedRegisteredCreationUsesHistoricalIssuerAfterRotation(t *testing.T) {
	raw, err := os.ReadFile("../../../../docs/vectors/id-certificates-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Keys map[string]struct {
			Seed   string `json:"seed_hex"`
			DIDKey string `json:"did_key"`
			DIDAW  string `json:"did_aw"`
		}
		Certificates map[string]struct{ Signed map[string]any }
		Statuses     map[string]map[string]any `json:"status_fixtures"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&v); err != nil {
		t.Fatal(err)
	}
	fixture := v.Keys["global_agent"]
	seed, _ := hex.DecodeString(fixture.Seed)
	writes := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/id-certificates/status" {
			writes++
			http.Error(w, "unexpected write", 500)
			return
		}
		json.NewEncoder(w).Encode(v.Statuses["registered-root-agent-rotated"])
	}))
	defer server.Close()
	transport := server.Client().Transport.(*http.Transport).Clone()
	transport.TLSClientConfig.ServerName = "127.0.0.1"
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}
	resolver := staticTXTResolver{"_awid.example.com": {idCreateDNSRecordValue(v.Keys["root_rotated"].DIDKey, "https://registry.example.test")}}
	registry := awid.NewAWIDRegistryClient(&http.Client{Transport: transport}, resolver)
	tree := &hostedIDTreeRecovery{Domain: "example.com", Parent: map[string]any{"kind": "namespace", "id": "example.com"}}
	response := awid.IDTreeCreationResponse{FieldsPresent: true, IDChain: awid.ReceivedIDChain{"v": 1, "type": "aweb.id-chain", "certificates": []any{v.Certificates["registered-root-agent"].Signed}}}
	material := workspaceTeamIdentityMaterial{SigningKey: ed25519.NewKeyFromSeed(seed), DIDKey: fixture.DIDKey, StableID: fixture.DIDAW, IdentityScope: awid.IdentityModeGlobal}
	verdict, err := finishHostedIDTree(t.Context(), tree, response, material, t.TempDir(), registry, resolver)
	if err != nil || verdict == nil || verdict.IdentityValid == nil || !*verdict.IdentityValid || writes != 0 {
		t.Fatalf("registered chain lost valid historical issuance: %+v %v writes=%d", verdict, err, writes)
	}
}

func TestHostedGlobalCreationResumesSameCertificateAndRefreshesAfterRegistration(t *testing.T) {
	raw, err := os.ReadFile("../../../../docs/vectors/id-certificates-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Keys map[string]struct {
			Seed   string `json:"seed_hex"`
			DIDKey string `json:"did_key"`
			DIDAW  string `json:"did_aw"`
		}
		Certificates map[string]struct{ Signed map[string]any }
		Statuses     map[string]map[string]any `json:"status_fixtures"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&v); err != nil {
		t.Fatal(err)
	}
	fixture := v.Keys["global_agent"]
	seed, _ := hex.DecodeString(fixture.Seed)
	before := v.Statuses["normal"]
	rows := []any{}
	for _, row := range before["identities"].([]any) {
		if row.(map[string]any)["id"] != fixture.DIDAW {
			rows = append(rows, row)
		}
	}
	before["identities"] = rows
	before["missing"] = append(before["missing"].([]any), fixture.DIDAW)
	reads, writes := 0, 0
	var registered atomic.Bool
	var originalBody []byte
	var originalHeader string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/id-certificates/status":
			reads++
			if registered.Load() {
				json.NewEncoder(w).Encode(v.Statuses["registered-root-agent-rotated"])
			} else {
				json.NewEncoder(w).Encode(before)
			}
		case "/v1/id-certificates/register":
			writes++
			body, _ := io.ReadAll(r.Body)
			if writes == 1 {
				originalBody = body
				originalHeader = r.Header.Get("X-AWID-ID-Chain")
				http.Error(w, "temporary registry outage", 503)
				return
			}
			if !bytes.Equal(originalBody, body) || originalHeader != r.Header.Get("X-AWID-ID-Chain") {
				t.Error("registration retry replaced certificate or arguments")
			}
			registered.Store(true)
			io.WriteString(w, `{}`)
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	transport := server.Client().Transport.(*http.Transport).Clone()
	transport.TLSClientConfig.ServerName = "127.0.0.1"
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}
	resolver := staticTXTResolver{"_awid.example.com": {idCreateDNSRecordValue(v.Keys["root"].DIDKey, "https://registry.example.test")}}
	registry := awid.NewAWIDRegistryClient(&http.Client{Transport: transport}, resolver)
	tree := &hostedIDTreeRecovery{Domain: "example.com", Parent: map[string]any{"kind": "namespace", "id": "example.com"}}
	response := awid.IDTreeCreationResponse{FieldsPresent: true, IDChain: awid.ReceivedIDChain{"v": 1, "type": "aweb.id-chain", "certificates": []any{v.Certificates["registered-root-agent"].Signed}}, RegistrationRequest: &awid.IDTreeRegistrationRequest{}}
	material := workspaceTeamIdentityMaterial{SigningKey: ed25519.NewKeyFromSeed(seed), DIDKey: fixture.DIDKey, StableID: fixture.DIDAW, IdentityScope: awid.IdentityModeGlobal}
	root := t.TempDir()
	if _, err := finishHostedIDTree(t.Context(), tree, response, material, root, registry, resolver); err == nil {
		t.Fatal("registry outage installed an unregistered leaf")
	}
	if chain, err := awconfig.LoadInstalledIDChain(root); err != nil || chain != nil {
		t.Fatalf("failed registration installed chain: %v", err)
	}
	// The registration happens under epoch 1; the second public read observes
	// its rotated successor, where historical registration remains valid.
	// Keep the preflight on the old controller, then publish its successor for
	// the post-registration evidence read.
	switching := &registrationTXTResolver{before: resolver, after: staticTXTResolver{"_awid.example.com": {idCreateDNSRecordValue(v.Keys["root_rotated"].DIDKey, "https://registry.example.test")}}, registered: &registered}
	verdict, err := finishHostedIDTree(t.Context(), tree, response, material, root, registry, switching)
	if err != nil || verdict == nil || verdict.IdentityValid == nil || !*verdict.IdentityValid || writes != 2 || reads != 3 {
		t.Fatalf("resume lacks fresh completed verification: %+v %v reads=%d writes=%d", verdict, err, reads, writes)
	}
}

type registrationTXTResolver struct {
	before, after staticTXTResolver
	registered    *atomic.Bool
}

func (r *registrationTXTResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	if r.registered.Load() {
		return r.after.LookupTXT(ctx, name)
	}
	return r.before.LookupTXT(ctx, name)
}

func TestHostedLocalOwnerCannotCreateRegisteredChild(t *testing.T) {
	raw, err := os.ReadFile("../../../../docs/vectors/id-certificates-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Keys map[string]struct {
			Seed   string `json:"seed_hex"`
			DIDKey string `json:"did_key"`
		}
		Certificates map[string]struct{ Signed map[string]any }
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&v); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	chain := map[string]any{"v": 1, "type": "aweb.id-chain", "certificates": []any{v.Certificates["root-agent"].Signed}}
	if err := awconfig.SaveInstalledIDChain(root, chain); err != nil {
		t.Fatal(err)
	}
	seed, _ := hex.DecodeString(v.Keys["root_agent"].Seed)

	key := ed25519.NewKeyFromSeed(seed)
	if err := awid.SaveSigningKey(filepath.Join(root, "signing.key"), key); err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveWorktreeIdentityTo(filepath.Join(root, "identity.yaml"), &awconfig.WorktreeIdentity{DID: v.Keys["root_agent"].DIDKey, Custody: awid.CustodySelf, IdentityScope: awid.IdentityModeLocal, RegistryURL: "http://127.0.0.1:1"}); err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveWorktreeWorkspaceTo(filepath.Join(root, "workspace.yaml"), &awconfig.WorktreeWorkspace{AwebURL: "http://127.0.0.1:1", WorkspacePath: root, Memberships: []awconfig.WorktreeMembership{{TeamID: "agents:example.com", Alias: "owner", CertPath: "team.crt"}}}); err != nil {
		t.Fatal(err)
	}
	owner, err := loadHostedOwnerAuthority(t.TempDir(), awconfig.IdentityHome{Root: t.TempDir()}, root)
	if err != nil {
		t.Fatal(err)
	}
	resolver := &unexpectedHostedOwnerDNS{}

	registry := awid.NewAWIDRegistryClient(nil, staticTXTResolver{})
	registry.DefaultRegistryURL = "http://127.0.0.1:1"
	issuer, err := hostedOwnerIssuer(t.Context(), t.TempDir(), owner, registry, resolver)
	if issuer != nil || awid.IDCertificateErrorCode(err) != "unregistered_parent" || resolver.calls != 0 {
		t.Fatalf("local parent was not refused before global creation: %+v %v", issuer, err)
	}
}

type unexpectedHostedOwnerDNS struct{ calls int }

func (r *unexpectedHostedOwnerDNS) LookupTXT(context.Context, string) ([]string, error) {
	r.calls++
	return nil, errors.New("unexpected DNS before local-parent refusal")
}
