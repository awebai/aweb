package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

// namespaceRegistryTransport forwards requests for each namespace registry
// host to its local server and refuses every other host, recording it.
// Nothing reaches a public registry, even when the command asks for one.
type namespaceRegistryTransport struct {
	targets map[string]*url.URL
	mu      sync.Mutex
	refused []string
}

func (t *namespaceRegistryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	target := t.targets[req.URL.Host]
	if target == nil {
		t.mu.Lock()
		t.refused = append(t.refused, req.URL.Host)
		t.mu.Unlock()
		return nil, errors.New("this test reaches only the namespaces' own registries")
	}
	forwarded := req.Clone(req.Context())
	forwarded.URL.Scheme, forwarded.URL.Host = target.Scheme, target.Host
	return http.DefaultTransport.RoundTrip(forwarded)
}

// registryServer is a local registry reached as https://host.
func registryServer(t *testing.T, handler http.HandlerFunc) *url.URL {
	t.Helper()
	target, err := url.Parse(newLocalHTTPServer(t, handler).URL)
	if err != nil {
		t.Fatal(err)
	}
	return target
}

func awidRecord(t *testing.T, registryURL string) []string {
	t.Helper()
	controller, _, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	return []string{idCreateDNSRecordValue(awid.ComputeDIDKey(controller), registryURL)}
}

// failingTXTResolver is DNS that cannot answer.
type failingTXTResolver struct{}

func (failingTXTResolver) LookupTXT(context.Context, string) ([]string, error) {
	return nil, errors.New("dns unavailable")
}

func addMemberWorld(t *testing.T, txt awid.TXTResolver, registries map[string]*url.URL) *namespaceRegistryTransport {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("AW_CONFIG_PATH", "")
	t.Setenv("AWID_REGISTRY_URL", "")
	_, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	writeTeamKeyForTest(t, home, "acme.com", "backend", teamKey)
	transport := &namespaceRegistryTransport{targets: registries}
	previous := teamAddMemberRegistryClient
	teamAddMemberRegistryClient = func() (*awid.RegistryClient, error) {
		client := newAWIDRegistryClient(&http.Client{Transport: transport}, txt)
		// Each namespace's registry is reached with this client's transport, as
		// one the operator trusts; which registry that is still comes only
		// from the _awid records.
		for host := range registries {
			if err := client.TrustRegistryOrigin("https://" + host); err != nil {
				return nil, err
			}
		}
		return client, nil
	}
	t.Cleanup(func() {
		teamAddMemberRegistryClient = previous
		teamAddTeam, teamAddNamespace, teamAddMember = "", "", ""
		teamAddMemberDID, teamAddMemberAlias = "", ""
	})
	memberPub, _, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	teamAddTeam, teamAddNamespace = "backend", "acme.com"
	teamAddMemberDID, teamAddMemberAlias = awid.ComputeDIDKey(memberPub), "laptop"
	return transport
}

func TestAddMemberRegistersTheCertificateAtTheTeamsOwnRegistry(t *testing.T) {
	var registered map[string]any
	team := registryServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/namespaces/acme.com/teams/backend/certificates") {
			_ = json.NewDecoder(r.Body).Decode(&registered)
			w.WriteHeader(http.StatusCreated)
			return
		}
		http.NotFound(w, r)
	})
	txt := staticTXTResolver{"_awid.acme.com": awidRecord(t, "https://registry.acme.test")}
	transport := addMemberWorld(t, txt, map[string]*url.URL{"registry.acme.test": team})
	if err := runTeamAddMember(&cobra.Command{}, nil); err != nil {
		t.Fatalf("add-member: %v (refused hosts %v)", err, transport.refused)
	}
	if registered["alias"] != "laptop" || len(transport.refused) != 0 {
		t.Fatalf("registered %v, refused hosts %v", registered, transport.refused)
	}
}

func TestAddMemberLooksUpAMemberAtItsOwnNamespacesRegistry(t *testing.T) {
	// The member's namespace names a different registry from the team's: the
	// address is read there, and the certificate still goes to the team's.
	memberPub, _, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	memberDIDAW := awid.ComputeStableID(memberPub)
	var registered map[string]any
	team := registryServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/namespaces/acme.com/teams/backend/certificates") {
			_ = json.NewDecoder(r.Body).Decode(&registered)
			w.WriteHeader(http.StatusCreated)
			return
		}
		http.NotFound(w, r)
	})
	partner := registryServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/v1/namespaces/partner.com/addresses/bob" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"address_id": "address-bob", "domain": "partner.com", "name": "bob",
				"did_aw": memberDIDAW, "current_did_key": awid.ComputeDIDKey(memberPub), "reachability": "public",
			})
			return
		}
		http.NotFound(w, r)
	})
	txt := staticTXTResolver{
		"_awid.acme.com":    awidRecord(t, "https://registry.acme.test"),
		"_awid.partner.com": awidRecord(t, "https://registry.partner.test"),
	}
	transport := addMemberWorld(t, txt, map[string]*url.URL{"registry.acme.test": team, "registry.partner.test": partner})
	teamAddMemberDID, teamAddMemberAlias = "", ""
	teamAddMember = "partner.com/bob"
	if err := runTeamAddMember(&cobra.Command{}, nil); err != nil {
		t.Fatalf("add-member: %v (refused hosts %v)", err, transport.refused)
	}
	if registered["member_address"] != "partner.com/bob" || registered["member_did_aw"] != memberDIDAW || len(transport.refused) != 0 {
		t.Fatalf("registered %v, refused hosts %v", registered, transport.refused)
	}
}

func TestAddMemberSendsNothingWhenTheTeamsRegistryCannotBeResolved(t *testing.T) {
	transport := addMemberWorld(t, failingTXTResolver{}, nil)
	if err := runTeamAddMember(&cobra.Command{}, nil); err == nil {
		t.Fatal("add-member succeeded without resolving acme.com's registry")
	}
	if len(transport.refused) != 0 {
		t.Fatalf("refused hosts %v", transport.refused)
	}
}
