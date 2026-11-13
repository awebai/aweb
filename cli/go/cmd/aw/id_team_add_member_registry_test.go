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

// namespaceRegistryTransport forwards requests for the namespace's own
// registry host to a local server and refuses every other host, recording it.
// Nothing reaches a public registry, even when the command asks for one.
type namespaceRegistryTransport struct {
	target  *url.URL
	mu      sync.Mutex
	refused []string
}

func (t *namespaceRegistryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Host != "registry.acme.test" || t.target == nil {
		t.mu.Lock()
		t.refused = append(t.refused, req.URL.Host)
		t.mu.Unlock()
		return nil, errors.New("this test reaches only the namespace's own registry")
	}
	forwarded := req.Clone(req.Context())
	forwarded.URL.Scheme, forwarded.URL.Host = t.target.Scheme, t.target.Host
	return http.DefaultTransport.RoundTrip(forwarded)
}

// failingTXTResolver is DNS that cannot answer.
type failingTXTResolver struct{}

func (failingTXTResolver) LookupTXT(context.Context, string) ([]string, error) {
	return nil, errors.New("dns unavailable")
}

func addMemberWorld(t *testing.T, txt awid.TXTResolver, registry *url.URL) *namespaceRegistryTransport {
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
	transport := &namespaceRegistryTransport{target: registry}
	previous := teamAddMemberRegistryClient
	teamAddMemberRegistryClient = func() (*awid.RegistryClient, error) {
		client := newAWIDRegistryClient(&http.Client{Transport: transport}, txt)
		// The namespace's registry is reached with this client's transport, as
		// one the operator trusts; which registry that is still comes only
		// from the _awid record.
		if err := client.TrustRegistryOrigin("https://registry.acme.test"); err != nil {
			return nil, err
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
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/namespaces/acme.com/teams/backend/certificates") {
			_ = json.NewDecoder(r.Body).Decode(&registered)
			w.WriteHeader(http.StatusCreated)
			return
		}
		http.NotFound(w, r)
	}))
	controller, _, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	target, _ := url.Parse(server.URL)
	transport := addMemberWorld(t, staticTXTResolver{"_awid.acme.com": {idCreateDNSRecordValue(awid.ComputeDIDKey(controller), "https://registry.acme.test")}}, target)
	if err := runTeamAddMember(&cobra.Command{}, nil); err != nil {
		t.Fatalf("add-member: %v (refused hosts %v)", err, transport.refused)
	}
	if registered["alias"] != "laptop" || len(transport.refused) != 0 {
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
