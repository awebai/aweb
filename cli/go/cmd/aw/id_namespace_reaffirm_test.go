package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/zalando/go-keyring"
)

// reaffirmRegistry is a fixture AWID registry for one namespace: it serves the
// namespace row, the registration route and the ID-certificate status, and
// records every registration. Like AWID, status answers 503
// evidence_unavailable whenever the domain has no open epoch for its stored
// controller, and the epochs otherwise.
type reaffirmRegistry struct {
	mu         sync.Mutex
	stored     string
	epochs     []map[string]any
	opensEpoch bool
	posts      int
}

func (r *reaffirmRegistry) handler(t *testing.T, domain string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.mu.Lock()
		defer r.mu.Unlock()
		switch {
		case req.Method == http.MethodGet && req.URL.Path == "/v1/namespaces/"+domain:
			_ = json.NewEncoder(w).Encode(map[string]any{"namespace_id": "ns-1", "domain": domain, "controller_did": r.stored, "verification_status": "verified", "created_at": "2026-01-01T00:00:00Z"})
		case req.Method == http.MethodPost && req.URL.Path == "/v1/namespaces":
			r.posts++
			var body map[string]any
			_ = json.NewDecoder(req.Body).Decode(&body)
			if body["domain"] != domain || body["controller_did"] != r.stored {
				t.Errorf("registration body %v", body)
			}
			// Like AWID, a registration opens only a missing first epoch.
			if r.opensEpoch && len(r.epochs) == 0 {
				r.epochs = []map[string]any{{"seq": 1, "did_key": r.stored, "registered_at": "2026-10-31T12:00:00.000000Z", "retired_at": nil, "continuity": "replaced"}}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"namespace_id": "ns-1", "domain": domain, "controller_did": r.stored, "verification_status": "verified", "created_at": "2026-01-01T00:00:00Z"})
		case req.Method == http.MethodPost && req.URL.Path == "/v1/id-certificates/status":
			var body map[string]any
			_ = json.NewDecoder(req.Body).Decode(&body)
			if body["domain"] != domain || body["v"] != float64(1) {
				t.Errorf("status body %v", body)
			}
			currentRoot := false
			for _, epoch := range r.epochs {
				if epoch["retired_at"] == nil && epoch["did_key"] == r.stored {
					currentRoot = true
				}
			}
			if !currentRoot {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusServiceUnavailable)
				_ = json.NewEncoder(w).Encode(map[string]any{"detail": map[string]string{"code": "evidence_unavailable", "message": "evidence unavailable"}})
				return
			}
			epochs := r.epochs
			_ = json.NewEncoder(w).Encode(map[string]any{"v": 1, "domain": domain, "observed_at": "2026-10-31T12:00:01.000000Z", "namespace": map[string]any{"epochs": epochs}, "identities": []any{}, "missing": []any{}})
		default:
			t.Errorf("unexpected registry request %s %s", req.Method, req.URL.Path)
			http.NotFound(w, req)
		}
	})
}

// aw id namespace reaffirm opens a BYOT namespace's first ID-tree epoch
// through the existing signed registration, only for the stored controller
// with exact DNS, and believes only the epochs it reads back.
func TestIDNamespaceReaffirm(t *testing.T) {
	const domain = "juanreyero.example"
	for _, tc := range []struct {
		name                 string
		dnsOther, storeOther bool
		enrolled, noEpoch    bool
		retiredOnly          bool
		wantStatus, wantErr  string
		wantPosts            int
	}{
		{name: "opens the first epoch", wantStatus: "opened", wantPosts: 1},
		{name: "already enrolled", enrolled: true, wantStatus: "already_enrolled"},
		{name: "DNS names another key", dnsOther: true, wantErr: "_awid." + domain + " names"},
		{name: "the registry stores another controller", storeOther: true, wantErr: "aw id namespace rotate-controller --domain " + domain},
		{name: "the registry opens no epoch", noEpoch: true, wantErr: "the registry did not open an epoch for " + domain + "; it opens only a missing first epoch", wantPosts: 1},
		// Epoch history with none open: the server opens only a missing
		// first epoch, so the registration changes nothing and says so.
		{name: "history but no open epoch", retiredOnly: true, wantErr: "it opens only a missing first epoch for the stored controller with exact DNS", wantPosts: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			keyring.MockInit()
			t.Setenv("HOME", t.TempDir())
			t.Setenv("AW_CONFIG_PATH", "")
			pub, key, _ := awid.GenerateKeypair()
			did := awid.ComputeDIDKey(pub)
			if err := awconfig.SaveControllerKey(domain, key); err != nil {
				t.Fatal(err)
			}
			otherPub, _, _ := ed25519.GenerateKey(nil)
			other := awid.ComputeDIDKey(otherPub)

			fixture := &reaffirmRegistry{stored: did, opensEpoch: !tc.noEpoch}
			if tc.storeOther {
				fixture.stored = other
			}
			if tc.enrolled {
				fixture.epochs = []map[string]any{{"seq": 1, "did_key": did, "registered_at": "2026-10-01T00:00:00.000000Z", "retired_at": nil, "continuity": "replaced"}}
			}
			if tc.retiredOnly {
				fixture.epochs = []map[string]any{{"seq": 1, "did_key": did, "registered_at": "2026-09-01T00:00:00.000000Z", "retired_at": "2026-09-02T00:00:00.000000Z", "continuity": "replaced"}}
			}
			server := httptest.NewServer(fixture.handler(t, domain))
			defer server.Close()
			dnsKey := did
			if tc.dnsOther {
				dnsKey = other
			}
			out, err := executeIDNamespaceReaffirm(context.Background(), idNamespaceReaffirmOptions{
				Domain:      domain,
				RegistryURL: server.URL,
				TXTResolver: staticTXTResolver{"_awid." + domain: {idCreateDNSRecordValue(dnsKey, "")}},
			})
			fixture.mu.Lock()
			posts := fixture.posts
			fixture.mu.Unlock()
			if posts != tc.wantPosts {
				t.Fatalf("registrations=%d, want %d", posts, tc.wantPosts)
			}
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err=%v, want it to contain %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if out.Status != tc.wantStatus || out.Domain != domain || out.ControllerDID != did || out.Epoch.Seq != 1 || out.Epoch.DIDKey != did || out.Epoch.Continuity != "replaced" {
				t.Fatalf("output %+v", out)
			}
		})
	}
}

// Reaffirmation runs only where the namespace's controller key is, and never
// for the reserved local namespace; both refuse before any request.
func TestIDNamespaceReaffirmRefusesWithoutAuthority(t *testing.T) {
	keyring.MockInit()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("AW_CONFIG_PATH", "")
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		http.NotFound(w, r)
	}))
	defer server.Close()
	resolver := staticTXTResolver{"_awid.hosted.example": {idCreateDNSRecordValue("did:key:z6Mkhosted", "")}}
	for _, tc := range []struct{ domain, want string }{
		{"local", "the local namespace has no DNS authority"},
		{"hosted.example", "no controller key for hosted.example here"},
	} {
		if _, err := executeIDNamespaceReaffirm(context.Background(), idNamespaceReaffirmOptions{Domain: tc.domain, RegistryURL: server.URL, TXTResolver: resolver}); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: err=%v, want %q", tc.domain, err, tc.want)
		}
	}
	if calls != 0 {
		t.Fatalf("a refusal made %d registry requests", calls)
	}
}
