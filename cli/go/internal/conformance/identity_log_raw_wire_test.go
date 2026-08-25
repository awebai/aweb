package conformance_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	awid "github.com/awebai/aw/awid"
)

type identityLogRawWireVectors struct {
	Schema string `json:"schema"`
	Cases  []struct {
		Name            string `json:"name"`
		ResolutionJSON  string `json:"resolution_json"`
		CachedJSON      string `json:"cached_json"`
		ExpectedOutcome string `json:"expected_outcome"`
		// Positive per-runtime expectations. A nullable note that doubled as a
		// branch selector let the corpus change WHICH assertion ran, which is the
		// divergence-hiding property a conformance corpus exists to prevent.
		ExpectedErrorSubstrings struct {
			Go      []string `json:"go"`
			GoInt32 []string `json:"go_int32"`
		} `json:"expected_error_substrings"`
	} `json:"cases"`
}

type identityLogRawWireRoute struct {
	DIDAW         string          `json:"did_aw"`
	CurrentDIDKey string          `json:"current_did_key"`
	LogHead       json.RawMessage `json:"log_head"`
}

type identityLogRawWireCached struct {
	Seq           int    `json:"seq"`
	EntryHash     string `json:"entryHash"`
	StateHash     string `json:"stateHash"`
	CurrentDIDKey string `json:"currentDidKey"`
}

type forbiddenTXTResolver struct {
	t *testing.T
}

func (r forbiddenTXTResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	r.t.Helper()
	r.t.Fatalf("unexpected live DNS lookup for %s", name)
	return nil, nil
}

// TestIdentityLogRawWireVectors sends the embedded resolution JSON through the
// registry resolver unchanged. Decoding it into DidKeyResolution in this test
// would make encoding/json in the harness, rather than the production registry
// path, decide whether malformed wire reaches verification.
func TestIdentityLogRawWireVectors(t *testing.T) {
	data := readRootVector(t, "identity-log-raw-wire-v1.json")
	var vectors identityLogRawWireVectors
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	if vectors.Schema != "aweb.identity-log.raw-wire.v1" {
		t.Fatalf("schema=%q", vectors.Schema)
	}
	if len(vectors.Cases) == 0 {
		t.Fatal("expected raw-wire cases")
	}

	for _, c := range vectors.Cases {
		t.Run(c.Name, func(t *testing.T) {
			if c.ExpectedOutcome != string(awid.StableIdentityHardError) {
				t.Fatalf("expected_outcome=%q", c.ExpectedOutcome)
			}
			var route identityLogRawWireRoute
			if err := json.Unmarshal([]byte(c.ResolutionJSON), &route); err != nil {
				t.Fatalf("decode route metadata without decoding log_head: %v", err)
			}
			if route.DIDAW == "" || route.CurrentDIDKey == "" || len(route.LogHead) == 0 {
				t.Fatal("raw resolution is missing route metadata")
			}
			var cached identityLogRawWireCached
			if err := json.Unmarshal([]byte(c.CachedJSON), &cached); err != nil {
				t.Fatalf("decode cached checkpoint: %v", err)
			}

			mux := http.NewServeMux()
			mux.HandleFunc("/v1/namespaces/acme.com/addresses/alice", func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprintf(w, `{"address_id":"address-1","domain":"acme.com","name":"alice","did_aw":%q,"current_did_key":%q,"created_at":"2026-01-01T00:00:00Z"}`, route.DIDAW, route.CurrentDIDKey)
			})
			mux.HandleFunc("/v1/did/"+route.DIDAW+"/key", func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(c.ResolutionJSON))
			})
			server := httptest.NewServer(mux)
			t.Cleanup(server.Close)

			resolver := awid.NewRegistryResolver(server.Client(), forbiddenTXTResolver{t: t})
			if err := resolver.SetFallbackRegistryURL(server.URL); err != nil {
				t.Fatal(err)
			}
			resolver.SeedVerifiedHead(route.DIDAW, &awid.VerifiedLogHead{
				Seq:           cached.Seq,
				EntryHash:     cached.EntryHash,
				StateHash:     cached.StateHash,
				CurrentDIDKey: cached.CurrentDIDKey,
			})

			_, err := resolver.ResolveFresh(context.Background(), "acme.com/alice")
			if err == nil {
				t.Fatal("raw-wire case unexpectedly resolved")
			}
			// Expectations come from the vector, so the corpus states what each
			// runtime must do rather than selecting an assertion for it.
			want := c.ExpectedErrorSubstrings.Go
			if strconv.IntSize == 32 && len(c.ExpectedErrorSubstrings.GoInt32) > 0 {
				want = c.ExpectedErrorSubstrings.GoInt32
			}
			if len(want) == 0 {
				t.Fatalf("vector %q carries no Go error expectation", c.Name)
			}
			for _, substr := range want {
				if !strings.Contains(err.Error(), substr) {
					t.Fatalf("error %q does not contain %q", err.Error(), substr)
				}
			}
		})
	}
}
