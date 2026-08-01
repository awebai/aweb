package awid

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"testing"
)

type strictTestHosts struct{ calls []string }

func (r *strictTestHosts) LookupNetIP(_ context.Context, _ string, host string) ([]netip.Addr, error) {
	r.calls = append(r.calls, host)
	return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
}

type strictRoundTrip func(*http.Request) (*http.Response, error)

func (f strictRoundTrip) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

func TestStrictGoExternalRegistryFetchesGenesisVerifiedEvidence(t *testing.T) {
	var identity struct {
		Mapping struct {
			DIDAW         string `json:"did_aw"`
			InitialDIDKey string `json:"initial_did_key"`
			RotatedDIDKey string `json:"rotated_did_key"`
		} `json:"mapping"`
		Entries []struct {
			EntryPayload map[string]interface{} `json:"entry_payload"`
			EntryHash    string                 `json:"entry_hash"`
			Signature    string                 `json:"signature_b64"`
		} `json:"entries"`
	}
	loadFederationVector(t, "identity-log-v1.json", &identity)
	entries := make([]map[string]interface{}, 0, len(identity.Entries))
	for _, item := range identity.Entries {
		entry := item.EntryPayload
		entry["entry_hash"] = item.EntryHash
		entry["signature"] = item.Signature
		entries = append(entries, entry)
	}
	responses := map[string]interface{}{
		"/v1/namespaces/alpha.example.com": map[string]interface{}{
			"domain": "Alpha.Example.Com.", "controller_did": identity.Mapping.InitialDIDKey,
		},
		"/v1/namespaces/alpha.example.com/addresses/Alice": map[string]interface{}{
			"address_id": "addr-alpha-alice", "domain": "ALPHA.EXAMPLE.COM.", "name": "Alice",
			"did_aw": identity.Mapping.DIDAW, "current_did_key": identity.Mapping.RotatedDIDKey,
			"delivery": map[string]interface{}{"origin": "https://aweb-alpha.example"},
		},
		"/key": map[string]interface{}{
			"did_aw": identity.Mapping.DIDAW, "current_did_key": identity.Mapping.RotatedDIDKey,
			"log_head": entries[len(entries)-1], "status": "OK_DEGRADED",
		},
		"/log": entries,
	}
	requests := []string{}
	client := &http.Client{Transport: strictRoundTrip(func(request *http.Request) (*http.Response, error) {
		requests = append(requests, request.URL.Path)
		key := request.URL.Path
		if strings.HasSuffix(key, "/key") {
			key = "/key"
		} else if strings.HasSuffix(key, "/log") {
			key = "/log"
		}
		body, ok := responses[key]
		if !ok {
			t.Fatalf("unexpected path %s", request.URL.Path)
		}
		encoded, _ := json.Marshal(body)
		return &http.Response{
			StatusCode: 200,
			Header:     http.Header{"Content-Type": {"application/json"}},
			Body:       io.NopCloser(bytes.NewReader(encoded)),
			Request:    request,
		}, nil
	})}
	hosts := &strictTestHosts{}
	factoryCalls := 0
	resolver := &StrictFederationExternalResolver{
		TXTResolver: vectorFederationDNS{
			"_awid.alpha.example.com": {
				Outcome: "record",
				Records: []string{"awid=v1; controller=" + identity.Mapping.InitialDIDKey + "; registry=https://registry-a.example;"},
			},
		},
		HostResolver: hosts,
		HTTPFactory: func(origin string, approved []string, generation int64) (*http.Client, error) {
			factoryCalls++
			if origin != "https://registry-a.example" || generation != 4 || len(approved) != 1 || approved[0] != "93.184.216.34" {
				t.Fatalf("factory origin=%s approved=%v generation=%d", origin, approved, generation)
			}
			return client, nil
		},
	}
	evidence, err := resolver.FetchEvidence(context.Background(), "alpha.example.com/Alice", 4, nil)
	if err != nil {
		t.Fatal(err)
	}
	if evidence.DIDAW != identity.Mapping.DIDAW || evidence.CurrentDIDKey != identity.Mapping.RotatedDIDKey || evidence.VerifiedLog.Seq != 2 {
		t.Fatalf("unexpected evidence %#v", evidence)
	}
	if hosts.calls[0] != "registry-a.example" || factoryCalls != 1 {
		t.Fatalf("hosts=%v factories=%d", hosts.calls, factoryCalls)
	}
	if len(requests) != 4 || !strings.HasSuffix(requests[3], "/log") {
		t.Fatalf("requests=%v", requests)
	}
}

type authorityLookupVector struct {
	AuthorityLookupCases []struct {
		Name           string          `json:"name"`
		Selection      string          `json:"selection"`
		RegistryOrigin string          `json:"registry_origin"`
		Namespace      json.RawMessage `json:"namespace"`
		Address        json.RawMessage `json:"address"`
		Key            json.RawMessage `json:"key"`
		Expected       struct {
			Accepted          bool    `json:"accepted"`
			Reason            *string `json:"reason"`
			FallbackContacted bool    `json:"fallback_contacted"`
			FullLogRequired   *bool   `json:"full_log_required"`
		} `json:"expected"`
	} `json:"authority_lookup_cases"`
}

type lookupCaseTXT struct {
	selection, controller, origin string
}

func (r lookupCaseTXT) LookupFederationTXT(_ context.Context, _ string) (FederationTXTLookup, error) {
	if r.selection == "public_default" {
		return FederationTXTLookup{Outcome: "nxdomain"}, nil
	}
	return FederationTXTLookup{
		Outcome: "record",
		Records: []string{"awid=v1; controller=" + r.controller + "; registry=" + r.origin + ";"},
	}, nil
}

func decodeLookupObject(t *testing.T, raw json.RawMessage) (map[string]interface{}, string) {
	t.Helper()
	if string(raw) == "null" {
		return nil, ""
	}
	var object map[string]interface{}
	if err := json.Unmarshal(raw, &object); err == nil {
		if object == nil {
			return nil, ""
		}
		return object, ""
	}
	var sentinel string
	if err := json.Unmarshal(raw, &sentinel); err != nil {
		t.Fatal(err)
	}
	return nil, sentinel
}

func TestStrictGoClaimComparisonIsIndependent(t *testing.T) {
	evidence := &StrictFederationExternalEvidence{
		CanonicalAddress: "alpha.example.com/Alice",
		DIDAW:            "did:aw:correct",
		CurrentDIDKey:    "did:key:correct",
		DeliveryOrigin:   "https://aweb-alpha.example",
	}
	if err := evidence.CompareClaim("did:aw:wrong", "did:key:correct", "https://aweb-alpha.example"); !IsFederationReason(err, "sender_address_did_mismatch") {
		t.Fatalf("wrong claim error=%v", err)
	}
	if err := evidence.CompareClaim("did:aw:correct", "did:key:correct", "https://aweb-alpha.example"); err != nil {
		t.Fatal(err)
	}
}
