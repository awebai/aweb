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
	for _, test := range []struct {
		name, missingPath, reason string
		contact                   bool
	}{
		{name: "verified_sender"},
		{name: "verified_contact", contact: true},
		{name: "missing_namespace_sender", missingPath: "/v1/namespaces/alpha.example.com", reason: "sender_identity_not_found", contact: false},
		{name: "missing_namespace_contact", missingPath: "/v1/namespaces/alpha.example.com", reason: "recipient_identity_not_found", contact: true},
		{name: "missing_address_sender", missingPath: "/v1/namespaces/alpha.example.com/addresses/Alice", reason: "sender_identity_not_found", contact: false},
		{name: "missing_address_contact", missingPath: "/v1/namespaces/alpha.example.com/addresses/Alice", reason: "recipient_identity_not_found", contact: true},
		{name: "missing_key_sender", missingPath: "/key", reason: "sender_identity_not_found", contact: false},
		{name: "missing_key_contact", missingPath: "/key", reason: "recipient_identity_not_found", contact: true},
		{name: "missing_log_sender", missingPath: "/log", reason: "sender_identity_unverifiable", contact: false},
		{name: "missing_log_contact", missingPath: "/log", reason: "sender_identity_unverifiable", contact: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			requests := []string{}
			client := &http.Client{Transport: strictRoundTrip(func(request *http.Request) (*http.Response, error) {
				requests = append(requests, request.URL.Path)
				if request.URL.Path == test.missingPath || (test.missingPath == "/key" && strings.HasSuffix(request.URL.Path, "/key")) || (test.missingPath == "/log" && strings.HasSuffix(request.URL.Path, "/log")) {
					return &http.Response{StatusCode: http.StatusNotFound, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`{}`)), Request: request}, nil
				}
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
			fetch := resolver.FetchEvidence
			if test.contact {
				fetch = resolver.FetchContactEvidence
			}
			evidence, err := fetch(context.Background(), "alpha.example.com/Alice", 4, nil)
			if test.reason != "" {
				if !IsFederationReason(err, test.reason) || evidence != nil {
					t.Fatalf("evidence=%#v error=%v, want %s", evidence, err, test.reason)
				}
				return
			}
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
		})
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

func TestStrictNamespaceDelegationAuthority(t *testing.T) {
	var vector struct {
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
	loadFederationVector(t, "identity-log-v1.json", &vector)
	entries := make([]map[string]interface{}, 0, len(vector.Entries))
	for _, item := range vector.Entries {
		entry := item.EntryPayload
		entry["entry_hash"], entry["signature"] = item.EntryHash, item.Signature
		entries = append(entries, entry)
	}
	parent, child := vector.Mapping.InitialDIDKey, vector.Mapping.RotatedDIDKey
	for _, scenario := range []struct {
		name     string
		accepted bool
	}{
		{"delegated", true}, {"exact", true}, {"inherited_same_key", true},
		{"missing", false}, {"wrong_parent_key", false}, {"wrong_child_key", false},
		{"wrong_ancestor", false}, {"non_ancestor", false}, {"exact_mismatch", false},
	} {
		for _, contact := range []bool{false, true} {
			kind := "sender"
			if contact {
				kind = "contact"
			}
			t.Run(scenario.name+"/"+kind, func(t *testing.T) {
				delegation := map[string]interface{}{"parent_domain": "example.com", "parent_controller_key": parent, "controller_key": child}
				namespace := map[string]interface{}{"domain": "alpha.example.com", "controller_did": child, "delegation": delegation}
				exact := scenario.name == "exact" || scenario.name == "exact_mismatch"
				switch scenario.name {
				case "inherited_same_key":
					namespace["controller_did"] = parent
					delete(namespace, "delegation")
				case "missing":
					delete(namespace, "delegation")
				case "wrong_parent_key":
					delegation["parent_controller_key"] = child
				case "wrong_child_key":
					delegation["controller_key"] = parent
				case "wrong_ancestor":
					delegation["parent_domain"] = "com"
				case "non_ancestor":
					delegation["parent_domain"] = "other.com"
				}
				anchor, key := "_awid.example.com", parent
				if exact {
					anchor = "_awid.alpha.example.com"
				}
				if scenario.name == "exact" {
					key = child
				}
				dns := vectorFederationDNS{anchor: {Outcome: "record", Records: []string{"awid=v1; controller=" + key + "; registry=https://registry-a.example;"}}}
				if !exact {
					dns["_awid.alpha.example.com"] = FederationTXTLookup{Outcome: "nodata"}
				}
				requests := []string{}
				client := &http.Client{Transport: strictRoundTrip(func(request *http.Request) (*http.Response, error) {
					requests = append(requests, request.URL.Path)
					var body interface{}
					switch {
					case request.URL.Path == "/v1/namespaces/alpha.example.com":
						body = namespace
					case request.URL.Path == "/v1/namespaces/alpha.example.com/addresses/Alice":
						body = map[string]interface{}{"domain": "alpha.example.com", "name": "Alice", "did_aw": vector.Mapping.DIDAW, "current_did_key": child, "delivery": map[string]interface{}{"origin": "https://aweb-alpha.example"}}
					case strings.HasSuffix(request.URL.Path, "/key"):
						body = map[string]interface{}{"did_aw": vector.Mapping.DIDAW, "current_did_key": child, "log_head": entries[len(entries)-1], "status": "OK_DEGRADED"}
					case strings.HasSuffix(request.URL.Path, "/log"):
						body = entries
					default:
						t.Fatalf("unexpected request %s", request.URL.Path)
					}
					encoded, err := json.Marshal(body)
					if err != nil {
						t.Fatal(err)
					}
					return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(bytes.NewReader(encoded)), Request: request}, nil
				})}
				resolver := &StrictFederationExternalResolver{TXTResolver: dns, HostResolver: &strictTestHosts{}, HTTPFactory: func(_ string, _ []string, _ int64) (*http.Client, error) { return client, nil }}
				fetch := resolver.FetchEvidence
				if contact {
					fetch = resolver.FetchContactEvidence
				}
				evidence, err := fetch(context.Background(), "alpha.example.com/Alice", 1, nil)
				if !scenario.accepted {
					if !IsFederationReason(err, "sender_address_did_mismatch") || evidence != nil {
						t.Fatalf("evidence=%#v err=%v", evidence, err)
					}
					if len(requests) != 1 {
						t.Fatalf("refused namespace reached address: %v", requests)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				if evidence.ControllerDID != namespace["controller_did"] || evidence.Inherited != !exact || evidence.DIDAW != vector.Mapping.DIDAW {
					t.Fatalf("unexpected evidence: %#v", evidence)
				}
			})
		}
	}
}
