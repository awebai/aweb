package awid

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type federationDiscoveryCases struct {
	CanonicalAddressCases []struct {
		Name     string `json:"name"`
		Input    string `json:"input"`
		Expected struct {
			Valid     bool    `json:"valid"`
			Canonical *string `json:"canonical"`
		} `json:"expected"`
	} `json:"canonical_address_cases"`
	DNSCases []struct {
		Name             string `json:"name"`
		SenderDomain     string `json:"sender_domain"`
		RegisteredDomain string `json:"registered_domain"`
		Queries          []struct {
			Name    string   `json:"name"`
			Outcome string   `json:"outcome"`
			Records []string `json:"records"`
		} `json:"queries"`
		Expected struct {
			Selection        *string `json:"selection"`
			AuthorityName    *string `json:"authority_name"`
			Inherited        bool    `json:"inherited"`
			RegistryExplicit bool    `json:"registry_explicit"`
			RegistryOrigin   *string `json:"registry_origin"`
			Reason           *string `json:"reason"`
		} `json:"expected"`
	} `json:"dns_cases"`
	AuthorityStatementCases []struct {
		Name                      string                 `json:"name"`
		Payload                   map[string]interface{} `json:"payload"`
		CanonicalPayload          string                 `json:"canonical_payload"`
		AuthorityStatementVersion string                 `json:"authority_statement_version"`
		AuthorityStatementDigest  string                 `json:"authority_statement_digest"`
	} `json:"authority_statement_cases"`
}

type changingVectorAnswers struct {
	answers [][]string
	calls   int
}

func (r *changingVectorAnswers) Resolve() []string {
	index := r.calls
	if index > 1 {
		index = 1
	}
	r.calls++
	return append([]string(nil), r.answers[index]...)
}

type federationOriginCases struct {
	OriginCases []struct {
		Name    string `json:"name"`
		Input   string `json:"input"`
		Context struct {
			AppEnv                string `json:"app_env"`
			FederationTestEnabled bool   `json:"federation_test_enabled"`
			ListenerOrigin        string `json:"listener_origin"`
		} `json:"context"`
		Expected struct {
			OK              bool    `json:"ok"`
			CanonicalOrigin *string `json:"canonical_origin"`
			Reason          *string `json:"reason"`
		} `json:"expected"`
	} `json:"origin_cases"`
	IPCases []struct {
		Name     string `json:"name"`
		Input    string `json:"input"`
		Expected struct {
			Allowed bool    `json:"allowed"`
			Reason  *string `json:"reason"`
		} `json:"expected"`
	} `json:"ip_cases"`
	AnswerSetCases []struct {
		Name     string   `json:"name"`
		Answers  []string `json:"answers"`
		Expected struct {
			Allowed     bool     `json:"allowed"`
			ApprovedIPs []string `json:"approved_ips"`
			Reason      *string  `json:"reason"`
		} `json:"expected"`
	} `json:"answer_set_cases"`
	SourceIPCases []struct {
		Name              string   `json:"name"`
		DirectPeer        string   `json:"direct_peer"`
		ForwardedFor      string   `json:"forwarded_for"`
		TrustedProxyCIDRs []string `json:"trusted_proxy_cidrs"`
		Expected          struct {
			SourceIP            *string `json:"source_ip"`
			ForwardedHeaderUsed bool    `json:"forwarded_header_used"`
			UnknownBucket       bool    `json:"unknown_bucket"`
		} `json:"expected"`
	} `json:"source_ip_cases"`
	TransportCases []struct {
		Name              string   `json:"name"`
		Origin            string   `json:"origin"`
		ResolvedAnswers   []string `json:"resolved_answers"`
		SubsequentAnswers []string `json:"subsequent_answers"`
		SelectedIP        string   `json:"selected_ip"`
		Expected          struct {
			ConnectIP        string   `json:"connect_ip"`
			TLSServerName    string   `json:"tls_server_name"`
			HostHeader       string   `json:"host_header"`
			AcceptEncoding   string   `json:"accept_encoding"`
			SecondResolution bool     `json:"second_resolution"`
			RedirectFollow   bool     `json:"redirect_follow"`
			AmbientProxy     bool     `json:"ambient_proxy"`
			Cookies          bool     `json:"cookies"`
			Auth             bool     `json:"auth"`
			PoolKeyFields    []string `json:"pool_key_fields"`
		} `json:"expected"`
	} `json:"transport_cases"`
}

func loadFederationVector(t *testing.T, name string, out interface{}) {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "vectors", name))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(body, out); err != nil {
		t.Fatal(err)
	}
}

type vectorFederationDNS map[string]FederationTXTLookup

func (v vectorFederationDNS) LookupFederationTXT(_ context.Context, name string) (FederationTXTLookup, error) {
	return v[name], nil
}

func TestStrictFederationAddressRejectsUnicodeSpace(t *testing.T) {
	for _, space := range []string{"\u00a0", "\u2003"} {
		if _, err := CanonicalFederationAddress("alpha.example.com/Alice" + space + "Smith"); !IsFederationReason(err, "sender_registry_unresolvable") {
			t.Fatalf("space %U error=%v", []rune(space)[0], err)
		}
	}
}

func TestStrictFederationAddressAndAuthorityStatementVectors(t *testing.T) {
	var vector federationDiscoveryCases
	loadFederationVector(t, "federation-discovery-v1.json", &vector)
	for _, test := range vector.CanonicalAddressCases {
		t.Run(test.Name, func(t *testing.T) {
			got, err := CanonicalFederationAddress(test.Input)
			if !test.Expected.Valid {
				if !IsFederationReason(err, "sender_registry_unresolvable") {
					t.Fatalf("error=%v", err)
				}
				return
			}
			if err != nil || test.Expected.Canonical == nil || got != *test.Expected.Canonical {
				t.Fatalf("got %q, %v; want %v", got, err, test.Expected.Canonical)
			}
		})
	}
	for _, test := range vector.DNSCases {
		t.Run(test.Name, func(t *testing.T) {
			resolver := vectorFederationDNS{}
			for _, query := range test.Queries {
				resolver[query.Name] = FederationTXTLookup{Outcome: query.Outcome, Records: query.Records}
			}
			authority, err := DiscoverStrictFederationRegistry(
				context.Background(), resolver, test.SenderDomain, test.RegisteredDomain, FederationOriginContext{},
			)
			if test.Expected.Reason != nil {
				if !IsFederationReason(err, *test.Expected.Reason) {
					t.Fatalf("error=%v", err)
				}
				return
			}
			if err != nil || test.Expected.Selection == nil || authority.Selection != *test.Expected.Selection ||
				test.Expected.AuthorityName == nil || authority.AuthorityName != *test.Expected.AuthorityName ||
				authority.Inherited != test.Expected.Inherited || authority.RegistryExplicit != test.Expected.RegistryExplicit ||
				test.Expected.RegistryOrigin == nil || authority.RegistryOrigin != *test.Expected.RegistryOrigin {
				t.Fatalf("authority=%#v error=%v expected=%#v", authority, err, test.Expected)
			}
		})
	}
	for _, test := range vector.AuthorityStatementCases {
		statement, err := NewFederationAuthorityStatement(test.Payload)
		if err != nil {
			t.Fatalf("%s: %v", test.Name, err)
		}
		if string(statement.CanonicalPayload) != test.CanonicalPayload ||
			statement.Version != test.AuthorityStatementVersion ||
			statement.Digest != test.AuthorityStatementDigest {
			t.Fatalf("%s: unexpected statement %#v", test.Name, statement)
		}
	}
}

func TestStrictFederationOriginAndIPVectors(t *testing.T) {
	var vector federationOriginCases
	loadFederationVector(t, "federation-origin-ip-v1.json", &vector)
	for _, test := range vector.OriginCases {
		t.Run(test.Name, func(t *testing.T) {
			got, err := CanonicalFederationRegistryOrigin(test.Input, FederationOriginContext{
				AppEnv:                test.Context.AppEnv,
				FederationTestEnabled: test.Context.FederationTestEnabled,
				ListenerOrigin:        test.Context.ListenerOrigin,
			})
			if !test.Expected.OK {
				if !IsFederationReason(err, "sender_registry_origin_forbidden") {
					t.Fatalf("error=%v", err)
				}
				return
			}
			if err != nil || test.Expected.CanonicalOrigin == nil || got != *test.Expected.CanonicalOrigin {
				t.Fatalf("got %q, %v; want %v", got, err, test.Expected.CanonicalOrigin)
			}
		})
	}
	for _, test := range vector.IPCases {
		t.Run(test.Name, func(t *testing.T) {
			got, err := ValidateFederationResolvedIPs([]string{test.Input})
			if !test.Expected.Allowed {
				if test.Expected.Reason == nil || !IsFederationReason(err, *test.Expected.Reason) {
					t.Fatalf("error=%v expected=%#v", err, test.Expected)
				}
				return
			}
			if err != nil || len(got) != 1 || got[0] != test.Input {
				t.Fatalf("got=%v error=%v", got, err)
			}
		})
	}
	for _, test := range vector.AnswerSetCases {
		t.Run(test.Name, func(t *testing.T) {
			got, err := ValidateFederationResolvedIPs(test.Answers)
			if !test.Expected.Allowed {
				if !IsFederationReason(err, "sender_registry_origin_forbidden") {
					t.Fatalf("error=%v", err)
				}
				return
			}
			if err != nil || len(got) != len(test.Expected.ApprovedIPs) {
				t.Fatalf("got %v, %v", got, err)
			}
			for i := range got {
				if got[i] != test.Expected.ApprovedIPs[i] {
					t.Fatalf("got %v want %v", got, test.Expected.ApprovedIPs)
				}
			}
		})
	}
	for _, test := range vector.SourceIPCases {
		t.Run(test.Name, func(t *testing.T) {
			got := NormalizeFederationSourceIP(test.DirectPeer, test.ForwardedFor, test.TrustedProxyCIDRs)
			sourceMatches := got.SourceIP == nil && test.Expected.SourceIP == nil
			if got.SourceIP != nil && test.Expected.SourceIP != nil {
				sourceMatches = *got.SourceIP == *test.Expected.SourceIP
			}
			if !sourceMatches || got.ForwardedHeaderUsed != test.Expected.ForwardedHeaderUsed || got.UnknownBucket != test.Expected.UnknownBucket {
				t.Fatalf("got=%#v expected=%#v", got, test.Expected)
			}
		})
	}
	for _, test := range vector.TransportCases {
		t.Run(test.Name, func(t *testing.T) {
			resolver := &changingVectorAnswers{answers: [][]string{test.ResolvedAnswers, test.SubsequentAnswers}}
			approved, err := ValidateFederationResolvedIPs(resolver.Resolve())
			if err != nil {
				t.Fatal(err)
			}
			client, err := NewPinnedFederationHTTPClient(test.Origin, approved, 7, nil)
			if err != nil {
				t.Fatal(err)
			}
			transport, ok := client.Transport.(*pinnedFederationRoundTripper)
			if !ok {
				t.Fatalf("transport=%T", client.Transport)
			}
			if resolver.calls != 1 || transport.selectedIP.String() != test.SelectedIP || transport.selectedIP.String() != test.Expected.ConnectIP || transport.transport.TLSClientConfig.ServerName != test.Expected.TLSServerName || transport.origin.Host != test.Expected.HostHeader {
				t.Fatalf("resolutions=%d transport=%#v expected=%#v", resolver.calls, transport, test.Expected)
			}
			if test.Name == "pinned_ip_preserves_hostname_tls_and_disables_ambient_state" {
				if _, err := ValidateFederationResolvedIPs(test.SubsequentAnswers); !IsFederationReason(err, "sender_registry_origin_forbidden") {
					t.Fatalf("rebinding answers=%v error=%v", test.SubsequentAnswers, err)
				}
				for _, answer := range test.SubsequentAnswers {
					if answer == transport.selectedIP.String() {
						t.Fatalf("selected IP %s came from rebinding answers %v", transport.selectedIP, test.SubsequentAnswers)
					}
				}
			} else {
				subsequent, err := ValidateFederationResolvedIPs(test.SubsequentAnswers)
				if err != nil || len(subsequent) != len(approved) {
					t.Fatalf("subsequent=%v error=%v approved=%v", subsequent, err, approved)
				}
				for i := range subsequent {
					if subsequent[i] != approved[i] {
						t.Fatalf("subsequent=%v approved=%v", subsequent, approved)
					}
				}
			}
			if test.Expected.AcceptEncoding != "identity" || !transport.transport.DisableCompression || test.Expected.SecondResolution || test.Expected.AmbientProxy || transport.transport.Proxy != nil || test.Expected.Cookies || client.Jar != nil || test.Expected.Auth {
				t.Fatalf("ambient transport policy differs from vector: %#v", test.Expected)
			}
			if test.Expected.RedirectFollow || !errors.Is(client.CheckRedirect(&http.Request{}, nil), http.ErrUseLastResponse) {
				t.Fatalf("redirect policy differs from vector")
			}
			if len(test.Expected.PoolKeyFields) != 3 || transport.poolKey == "" || transport.generation != 7 || len(transport.approvedIPs) != len(test.ResolvedAnswers) {
				t.Fatalf("pool key=%q approved=%v generation=%d", transport.poolKey, transport.approvedIPs, transport.generation)
			}
		})
	}
}

func TestStrictGoAuthorityLookupVectors(t *testing.T) {
	var lookup authorityLookupVector
	loadFederationVector(t, "federation-discovery-v1.json", &lookup)
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
		entry := map[string]interface{}{}
		for key, value := range item.EntryPayload {
			entry[key] = value
		}
		entry["entry_hash"] = item.EntryHash
		entry["signature"] = item.Signature
		entries = append(entries, entry)
	}

	for _, test := range lookup.AuthorityLookupCases {
		t.Run(test.Name, func(t *testing.T) {
			namespace, namespaceSentinel := decodeLookupObject(t, test.Namespace)
			address, _ := decodeLookupObject(t, test.Address)
			key, _ := decodeLookupObject(t, test.Key)
			domain := "alpha.example.com"
			name := "Alice"
			if namespace != nil {
				if value, ok := namespace["domain"].(string); ok {
					domain = value
				}
			} else if address != nil {
				if value, ok := address["domain"].(string); ok {
					domain = value
				}
			}
			if address != nil {
				if value, ok := address["name"].(string); ok {
					name = value
				}
				if delivery, ok := address["delivery_origin"].(string); ok {
					address["delivery"] = map[string]interface{}{"origin": delivery}
					delete(address, "delivery_origin")
				}
			}
			responses := map[string]interface{}{}
			namespacePath := "/v1/namespaces/" + domain
			addressPath := namespacePath + "/addresses/" + name
			switch {
			case namespaceSentinel == "transport_failure":
				responses[namespacePath] = federationReason("sender_registry_unavailable")
			case namespace == nil:
				responses[namespacePath] = nil
			default:
				responses[namespacePath] = namespace
			}
			if address == nil {
				responses[addressPath] = nil
			} else {
				responses[addressPath] = address
			}
			if key == nil {
				responses["/key"] = nil
			} else {
				responses["/key"] = key
			}
			responses["/log"] = entries
			var checkpoint *StrictFederationCheckpoint
			if key != nil {
				key["log_head"] = entries[len(entries)-1]
				if key["status"] == "OK_DEGRADED" {
					responses["/log"] = nil
				}
				if extends, ok := key["extends_checkpoint"].(bool); ok && !extends {
					key["status"] = "OK_DEGRADED"
					checkpoint = &StrictFederationCheckpoint{
						Seq: 1, EntryHash: strings.Repeat("a", 64), StateHash: strings.Repeat("b", 64),
						CurrentDIDKey: identity.Mapping.InitialDIDKey, Revision: 1,
					}
				}
			}

			requests := []string{}
			client := &http.Client{Transport: strictRoundTrip(func(request *http.Request) (*http.Response, error) {
				requests = append(requests, request.URL.Path)
				lookupPath := request.URL.Path
				if strings.HasSuffix(lookupPath, "/key") {
					lookupPath = "/key"
				} else if strings.HasSuffix(lookupPath, "/log") {
					lookupPath = "/log"
				}
				value, exists := responses[lookupPath]
				if !exists || value == nil {
					return &http.Response{StatusCode: 404, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(`{}`)), Request: request}, nil
				}
				if err, ok := value.(error); ok {
					return nil, err
				}
				body, err := json.Marshal(value)
				if err != nil {
					t.Fatal(err)
				}
				return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(bytes.NewReader(body)), Request: request}, nil
			})}
			contacted := []string{}
			resolver := &StrictFederationExternalResolver{
				TXTResolver:  lookupCaseTXT{selection: test.Selection, controller: identity.Mapping.InitialDIDKey, origin: test.RegistryOrigin},
				HostResolver: &strictTestHosts{},
				HTTPFactory: func(origin string, _ []string, _ int64) (*http.Client, error) {
					contacted = append(contacted, origin)
					return client, nil
				},
			}
			evidence, err := resolver.FetchEvidence(context.Background(), domain+"/"+name, 20, checkpoint)
			if test.Expected.Accepted {
				if err != nil || evidence == nil || evidence.RegistryOrigin != test.RegistryOrigin {
					t.Fatalf("evidence=%#v error=%v", evidence, err)
				}
			} else if test.Expected.Reason == nil || !IsFederationReason(err, *test.Expected.Reason) {
				t.Fatalf("error=%v expected=%#v", err, test.Expected)
			}
			if test.Expected.FallbackContacted || len(contacted) != 1 || contacted[0] != test.RegistryOrigin {
				t.Fatalf("contacted=%v expected=%#v", contacted, test.Expected)
			}
			requestedLog := false
			for _, path := range requests {
				requestedLog = requestedLog || strings.HasSuffix(path, "/log")
			}
			if test.Expected.FullLogRequired != nil && requestedLog != *test.Expected.FullLogRequired {
				t.Fatalf("full_log_required=%t but requests=%v", *test.Expected.FullLogRequired, requests)
			}
		})
	}
}

func TestStrictFederationErrorVocabulary(t *testing.T) {
	var vector struct {
		StableErrors []struct {
			Reason             string `json:"reason"`
			HTTPStatus         int    `json:"http_status"`
			Retryable          bool   `json:"retryable"`
			RetryAfterRequired bool   `json:"retry_after_required"`
		} `json:"stable_errors"`
	}
	loadFederationVector(t, "federation-authority-state-v1.json", &vector)
	for _, item := range vector.StableErrors {
		spec, ok := FederationErrorSpecFor(item.Reason)
		if !ok || spec.HTTPStatus != item.HTTPStatus || spec.Retryable != item.Retryable || spec.RetryAfterRequired != item.RetryAfterRequired {
			t.Fatalf("reason=%s spec=%#v ok=%v", item.Reason, spec, ok)
		}
	}
}

func TestStrictFederationLogRequiresVerifiedEvidence(t *testing.T) {
	var vector struct {
		Mapping struct {
			DIDAW         string `json:"did_aw"`
			RotatedDIDKey string `json:"rotated_did_key"`
		} `json:"mapping"`
		Entries []struct {
			EntryPayload map[string]interface{} `json:"entry_payload"`
			EntryHash    string                 `json:"entry_hash"`
			Signature    string                 `json:"signature_b64"`
		} `json:"entries"`
	}
	loadFederationVector(t, "identity-log-v1.json", &vector)
	body, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "vectors", "identity-log-v1.json"))
	if err != nil || len(body) == 0 {
		t.Fatal(err)
	}
	entries := make([]DidKeyEvidence, 0, len(vector.Entries))
	for _, item := range vector.Entries {
		payload, err := json.Marshal(item.EntryPayload)
		if err != nil {
			t.Fatal(err)
		}
		var entry DidKeyEvidence
		if err := json.Unmarshal(payload, &entry); err != nil {
			t.Fatal(err)
		}
		entry.EntryHash = item.EntryHash
		entry.Signature = item.Signature
		entries = append(entries, entry)
	}
	verified, err := VerifyStrictFederationDIDLog(context.Background(), vector.Mapping.DIDAW, entries, vector.Mapping.RotatedDIDKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	if verified.CurrentDIDKey != vector.Mapping.RotatedDIDKey || verified.Seq != 2 {
		t.Fatalf("unexpected verified log %#v", verified)
	}

	_, err = VerifyStrictFederationDIDLog(context.Background(), vector.Mapping.DIDAW, entries[1:], vector.Mapping.RotatedDIDKey, nil)
	if !IsFederationReason(err, "sender_did_log_invalid") {
		t.Fatalf("truncated log error=%v", err)
	}
}
