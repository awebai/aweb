package handoff

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/awebai/aw/awid"
)

type protectedRequestVectors struct {
	RequesterID  string `json:"requester_id"`
	RequesterKey string `json:"requester_key"`
	Cases        []struct {
		Operation string            `json:"operation"`
		Method    string            `json:"method"`
		Path      string            `json:"path"`
		Body      string            `json:"body"`
		Envelope  map[string]any    `json:"envelope"`
		Headers   map[string]string `json:"headers"`
	} `json:"cases"`
}

func readProtectedVectors(t *testing.T) (protectedRequestVectors, *Profile) {
	t.Helper()
	data, err := os.ReadFile("../../../../docs/vectors/protected-service-request-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors protectedRequestVectors
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("../../../../docs/vectors/protected-service-profile-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	profile, err := ParseProfile(raw)
	if err != nil {
		t.Fatal(err)
	}
	return vectors, profile
}

// vectorSigner answers with the vector's own signature: it verifies only over
// the exact envelope bytes the vector signed.
func vectorSigner(key, authorization string) RequestKeySigner {
	signature, _ := base64.RawStdEncoding.DecodeString(authorization[strings.LastIndex(authorization, " ")+1:])
	return func(payload []byte) (string, []byte, error) { return key, signature, nil }
}

func TestProtectedRequestsSignTheVectorsExactEnvelope(t *testing.T) {
	vectors, profile := readProtectedVectors(t)
	scope := profile.Bindings[0].Scope
	for _, tc := range vectors.Cases {
		t.Run(tc.Operation, func(t *testing.T) {
			headers, err := ProtectedRequestHeaders(ProtectedRequest{
				Profile: profile, Scope: scope, RequesterID: vectors.RequesterID,
				Method: tc.Method, Path: tc.Path, Body: []byte(tc.Body),
				Timestamp: tc.Headers["X-AWEB-Timestamp"],
				Sign:      vectorSigner(vectors.RequesterKey, tc.Headers["Authorization"]),
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"Authorization", "X-AWEB-DID-AW", "X-AWEB-Timestamp", "X-AWEB-Signed-Payload"} {
				if headers.Get(name) != tc.Headers[name] {
					t.Errorf("%s = %q, want %q", name, headers.Get(name), tc.Headers[name])
				}
			}
		})
	}
}

func TestAProtectedRequestForAnotherScopeOrBodyIsNotTheSignedOne(t *testing.T) {
	vectors, profile := readProtectedVectors(t)
	tc := vectors.Cases[0]
	other := profile.Bindings[0].Scope
	changed := map[string]any{}
	for k, v := range other {
		changed[k] = v
	}
	changed["generation"] = json.Number("2")
	for name, request := range map[string]ProtectedRequest{
		"scope": {Scope: changed, Body: []byte(tc.Body)},
		"body":  {Scope: other, Body: append([]byte(tc.Body), ' ')},
	} {
		request.Profile, request.RequesterID, request.Method, request.Path = profile, vectors.RequesterID, tc.Method, tc.Path
		request.Timestamp = tc.Headers["X-AWEB-Timestamp"]
		request.Sign = vectorSigner(vectors.RequesterKey, tc.Headers["Authorization"])
		if _, err := ProtectedRequestHeaders(request); err == nil {
			t.Errorf("changed %s: the vector signature was accepted for another envelope", name)
		}
	}
}

func TestOnlyTheProtectedRoutesHaveAnOperationLabel(t *testing.T) {
	vectors, profile := readProtectedVectors(t)
	for _, route := range [][2]string{{"POST", "/protected-operations/x"}, {"GET", "/protected-operations"}, {"DELETE", "/protected-operations/x"}, {"POST", "/other"},
		{"POST", "/protected-admission-policies?team_id=engineering%3Acustomer.example"}, {"GET", "/protected-admission-policies"},
		{"GET", "/protected-operations/x/execute"}, {"POST", "/protected-operations/x/execute/more"}, {"POST", "/protected-operations//execute"}} {
		_, err := ProtectedRequestHeaders(ProtectedRequest{
			Profile: profile, Scope: profile.Bindings[0].Scope, RequesterID: vectors.RequesterID,
			Method: route[0], Path: route[1], Timestamp: "2026-11-11T00:00:00Z",
			Sign: func([]byte) (string, []byte, error) { t.Fatal("signed an unlabelled route"); return "", nil, nil },
		})
		if err == nil {
			t.Errorf("%s %s was labelled", route[0], route[1])
		}
	}
}

func TestTheProfileVectorParsesAndRefusesItsNeighbours(t *testing.T) {
	raw, err := os.ReadFile("../../../../docs/vectors/protected-service-profile-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	profile, err := ParseProfile(raw)
	if err != nil {
		t.Fatal(err)
	}
	if profile.RequestOrigin != "https://signer.customer.example" || profile.HumanOrigin != "https://human.customer.example" || profile.ServiceID != "customer-signer" {
		t.Fatalf("profile %+v", profile)
	}
	if len(profile.NamespaceAuthorities) != 1 || profile.NamespaceAuthorities["customer.example"] != "did:key:z6Mkon3Necd6NkkyfoGoHxid2znGc59LU3K7mubaRcFbLfLX" {
		t.Fatalf("namespace authorities %v", profile.NamespaceAuthorities)
	}
	for name, mutate := range map[string]func(string) string{
		"unknown member": func(s string) string { return strings.Replace(s, `"v": 1,`, `"v": 1, "extra": 1,`, 1) },
		"duplicate":      func(s string) string { return strings.Replace(s, `"v": 1,`, `"v": 1, "v": 1,`, 1) },
		"http human": func(s string) string {
			return strings.Replace(s, `"human_origin": "https://`, `"human_origin": "http://`, 1)
		},
		"rp mismatch": func(s string) string {
			return strings.Replace(s, `"rp_id": "human.customer.example"`, `"rp_id": "other.example"`, 1)
		},
		"float version": func(s string) string { return strings.Replace(s, `"version": 1`, `"version": 1.0`, 1) },
		"other service": func(s string) string {
			return strings.Replace(s, `"service_id": "customer-signer",`+"\n"+`                "authority"`, `"service_id": "x",`+"\n"+`                "authority"`, 1)
		},
		"origin with path": func(s string) string {
			return strings.Replace(s, `"https://signer.customer.example"`, `"https://signer.customer.example/x"`, 1)
		},
	} {
		indented := indentJSON(t, raw)
		changed := mutate(indented)
		if changed == indented {
			t.Fatalf("%s: mutation did not apply", name)
		}
		if _, err := ParseProfile([]byte(changed)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func indentJSON(t *testing.T, raw []byte) string {
	t.Helper()
	var out bytes.Buffer
	if err := json.Indent(&out, raw, "", "    "); err != nil {
		t.Fatal(err)
	}
	return out.String()
}

func TestAScopeTheProfileDoesNotConfigureIsNeverSigned(t *testing.T) {
	vectors, profile := readProtectedVectors(t)
	scope := map[string]any{}
	for k, v := range profile.Bindings[0].Scope {
		scope[k] = v
	}
	scope["generation"] = json.Number("2")
	_, err := ProtectedRequestHeaders(ProtectedRequest{
		Profile: profile, Scope: scope, RequesterID: vectors.RequesterID,
		Method: "POST", Path: "/protected-operations", Body: []byte("{}"), Timestamp: "2026-11-11T00:00:00Z",
		Sign: func([]byte) (string, []byte, error) { t.Fatal("signed an unconfigured scope"); return "", nil, nil },
	})
	if ErrorCode(err) != "profile_scope_refused" {
		t.Fatalf("err %v", err)
	}
}

// policyReadRequest is a policy read of team by a freshly keyed requester.
func policyReadRequest(t *testing.T, profile *Profile, team, query string) (ProtectedRequest, ed25519.PublicKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return ProtectedRequest{
		Profile: profile, Scope: map[string]any{"service_id": profile.ServiceID, "team_id": team},
		RequesterID: "did:aw:3YDAM5ZLRKg7eHH1Zs6sSMwkga8w", Method: "GET",
		Path: "/protected-admission-policies?" + query, Timestamp: "2026-11-11T00:00:00Z",
		Sign: func(payload []byte) (string, []byte, error) {
			return awid.ComputeDIDKey(public), ed25519.Sign(private, payload), nil
		},
	}, public
}

func TestAPolicyReadIsSignedOverItsTeamScopeAndExactQuery(t *testing.T) {
	_, profile := readProtectedVectors(t)
	request, _ := policyReadRequest(t, profile, "engineering:customer.example", "team_id=engineering%3Acustomer.example")
	headers, err := ProtectedRequestHeaders(request)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(headers.Get("X-AWEB-Signed-Payload"))
	if err != nil {
		t.Fatal(err)
	}
	envelope, ok := decodeObject(raw)
	if !ok {
		t.Fatalf("envelope %s", raw)
	}
	scope, _ := awid.StrictCanonicalJSON(map[string]any{"service_id": "customer-signer", "team_id": "engineering:customer.example"})
	scopeSum := sha256.Sum256(scope)
	emptySum := sha256.Sum256(nil)
	for name, want := range map[string]string{
		"operation": "protected_admission_policy_read", "method": "GET", "aud": "https://signer.customer.example",
		"path": "/protected-admission-policies?team_id=engineering%3Acustomer.example", "domain": "customer.example",
		"service_id": "customer-signer", "scope_sha256": hex.EncodeToString(scopeSum[:]), "body_sha256": hex.EncodeToString(emptySum[:]),
	} {
		if envelope[name] != want {
			t.Errorf("%s = %v, want %s", name, envelope[name], want)
		}
	}
}

func TestAPolicyReadForATeamTheProfileDoesNotBindOrAnotherQueryIsNeverSigned(t *testing.T) {
	_, profile := readProtectedVectors(t)
	for name, change := range map[string]func(*ProtectedRequest){
		"unbound team": func(r *ProtectedRequest) {
			r.Scope["team_id"] = "sales:customer.example"
			r.Path = "/protected-admission-policies?team_id=sales%3Acustomer.example"
		},
		"query for another team": func(r *ProtectedRequest) {
			r.Path = "/protected-admission-policies?team_id=sales%3Acustomer.example"
		},
		"extra query":     func(r *ProtectedRequest) { r.Path += "&x=1" },
		"other service":   func(r *ProtectedRequest) { r.Scope["service_id"] = "other" },
		"extra scope":     func(r *ProtectedRequest) { r.Scope["human"] = "did:aw:x" },
		"body":            func(r *ProtectedRequest) { r.Body = []byte("{}") },
		"operation scope": func(r *ProtectedRequest) { r.Scope = profile.Bindings[0].Scope },
	} {
		request, _ := policyReadRequest(t, profile, "engineering:customer.example", "team_id=engineering%3Acustomer.example")
		change(&request)
		request.Sign = func([]byte) (string, []byte, error) { t.Fatalf("%s: signed", name); return "", nil, nil }
		if _, err := ProtectedRequestHeaders(request); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestAnExecuteIsSignedAsAnExecuteOverItsOperationsScope(t *testing.T) {
	vectors, profile := readProtectedVectors(t)
	public, private, _ := ed25519.GenerateKey(nil)
	headers, err := ProtectedRequestHeaders(ProtectedRequest{
		Profile: profile, Scope: profile.Bindings[0].Scope, RequesterID: vectors.RequesterID,
		Method: "POST", Path: "/protected-operations/11111111-1111-4111-8111-111111111111/execute", Timestamp: "2026-11-11T00:00:00Z",
		Sign: func(payload []byte) (string, []byte, error) {
			return awid.ComputeDIDKey(public), ed25519.Sign(private, payload), nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.RawURLEncoding.DecodeString(headers.Get("X-AWEB-Signed-Payload"))
	envelope, _ := decodeObject(raw)
	emptySum := sha256.Sum256(nil)
	if envelope["operation"] != "protected_operation_execute" || envelope["method"] != "POST" || envelope["body_sha256"] != hex.EncodeToString(emptySum[:]) {
		t.Fatalf("envelope %v", envelope)
	}
}
