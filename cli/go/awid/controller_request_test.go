package awid

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestControllerRequestPayloadMatchesTheFrozenVector(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "vectors", "awid-controller-request-v2.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		SeedHex          string         `json:"seed_hex"`
		DIDKey           string         `json:"did_key"`
		BodyUTF8         string         `json:"body_utf8"`
		Payload          map[string]any `json:"payload"`
		CanonicalPayload string         `json:"canonical_payload"`
		SignatureB64     string         `json:"signature_b64"`
	}
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	p := v.Payload
	claims := map[string]any{}
	for k, x := range p {
		switch k {
		case "v", "type", "aud", "method", "path", "body_sha256", "timestamp", "domain", "operation":
		default:
			claims[k] = x
		}
	}
	payload, err := ControllerRequestPayload(p["aud"].(string), p["method"].(string), p["path"].(string), []byte(v.BodyUTF8), p["timestamp"].(string), p["domain"].(string), p["operation"].(string), claims)
	if err != nil {
		t.Fatal(err)
	}
	if string(payload) != v.CanonicalPayload {
		t.Fatalf("payload\n%s\nwant\n%s", payload, v.CanonicalPayload)
	}
	seed, err := hex.DecodeString(v.SeedHex)
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(seed)
	if ComputeDIDKey(key.Public().(ed25519.PublicKey)) != v.DIDKey {
		t.Fatal("vector key mismatch")
	}
	if got := base64.RawStdEncoding.EncodeToString(ed25519.Sign(key, payload)); got != v.SignatureB64 {
		t.Fatalf("signature %s want %s", got, v.SignatureB64)
	}
}

// registrySink records the one request a covering call sends.
type registrySink struct {
	mu       sync.Mutex
	requests []*http.Request
	bodies   [][]byte
	status   int
	answer   string
}

func (s *registrySink) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	s.mu.Lock()
	s.requests = append(s.requests, r)
	s.bodies = append(s.bodies, body)
	status, answer := s.status, s.answer
	s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, answer)
}

func testChainBundle(t *testing.T) map[string]any {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "vectors", "id-certificates-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Certificates map[string]struct {
			Signed map[string]any `json:"signed"`
		} `json:"certificates"`
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if err := d.Decode(&v); err != nil {
		t.Fatal(err)
	}
	return map[string]any{"v": json.Number("1"), "type": "aweb.id-chain", "certificates": []any{v.Certificates["alice"].Signed, v.Certificates["bob"].Signed}}
}

func seedSigner(seed byte, calls *int) IDCertificateSigner {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32))
	return func(payload []byte) (string, []byte, error) {
		*calls++
		return ComputeDIDKey(key.Public().(ed25519.PublicKey)), ed25519.Sign(key, payload), nil
	}
}

func TestRegisterIDCertificateSendsOneCoveringRequest(t *testing.T) {
	sink := &registrySink{status: 200, answer: `{"certificate_id":"sha256:abc","registered_at":"2026-10-26T00:02:00.000000Z"}`}
	server := httptest.NewServer(sink)
	defer server.Close()
	bundle := testChainBundle(t)
	calls := 0
	client := &RegistryClient{HTTPClient: server.Client(), Now: func() time.Time { return time.Date(2026, 10, 26, 0, 2, 0, 0, time.UTC) }}
	invitation := "10000000-0000-4000-8000-000000000001"
	receipt, err := client.RegisterIDCertificateAt(context.Background(), server.URL, bundle, seedSigner(5, &calls), nil, &invitation)
	if err != nil {
		t.Fatal(err)
	}
	if receipt["certificate_id"] != "sha256:abc" || calls != 1 || len(sink.requests) != 1 {
		t.Fatalf("receipt=%v calls=%d requests=%d", receipt, calls, len(sink.requests))
	}
	r, body := sink.requests[0], sink.bodies[0]
	if r.Method != http.MethodPost || r.URL.Path != "/v1/id-certificates/register" {
		t.Fatalf("%s %s", r.Method, r.URL.Path)
	}
	leaf := bundle["certificates"].([]any)[1]
	wantBody, err := CanonicalJSONValue(map[string]any{"certificate": leaf, "expected_head": nil, "invitation_id": invitation})
	if err != nil || string(body) != wantBody {
		t.Fatalf("body %s want %s", body, wantBody)
	}
	header, err := EncodeIDChainHeader(bundle)
	if err != nil || r.Header.Get("X-AWID-ID-Chain") != header {
		t.Fatal("the candidate chain header is missing or differs")
	}
	payload, err := base64.RawURLEncoding.DecodeString(r.Header.Get("X-AWEB-Signed-Payload"))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	wantPayload, err := ControllerRequestPayload(server.URL, "POST", "/v1/id-certificates/register", body, "2026-10-26T00:02:00Z", "example.com", "register_id_certificate", nil)
	if err != nil || string(payload) != string(wantPayload) || !strings.Contains(string(payload), hex.EncodeToString(sum[:])) {
		t.Fatalf("payload %s want %s", payload, wantPayload)
	}
	if r.Header.Get("X-AWEB-Timestamp") != "2026-10-26T00:02:00Z" {
		t.Fatalf("timestamp %q", r.Header.Get("X-AWEB-Timestamp"))
	}
	auth := strings.Fields(r.Header.Get("Authorization"))
	if len(auth) != 3 || auth[0] != "DIDKey" {
		t.Fatalf("authorization %q", r.Header.Get("Authorization"))
	}
	signature, err := base64.RawStdEncoding.DecodeString(auth[2])
	if err != nil {
		t.Fatal(err)
	}
	public, err := ExtractPublicKey(auth[1])
	if err != nil || !ed25519.Verify(public, payload, signature) {
		t.Fatal("the authorization does not verify over the signed payload")
	}
}

func TestRegisterIDCertificateSendsNothingForABadSigner(t *testing.T) {
	sink := &registrySink{status: 200, answer: `{}`}
	server := httptest.NewServer(sink)
	defer server.Close()
	client := &RegistryClient{HTTPClient: server.Client()}
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32))
	label := ComputeDIDKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{5}, 32)).Public().(ed25519.PublicKey))
	for name, signer := range map[string]IDCertificateSigner{
		"signer error":    func([]byte) (string, []byte, error) { return "", nil, errors.New("no terminal") },
		"mislabelled":     func(p []byte) (string, []byte, error) { return label, ed25519.Sign(other, p), nil },
		"short signature": func([]byte) (string, []byte, error) { return label, make([]byte, 10), nil },
		"degenerate signer": func([]byte) (string, []byte, error) {
			return "did:key:z6MkeTG3bFFSLYVU7VqhgZxqr6YzpaGrQtFMh1uvqGy1vDnP", make([]byte, 64), nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := client.RegisterIDCertificateAt(context.Background(), server.URL, testChainBundle(t), signer, nil, nil); err == nil {
				t.Fatal("a bad signer answer was accepted")
			}
			if len(sink.requests) != 0 {
				t.Fatal("a request was sent")
			}
		})
	}
}

func TestRegisterIDCertificateSurfacesTheRegistryCode(t *testing.T) {
	sink := &registrySink{status: 409, answer: `{"detail":{"code":"head_conflict","message":"conflict"}}`}
	server := httptest.NewServer(sink)
	defer server.Close()
	calls := 0
	_, err := (&RegistryClient{HTTPClient: server.Client()}).RegisterIDCertificateAt(context.Background(), server.URL, testChainBundle(t), seedSigner(5, &calls), nil, nil)
	var registryErr *RegistryError
	if !errors.As(err, &registryErr) || registryErr.StatusCode != 409 || !registryErr.HasCode("head_conflict") {
		t.Fatalf("err=%v", err)
	}
}

func TestRevokeIDCertificateSendsOneCoveringRequest(t *testing.T) {
	sink := &registrySink{status: 200, answer: `{"revoked_at":"2026-10-26T00:20:00.000000Z","effective_from":"2026-10-26T00:20:00.000000Z"}`}
	server := httptest.NewServer(sink)
	defer server.Close()
	calls := 0
	head := "sha256:abc"
	answer, err := (&RegistryClient{HTTPClient: server.Client()}).RevokeIDCertificateAt(context.Background(), server.URL, "example.com", "did:aw:2e2SPDJNyxg5Dt6EFJX3Tcn8Tauj", seedSigner(3, &calls), &head, nil)
	if err != nil || answer["revoked_at"] == nil || calls != 1 {
		t.Fatalf("answer=%v err=%v calls=%d", answer, err, calls)
	}
	r, body := sink.requests[0], sink.bodies[0]
	want, err := CanonicalJSONValue(map[string]any{"domain": "example.com", "id": "did:aw:2e2SPDJNyxg5Dt6EFJX3Tcn8Tauj", "expected_head": head, "effective_from": nil})
	if err != nil || r.URL.Path != "/v1/id-certificates/revoke" || string(body) != want {
		t.Fatalf("%s body %s", r.URL.Path, body)
	}
	payload, _ := base64.RawURLEncoding.DecodeString(r.Header.Get("X-AWEB-Signed-Payload"))
	if !strings.Contains(string(payload), `"operation":"revoke_id_certificate"`) {
		t.Fatalf("payload %s", payload)
	}
}

func TestRegisterIDCertificateRefusesARegistryURLWithAPath(t *testing.T) {
	sink := &registrySink{status: 200, answer: `{}`}
	server := httptest.NewServer(sink)
	defer server.Close()
	calls := 0
	if _, err := (&RegistryClient{HTTPClient: server.Client()}).RegisterIDCertificateAt(context.Background(), server.URL+"/awid", testChainBundle(t), seedSigner(5, &calls), nil, nil); err == nil {
		t.Fatal("a registry URL with a path was accepted")
	}
	if len(sink.requests) != 0 || calls != 0 {
		t.Fatalf("requests=%d signer calls=%d", len(sink.requests), calls)
	}
}
