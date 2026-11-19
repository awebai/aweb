package awid

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The controller writes aw and the Python awid client both make. The vector
// is generated from the Python client (scripts/generate_controller_write_vectors.py);
// aw must send exactly the same method, path, body bytes and signing headers.
type controllerWriteVectors struct {
	RegistryOrigin string            `json:"registry_origin"`
	Timestamp      string            `json:"timestamp"`
	SeedsHex       map[string]string `json:"seeds_hex"`
	Cases          []struct {
		Name      string         `json:"name"`
		Arguments map[string]any `json:"arguments"`
		Expected  struct {
			Method   string            `json:"method"`
			RawPath  string            `json:"raw_path"`
			BodyUTF8 string            `json:"body_utf8"`
			Headers  map[string]string `json:"headers"`
		} `json:"expected"`
	} `json:"cases"`
}

var errWriteRecorded = errors.New("write recorded")

type recordWrite struct{ sent []*http.Request }

func (r *recordWrite) RoundTrip(req *http.Request) (*http.Response, error) {
	r.sent = append(r.sent, req)
	return nil, errWriteRecorded
}

func TestControllerWritesMatchThePythonClientBytes(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "vectors", "awid-controller-writes-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vectors controllerWriteVectors
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	keys := map[string]ed25519.PrivateKey{}
	for name, seedHex := range vectors.SeedsHex {
		seed, err := hex.DecodeString(seedHex)
		if err != nil {
			t.Fatal(err)
		}
		keys[name] = ed25519.NewKeyFromSeed(seed)
	}
	at, err := time.Parse(time.RFC3339, vectors.Timestamp)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range vectors.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			a := tc.Arguments
			text := func(name string) string { value, _ := a[name].(string); return value }
			key := func(name string) ed25519.PrivateKey { return keys[text(name)] }
			recorder := &recordWrite{}
			client := NewAWIDRegistryClient(&http.Client{Transport: recorder}, nil)
			client.Now = func() time.Time { return at }
			routeUntrustedRegistriesToInjectedClient(client)
			ctx, url, domain := context.Background(), vectors.RegistryOrigin, text("domain")
			switch tc.Name {
			case "register_namespace":
				_, err = client.RegisterNamespaceWithDeliveryOriginAt(ctx, url, domain, text("controller_did"), key("controller_signing_key"), text("default_delivery_origin"))
			case "update_namespace_delivery_origin":
				_, err = client.UpdateNamespaceDeliveryOriginAt(ctx, url, domain, key("controller_signing_key"), text("default_delivery_origin"))
			case "delete_namespace":
				err = client.DeleteNamespaceAt(ctx, url, domain, key("controller_signing_key"), text("reason"))
			case "register_team":
				_, err = client.CreateTeam(ctx, url, domain, text("name"), text("display_name"), text("team_did_key"), key("namespace_controller_signing_key"))
			case "set_team_visibility":
				_, err = client.SetTeamVisibility(ctx, url, domain, text("name"), text("visibility"), key("team_controller_signing_key"))
			case "delete_team":
				err = client.DeleteTeam(ctx, url, domain, text("name"), key("namespace_controller_signing_key"), "")
			case "rotate_team_key":
				_, err = client.RotateTeamKeyWithMembers(ctx, url, domain, text("name"), text("new_team_did_key"), nil, nil, key("namespace_controller_signing_key"))
			case "register_team_certificate":
				cert, decodeErr := DecodeTeamCertificateHeader(text("certificate"))
				if decodeErr != nil {
					t.Fatal(decodeErr)
				}
				err = client.RegisterCertificate(ctx, url, domain, text("name"), cert, key("team_controller_signing_key"))
			case "revoke_team_certificate":
				err = client.RevokeCertificate(ctx, url, domain, text("name"), text("certificate_id"), key("team_controller_signing_key"))
			case "register_address":
				_, err = client.RegisterAddressAt(ctx, url, domain, text("name"), text("did_aw"), text("current_did_key"), key("controller_signing_key"))
			case "delete_address", "delete_address_escaped_name":
				err = client.DeleteAddressAt(ctx, url, domain, text("name"), key("controller_signing_key"), "")
			default:
				t.Fatalf("no aw call for vector case %q", tc.Name)
			}
			if !errors.Is(err, errWriteRecorded) {
				t.Fatalf("expected the recorded write, got %v", err)
			}
			if len(recorder.sent) != 1 {
				t.Fatalf("sent %d requests", len(recorder.sent))
			}
			sent := recorder.sent[0]
			if sent.Method != tc.Expected.Method || sent.URL.EscapedPath() != tc.Expected.RawPath {
				t.Fatalf("sent %s %s, want %s %s", sent.Method, sent.URL.EscapedPath(), tc.Expected.Method, tc.Expected.RawPath)
			}
			var body []byte
			if sent.Body != nil {
				if body, err = io.ReadAll(sent.Body); err != nil {
					t.Fatal(err)
				}
			}
			if string(body) != tc.Expected.BodyUTF8 {
				t.Fatalf("body %s, want %s", body, tc.Expected.BodyUTF8)
			}
			for _, name := range []string{"Authorization", "X-AWEB-Timestamp", "X-AWEB-Signed-Payload", "Content-Type"} {
				want, expected := tc.Expected.Headers[http.CanonicalHeaderKey(name)]
				if !expected {
					want = tc.Expected.Headers[toLowerASCII(name)]
					_, expected = tc.Expected.Headers[toLowerASCII(name)]
				}
				if got := sent.Header.Get(name); got != want || (!expected && got != "") {
					t.Fatalf("%s = %q, want %q", name, got, want)
				}
			}
		})
	}
}

func toLowerASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}
