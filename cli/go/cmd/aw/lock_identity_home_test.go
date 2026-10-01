package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	aweb "github.com/awebai/aw"
	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

// The real binary must select the external principal for every lock operation,
// even when the cwd has working credentials for another principal/team.
func TestLockCommandsUseExternalIdentityHome(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	bin := filepath.Join(root, "aw")
	buildAwBinary(t, ctx, bin)
	for _, kind := range []string{"native", "grant"} {
		for _, source := range []string{"flag", "environment"} {
			for _, cwdKind := range []string{"empty", "shadow"} {
				t.Run(kind+"/"+source+"/"+cwdKind, func(t *testing.T) {
					dir := filepath.Join(root, kind, source, cwdKind)
					instance := filepath.Join(dir, "instance")
					if err := os.MkdirAll(instance, 0700); err != nil {
						t.Fatal(err)
					}
					pub, key, err := awid.GenerateKeypair()
					if err != nil {
						t.Fatal(err)
					}
					teamID, alias := "runtime:aweb.test", "principal"
					if kind == "grant" {
						teamID, alias = "backend:acme.com", "alice"
					}
					var calls, fallbackCalls atomic.Int32
					var held, refuse atomic.Bool
					fallback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						fallbackCalls.Add(1)
						http.Error(w, "must not use another principal or registry", 500)
					}))
					defer fallback.Close()
					server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						calls.Add(1)
						body, err := io.ReadAll(r.Body)
						if err != nil {
							t.Error(err)
						}
						assertLockPrincipalRequest(t, r, body, kind, teamID, pub)
						if refuse.Load() {
							w.WriteHeader(http.StatusForbidden)
							_ = json.NewEncoder(w).Encode(map[string]string{"detail": "lock authority refused"})
							return
						}
						switch {
						case r.Method == http.MethodGet && r.URL.Path == "/v1/reservations":
							if r.URL.Query().Get("prefix") != "integration/" {
								t.Errorf("prefix=%q", r.URL.RawQuery)
							}
							locks := []aweb.ReservationView{{ResourceKey: "integration/other", HolderAlias: "other"}}
							if held.Load() {
								locks = append(locks, aweb.ReservationView{ResourceKey: "integration/main", HolderAlias: alias})
							}
							_ = json.NewEncoder(w).Encode(aweb.ReservationListResponse{Reservations: locks})
						case r.Method == http.MethodPost && r.URL.Path == "/v1/reservations":
							var req aweb.ReservationAcquireRequest
							if err := json.Unmarshal(body, &req); err != nil {
								t.Error(err)
							}
							if req.ResourceKey != "integration/main" || req.TTLSeconds != 60 {
								t.Errorf("acquire=%+v", req)
							}
							if held.Swap(true) {
								t.Error("duplicate acquisition")
							}
							_ = json.NewEncoder(w).Encode(aweb.ReservationAcquireResponse{Status: "acquired", ResourceKey: req.ResourceKey, HolderAlias: alias})
						case r.Method == http.MethodPost && r.URL.Path == "/v1/reservations/renew":
							var req aweb.ReservationRenewRequest
							if err := json.Unmarshal(body, &req); err != nil {
								t.Error(err)
							}
							if req.ResourceKey != "integration/main" || req.TTLSeconds != 120 {
								t.Errorf("renew=%+v", req)
							}
							if !held.Load() {
								t.Error("renew without acquisition")
							}
							_ = json.NewEncoder(w).Encode(aweb.ReservationRenewResponse{Status: "renewed", ResourceKey: req.ResourceKey, ExpiresAt: "2099-01-01T00:00:00Z"})
						case r.Method == http.MethodPost && r.URL.Path == "/v1/reservations/release":
							var req aweb.ReservationReleaseRequest
							if err := json.Unmarshal(body, &req); err != nil {
								t.Error(err)
							}
							if req.ResourceKey != "integration/main" {
								t.Errorf("release=%+v", req)
							}
							if !held.Swap(false) {
								t.Error("release without acquisition")
							}
							_ = json.NewEncoder(w).Encode(aweb.ReservationReleaseResponse{Status: "released", ResourceKey: req.ResourceKey})
						default:
							t.Errorf("unexpected %s %s", r.Method, r.URL)
							http.NotFound(w, r)
						}
					}))
					defer server.Close()
					home := filepath.Join(dir, "principal", ".aw")
					keyPath := filepath.Join(home, "signing.key")
					if kind == "grant" {
						var grant *awconfig.GrantHome
						pub, grant = writeGrantHomeForTest(t, home, server.URL)
						grant.Scopes = []string{"coord.read", "coord.write"}
						if err := awconfig.SaveGrantHomeTo(awconfig.GrantHomeStatePath(home), grant); err != nil {
							t.Fatal(err)
						}
						keyPath = awconfig.GrantHomeSigningKeyPath(home)
					} else {
						writeMessagingPrincipalForTest(t, filepath.Dir(home), server.URL, alias, awid.ComputeDIDKey(pub), key)
						state, err := awconfig.LoadTeamStateFromIdentityHome(home)
						if err != nil {
							t.Fatal(err)
						}
						state.Memberships[0].RegistryURL = fallback.URL
						if err := awconfig.SaveTeamState(filepath.Dir(home), state); err != nil {
							t.Fatal(err)
						}
					}
					if cwdKind == "shadow" {
						writeTestConfig(t, instance, fallback.URL)
					}
					before, shadowBefore := fileDigestsForTest(t, home), fileDigestsForTest(t, instance)
					run := func(args ...string) (string, error) {
						return runReadOnlyBinary(ctx, bin, instance, filepath.Join(dir, "user"), home, source, append(args, "--json")...)
					}
					list := []string{"lock", "list", "--prefix", "integration/", "--mine"}
					acquire := []string{"lock", "acquire", "--resource-key", "integration/main", "--ttl-seconds", "60"}
					renew := []string{"lock", "renew", "--resource-key", "integration/main", "--ttl-seconds", "120"}
					release := []string{"lock", "release", "--resource-key", "integration/main"}
					for i, args := range [][]string{list, acquire, renew, list, release, list} {
						out, err := run(args...)
						if err != nil {
							t.Fatalf("%v: %v\n%s", args, err, out)
						}
						if args[1] == "list" {
							var got aweb.ReservationListResponse
							if err := json.Unmarshal([]byte(out), &got); err != nil {
								t.Fatal(err)
							}
							want := 0
							if i == 3 {
								want = 1
							}
							if len(got.Reservations) != want || (want == 1 && got.Reservations[0].HolderAlias != alias) {
								t.Errorf("wrong principal's locks: %s", out)
							}
						} else if !strings.Contains(out, "integration/main") {
							t.Errorf("wrong result: %s", out)
						}
					}
					if calls.Load() != 6 || held.Load() {
						t.Fatalf("round trip calls=%d held=%t", calls.Load(), held.Load())
					}
					for _, args := range [][]string{list, acquire, renew, release} {
						beforeCalls := calls.Load()
						out, err := run(append(append([]string{}, args...), "--team", "unknown:acme.com")...)
						want := "not present in workspace memberships"
						if kind == "grant" {
							want = "conflicts"
						}
						if err == nil || !strings.Contains(out, want) {
							t.Errorf("wrong-team %v: %v\n%s", args, err, out)
						}
						if calls.Load() != beforeCalls {
							t.Error("team mismatch reached network")
						}
					}
					refuse.Store(true)
					for _, args := range [][]string{list, acquire, renew, release} {
						beforeCalls := calls.Load()
						out, err := run(args...)
						if err == nil || !strings.Contains(out, "lock authority refused") {
							t.Errorf("refusal %v: %v\n%s", args, err, out)
						}
						if calls.Load() != beforeCalls+1 {
							t.Error("refusal retried with other authority")
						}
					}
					// Administrative revoke remains outside the holder workflow.
					for _, args := range [][]string{{"lock", "revoke", "--prefix", "integration/"}} {
						beforeCalls := calls.Load()
						out, err := run(args...)
						if err == nil || !strings.Contains(out, "not yet identity-home-aware") {
							t.Errorf("unapproved command admitted: %v %s", err, out)
						}
						if calls.Load() != beforeCalls {
							t.Error("unapproved command reached network")
						}
					}
					if !reflect.DeepEqual(before, fileDigestsForTest(t, home)) {
						t.Error("lock commands changed principal material")
					}
					if err := os.Remove(keyPath); err != nil {
						t.Fatal(err)
					}
					for _, args := range [][]string{list, acquire, renew, release} {
						beforeCalls := calls.Load()
						out, err := run(args...)
						if err == nil || !strings.Contains(out, "key") {
							t.Errorf("missing selected key: %v %s", err, out)
						}
						if calls.Load() != beforeCalls {
							t.Error("missing selected key reached network")
						}
					}
					if fallbackCalls.Load() != 0 {
						t.Errorf("fallback requests=%d", fallbackCalls.Load())
					}
					if !reflect.DeepEqual(shadowBefore, fileDigestsForTest(t, instance)) {
						t.Error("lock commands changed cwd principal material")
					}
				})
			}
		}
	}
}

func assertLockPrincipalRequest(t *testing.T, r *http.Request, body []byte, kind, teamID string, pub ed25519.PublicKey) {
	t.Helper()
	hash := sha256.Sum256(body)
	if kind == "grant" {
		assertReadOnlyGrantRequest(t, r, pub)
		payload, err := base64.RawURLEncoding.DecodeString(r.Header.Get("X-AWEB-Signed-Payload"))
		if err != nil {
			t.Error(err)
			return
		}
		var fields map[string]any
		if err := json.Unmarshal(payload, &fields); err != nil {
			t.Error(err)
			return
		}
		if fields["body_sha256"] != hex.EncodeToString(hash[:]) {
			t.Errorf("grant body not bound: %s", payload)
		}
		return
	}
	cert := requireCertificateAuthForTest(t, r)
	if cert.Team != teamID {
		t.Errorf("certificate team=%q want %q", cert.Team, teamID)
	}
	parts := strings.Fields(r.Header.Get("Authorization"))
	if len(parts) != 3 || parts[1] != awid.ComputeDIDKey(pub) {
		t.Errorf("wrong principal signature: %v", parts)
		return
	}
	payload, err := awid.CanonicalJSONValue(map[string]string{"body_sha256": hex.EncodeToString(hash[:]), "team_id": teamID, "timestamp": r.Header.Get("X-AWEB-Timestamp")})
	if err != nil {
		t.Error(err)
		return
	}
	sig, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil || !ed25519.Verify(pub, []byte(payload), sig) {
		t.Error("invalid selected-principal signature")
	}
}
