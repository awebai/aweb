package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

func TestIdentityRegistryRouting(t *testing.T) {
	testIdentityRegistryRouting(t, false)
}

func TestIdentityRegistryRoutingWithLiveAWID(t *testing.T) {
	if os.Getenv("AW_REGISTRY_ROUTE_LIVE_AWID") != "1" {
		t.Skip("enable under the isolated CLI suite runner")
	}
	testIdentityRegistryRouting(t, true)
}

func testIdentityRegistryRouting(t *testing.T, live bool) {
	t.Helper()
	v := loadWhoVectors(t)
	var privateReads, publicReads atomic.Int32
	serveStatus := func(reads *atomic.Int32) http.HandlerFunc {
		var backend *httputil.ReverseProxy
		if live {
			fixture, _ := startAWIDFixture(t, "AWID_FIXTURE_ID_TREE_VECTOR=1")
			origin, err := url.Parse(fixture)
			if err != nil {
				t.Fatal(err)
			}
			backend = httputil.NewSingleHostReverseProxy(origin)
		}
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost && r.URL.Path == "/v1/namespaces/example.com/teams/backend/certificates" {
				if backend != nil {
					backend.ServeHTTP(w, r)
				} else {
					_ = json.NewEncoder(w).Encode(map[string]string{"status": "registered"})
				}
				return
			}
			reads.Add(1)
			if r.Method == http.MethodGet && r.URL.Path == "/v1/did/"+v.Keys["global_agent"].DIDAW+"/key" {
				if backend != nil {
					backend.ServeHTTP(w, r)
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]any{
					"did_aw": v.Keys["global_agent"].DIDAW, "current_did_key": v.Keys["global_agent"].DIDKey,
					"id_tree": map[string]any{"enrolled": true, "domain": "example.com"},
				})
				return
			}
			raw, err := io.ReadAll(r.Body)
			if err != nil {
				t.Error(err)
				http.Error(w, "unable to read request", http.StatusBadRequest)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(raw))
			var payload struct {
				Domain string   `json:"domain"`
				IDs    []string `json:"ids"`
			}
			if r.Method != "POST" || r.URL.Path != "/v1/id-certificates/status" ||
				json.Unmarshal(raw, &payload) != nil || payload.Domain != "example.com" ||
				!slices.Contains(payload.IDs, v.Keys["alice"].DIDAW) {
				t.Errorf("unexpected status request: %s %s %+v", r.Method, r.URL.Path, payload)
				http.Error(w, "unexpected status request", http.StatusBadRequest)
				return
			}
			if backend != nil {
				backend.ServeHTTP(w, r)
				return
			}
			_ = json.NewEncoder(w).Encode(v.Statuses["normal"])
		}
	}
	privateHandler := serveStatus(&privateReads)
	private := httptest.NewServer(privateHandler)
	t.Cleanup(private.Close)
	public := httptest.NewUnstartedServer(serveStatus(&publicReads))
	cert, root := identityRegistryTestCertificate(t)
	public.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	public.StartTLS()
	t.Cleanup(public.Close)
	namedPrivate := httptest.NewUnstartedServer(privateHandler)
	namedPrivate.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	namedPrivate.StartTLS()
	t.Cleanup(namedPrivate.Close)
	namedPrivateURL := strings.Replace(namedPrivate.URL, "127.0.0.1", "registry.test", 1)
	proxy := identityRegistryTestProxy(t, public.Listener.Addr().String())
	rootFile := filepath.Join(t.TempDir(), "registry-root.pem")
	if err := os.WriteFile(rootFile, root, 0600); err != nil {
		t.Fatal(err)
	}

	const all = "who verify status invite join accept-invite"
	const readers = "who verify status"
	for _, tc := range []struct {
		name, verbs, stored, env, flag, txt string
		private, public                     bool
		global, foreign, unmarked           bool
		broken, txtConflict, absent         bool
		certOnly                            bool
		conflicts                           []string
	}{
		{name: "recorded", verbs: all + " refresh", stored: private.URL, private: true},
		{name: "recorded with same env", verbs: all, stored: private.URL, env: private.URL, private: true},
		{name: "recorded with same flag", verbs: readers, stored: private.URL, flag: private.URL, private: true},
		{name: "recorded with same TXT", verbs: all, stored: namedPrivateURL, txt: namedPrivateURL, private: true},
		{name: "recorded with different private TXT", verbs: all, stored: private.URL, txt: namedPrivateURL, txtConflict: true, conflicts: []string{private.URL, namedPrivateURL}},
		{name: "global key and status", verbs: "who status", stored: private.URL, private: true, global: true},
		{name: "hosted owner and finish use private", verbs: "hosted-owner hosted-finish", stored: private.URL, private: true, global: true},
		{name: "global conflict before key read", verbs: "who status", stored: private.URL, txt: awid.DefaultAWIDRegistryURL, conflicts: []string{private.URL, awid.DefaultAWIDRegistryURL}, global: true},
		{name: "recorded wins over env", verbs: all, stored: private.URL, env: awid.DefaultAWIDRegistryURL, private: true},
		{name: "conflicting flag", verbs: readers, stored: private.URL, flag: awid.DefaultAWIDRegistryURL, conflicts: []string{private.URL, awid.DefaultAWIDRegistryURL}},
		{name: "conflicting TXT", verbs: all, stored: private.URL, txt: awid.DefaultAWIDRegistryURL, txtConflict: true, conflicts: []string{private.URL, awid.DefaultAWIDRegistryURL}},
		{name: "missing TXT", verbs: all, stored: private.URL, txt: "-"},
		{name: "hosted", verbs: all, stored: awid.DefaultAWIDRegistryURL, public: true},
		{name: "no record", verbs: all, public: true},
		{name: "no selected home", verbs: "verify", public: true, absent: true},
		{name: "empty identity home", verbs: "verify", public: true, absent: true, certOnly: true},
		{name: "certificate only public", verbs: "who verify", stored: awid.DefaultAWIDRegistryURL, public: true, certOnly: true},
		{name: "certificate only private", verbs: "who verify", stored: private.URL, private: true, certOnly: true},
		{name: "foreign namespace", verbs: "verify", stored: private.URL, foreign: true, public: true},
		{name: "unmarked origin", verbs: readers, stored: private.URL, unmarked: true},
		{name: "unreadable installed chain", verbs: "who verify invite", stored: private.URL, broken: true},
		{name: "hosted with unreadable installed chain", verbs: "verify", stored: awid.DefaultAWIDRegistryURL, broken: true, public: true},
		{name: "hosted with unrelated env", verbs: all, stored: awid.DefaultAWIDRegistryURL, env: private.URL, public: true},
		{name: "hosted with explicit TXT", verbs: all, stored: awid.DefaultAWIDRegistryURL, txt: awid.DefaultAWIDRegistryURL, public: true},
		{name: "explicit flag", verbs: readers, flag: private.URL, private: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, verb := range strings.Fields(tc.verbs) {
				t.Run(verb, func(t *testing.T) {
					issuance := verb == "invite" || verb == "join" || verb == "accept-invite"
					private, conflicts := tc.private, tc.conflicts
					if tc.txtConflict && issuance {
						private, conflicts = true, nil
					}
					dir := whoIdentity(t, v, !tc.global && !tc.foreign, tc.global || tc.foreign)
					if tc.global {
						identityRegistryTestGlobalHome(t, dir, v)
					}
					path := filepath.Join(dir, ".aw", "identity.yaml")
					identity, err := awconfig.LoadWorktreeIdentityFrom(path)
					if err != nil {
						t.Fatal(err)
					}
					identity.RegistryURL, identity.RegistryOperatorOrigin = tc.stored, tc.stored
					if tc.foreign {
						identity.Address = "external.example.net/coordinator"
					}
					if tc.unmarked {
						identity.RegistryOperatorOrigin = ""
					}
					if err := awconfig.SaveWorktreeIdentityTo(path, identity); err != nil {
						t.Fatal(err)
					}
					if tc.broken {
						chainPath := filepath.Join(dir, ".aw", "id-chain.json")
						if err := os.Remove(chainPath); err != nil {
							t.Fatal(err)
						}
						if err := os.Mkdir(chainPath, 0700); err != nil {
							t.Fatal(err)
						}
					}
					if tc.absent {
						dir = t.TempDir()
						if tc.certOnly {
							if err := os.Mkdir(filepath.Join(dir, ".aw"), 0700); err != nil {
								t.Fatal(err)
							}
						}
					} else if tc.certOnly {
						makeCertificateOnlyRegistryHome(t, dir, tc.stored, identity.DID, v.Keys["seat"].SeedHex)
					}
					record := ""
					if tc.txt != "-" {
						record = idCreateDNSRecordValue(v.Keys["root"].DIDKey, "")
						if tc.txt != "" {
							record += "; registry=" + tc.txt
						}
					}
					env := append(withoutEnvForTest(testCommandEnv(t.TempDir()), "HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "NO_PROXY", "no_proxy", "ALL_PROXY", "all_proxy"), "AW_REGISTRY_ROUTE_CHILD=1",
						"AW_REGISTRY_ROUTE_TXT="+record, "AW_REGISTRY_ROUTE_CA="+rootFile,
						"GODEBUG=x509usefallbackroots=1", "HTTPS_PROXY="+proxy, "NO_PROXY=registry.test", "APP_ENV=production",
						"AW_REGISTRY_ROUTE_ENV="+tc.env, "AW_REGISTRY_ROUTE_TEAM_SEED="+v.Keys["seat"].SeedHex)

					args := []string{verb, "--json"}
					var input []byte
					if verb == "status" {
						args = append([]string{"id"}, args...)
					} else if verb == "refresh" {
						args = append([]string{"id", "parent"}, args...)
					} else if tc.flag != "" {
						args = append(args, "--registry", tc.flag)
					}
					if verb == "verify" {
						input = identityRegistryTestExport(t, v)
					}
					cmd := exec.CommandContext(t.Context(), os.Args[0], append([]string{"-test.run=^TestIdentityRegistryRouteChild$", "--"}, args...)...)
					cmd.Dir, cmd.Env, cmd.Stdin = dir, env, bytes.NewReader(input)
					beforePrivate, beforePublic := privateReads.Load(), publicReads.Load()
					output, err := cmd.CombinedOutput()
					gotPrivate, gotPublic := privateReads.Load()-beforePrivate, publicReads.Load()-beforePublic
					if tc.global && private && verb == "who" && gotPrivate != 2 {
						t.Errorf("private evidence calls = %d, want key and status: %s (%v)", gotPrivate, output, err)
					}
					if (gotPrivate > 0) != (private && verb != "status") || (gotPublic > 0) != (tc.public && verb != "status") ||
						(!tc.global && (verb == "who" || verb == "verify") && (gotPrivate > 1 || gotPublic > 1)) {
						t.Errorf("private/public requests = %d/%d: %s (%v)", gotPrivate, gotPublic, output, err)
					}
					if verb == "status" {
						if err != nil {
							t.Fatalf("offline status: %s (%v)", output, err)
						}
						return
					}
					if len(conflicts) > 0 {
						for _, origin := range conflicts {
							if err == nil || !strings.Contains(string(output), origin) {
								t.Errorf("refusal must name %q: %s (%v)", origin, output, err)
							}
						}
					} else if tc.broken && !tc.public {
						if err == nil && !strings.Contains(string(output), "evidence_unavailable") {
							t.Errorf("unreadable home must refuse: %s (%v)", output, err)
						}
					} else if private || tc.public {
						if err != nil || ((verb == "who" || verb == "verify") && !strings.Contains(string(output), `"reason": "verified"`)) {
							t.Errorf("expected verified status: %s (%v)", output, err)
						}
					}
				})
			}
		})
	}
}

func TestIdentityRegistryRouteChild(t *testing.T) {
	if os.Getenv("AW_REGISTRY_ROUTE_CHILD") != "1" {
		return
	}
	t.Setenv("AWID_REGISTRY_URL", os.Getenv("AW_REGISTRY_ROUTE_ENV"))
	root, err := os.ReadFile(os.Getenv("AW_REGISTRY_ROUTE_CA"))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(root) {
		t.Fatal("load fixture trust root")
	}
	x509.SetFallbackRoots(pool)
	serveRosterTXT(t, os.Getenv("AW_REGISTRY_ROUTE_TXT"))
	for i, arg := range os.Args {
		if arg == "--" {
			args := os.Args[i+1:]
			switch args[0] {
			case "hosted-owner", "hosted-finish":
				testHostedRegistryRoute(t, args[0])
				return
			case "invite", "join", "accept-invite":
				args = identityRegistryTestTeamCommand(t, args[0])
			}
			os.Args = append([]string{"aw"}, args...)
			main()
			return
		}
	}
	t.Fatal("missing command arguments")
}

func testHostedRegistryRoute(t *testing.T, command string) {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	identity, err := resolveIdentityForDir(wd)
	if err != nil {
		t.Fatal(err)
	}
	home := filepath.Dir(identity.SigningKeyPath)
	key, err := awid.LoadSigningKey(identity.SigningKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	resolver := &awid.NetTXTResolver{}
	registry := newAWIDRegistryClient(nil, resolver)
	if command == "hosted-owner" {
		issuer, err := hostedOwnerIssuer(t.Context(), wd, &hostedOwnerAuthority{home: home, did: identity.DID, stableID: identity.StableID, registryURL: identity.RegistryURL}, registry, resolver)
		if err != nil || issuer == nil {
			t.Fatalf("hosted owner route: %v", err)
		}
		defer issuer.close()
		return
	}
	bundle, err := awconfig.LoadInstalledIDChain(home)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := bundle.Leaf()
	if err != nil {
		t.Fatal(err)
	}
	parent := leaf.Signed()["certificate"].(map[string]any)["parent"].(map[string]any)
	tree, err := newHostedIDTreeRecovery(hostedIdentityContext{
		Domain: leaf.Domain(), ParentKind: parent["kind"].(string), ParentID: parent["id"].(string), RegistryURL: identity.RegistryURL,
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := finishHostedIDTree(t.Context(), tree,
		awid.IDTreeCreationResponse{IDChain: awid.ReceivedIDChain(bundle.Bundle)},
		workspaceTeamIdentityMaterial{SigningKey: key, DIDKey: identity.DID, StableID: identity.StableID, IdentityScope: awid.IdentityModeGlobal},
		t.TempDir(), registry, resolver)
	if err != nil || result == nil || result.Reason != "verified" {
		t.Fatalf("hosted completion route: %+v %v", result, err)
	}
}

// Both accept commands run the complete parent exchange. Their team
// membership goes to the fixture's team authority independently of ancestry.
func identityRegistryTestTeamCommand(t *testing.T, command string) []string {
	t.Helper()
	seed, err := hex.DecodeString(os.Getenv("AW_REGISTRY_ROUTE_TEAM_SEED"))
	if err != nil || len(seed) != ed25519.SeedSize {
		t.Fatalf("read fixture team seed: %v", err)
	}
	if err := awconfig.SaveTeamKey("example.com", "backend", ed25519.NewKeyFromSeed(seed)); err != nil {
		t.Fatal(err)
	}
	if command == "invite" {
		return []string{"id", "team", "invite", "--namespace", "example.com", "--team", "backend", "--json"}
	}
	parent, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	id, err := awid.GenerateUUID4()
	if err != nil {
		t.Fatal(err)
	}
	invite := &awconfig.TeamInvite{
		InviteID: id, Domain: "example.com", TeamName: "backend", Secret: id,
		IdentityScope: awid.IdentityModeLocal,
		RegistryURL:   awid.DefaultAWIDRegistryURL, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	if err := awconfig.SaveTeamInvite(invite); err != nil {
		t.Fatal(err)
	}
	token, err := awconfig.EncodeInviteToken(invite)
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(t.TempDir())
	args := []string{"id", "team", "accept-invite"}
	if command == "join" {
		args = []string{"team", "join", "--no-connect"}
	}
	return append(args, token, "--parent", parent, "--name", "child-"+id[:8], "--json")
}

func makeCertificateOnlyRegistryHome(t *testing.T, dir, origin, did, seedHex string) {
	t.Helper()
	const team = "backend:example.com"
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := awid.SignTeamCertificate(ed25519.NewKeyFromSeed(seed), awid.TeamCertificateFields{
		Team: team, Alias: "coordinator", MemberDIDKey: did, IdentityScope: awid.IdentityModeLocal,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := awconfig.SaveTeamCertificateForTeam(dir, team, cert); err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveTeamState(dir, &awconfig.TeamState{ActiveTeam: team, Memberships: []awconfig.TeamMembership{
		{TeamID: team, Alias: "coordinator", CertPath: awconfig.TeamCertificateRelativePath(team), RegistryURL: origin, RegistryOperatorOrigin: origin},
	}}); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(awconfig.WorktreeIdentityPath(dir)); err != nil {
		t.Fatal(err)
	}
}

func identityRegistryTestGlobalHome(t *testing.T, dir string, v whoVectors) {
	t.Helper()
	key := v.Keys["global_agent"]
	seed, err := hex.DecodeString(key.SeedHex)
	if err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(dir, ".aw")
	identity := &awconfig.WorktreeIdentity{
		DID: key.DIDKey, StableID: key.DIDAW, Address: "address-alias.example.com/agent",
		Custody: awid.CustodySelf, IdentityScope: awid.IdentityModeGlobal,
	}
	if err := awconfig.SaveWorktreeIdentityTo(filepath.Join(home, "identity.yaml"), identity); err != nil {
		t.Fatal(err)
	}
	if err := awid.SaveSigningKey(filepath.Join(home, "signing.key"), ed25519.NewKeyFromSeed(seed)); err != nil {
		t.Fatal(err)
	}
	chain := map[string]any{"v": 1, "type": "aweb.id-chain", "certificates": []any{v.Certificates["alice"].Signed, v.Certificates["global-agent"].Signed}}
	if err := awconfig.SaveInstalledIDChain(home, chain); err != nil {
		t.Fatal(err)
	}
}

func identityRegistryTestExport(t *testing.T, v whoVectors) []byte {
	t.Helper()
	seed, err := hex.DecodeString(v.Keys["coordinator"].SeedHex)
	if err != nil {
		t.Fatal(err)
	}
	message := &awid.MessageEnvelope{From: "example.com/coordinator", FromDID: v.Keys["coordinator"].DIDKey, To: "recipient", Type: "mail", Body: "fixture", Timestamp: time.Now().UTC().Format(time.RFC3339)}
	signature, err := awid.SignMessage(ed25519.NewKeyFromSeed(seed), message)
	if err != nil {
		t.Fatal(err)
	}
	return marshalMessageExport(t, messageExport{
		V: 1, Type: "aweb.message-envelope", SignedPayload: awid.CanonicalJSON(message), Signature: signature, SigningKeyID: message.FromDID,
		IDChain: awid.ReceivedIDChain{"v": 1, "type": "aweb.id-chain", "certificates": []any{v.Certificates["alice"].Signed, v.Certificates["coordinator"].Signed}},
	})
}

func identityRegistryTestCertificate(t *testing.T) (tls.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	leaf := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"api.awid.ai", "registry.test"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, leaf, leaf, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// Only the fixture's public default is reachable through this proxy.
func identityRegistryTestProxy(t *testing.T, publicAddr string) string {
	t.Helper()
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "CONNECT" || r.Host != "api.awid.ai:443" {
			t.Errorf("unexpected proxy request %s %s", r.Method, r.Host)
			http.Error(w, "blocked by fixture", http.StatusForbidden)
			return
		}
		upstream, err := net.Dial("tcp", publicAddr)
		if err != nil {
			http.Error(w, "fixture unavailable", http.StatusBadGateway)
			return
		}
		defer upstream.Close()
		client, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer client.Close()
		if _, err := rw.WriteString("HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
			t.Error(err)
			return
		}
		if err := rw.Flush(); err != nil {
			t.Error(err)
			return
		}
		go func() {
			_, _ = io.Copy(upstream, rw)
			_ = upstream.Close()
		}()
		_, _ = io.Copy(client, upstream)
	}))
	t.Cleanup(proxy.Close)
	return proxy.URL
}
