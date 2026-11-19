package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

// writeDropper drops the answer to every successful registry write while it
// is dropping, through the fault front: the registry applied the write and aw
// never hears so.
type writeDropper struct {
	mu       sync.Mutex
	dropping bool
	dropped  []string
}

func (d *writeDropper) dropWrites(drop bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.dropping = drop
}

func (d *writeDropper) droppedWrites() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string{}, d.dropped...)
}

func (d *writeDropper) fault() registryFault {
	return registryFault{DropAnswer: func(response *http.Response) bool {
		d.mu.Lock()
		defer d.mu.Unlock()
		request := response.Request
		write := request.Method != http.MethodGet && request.Method != http.MethodHead
		if !d.dropping || !write || response.StatusCode < 200 || response.StatusCode >= 300 {
			return false
		}
		d.dropped = append(d.dropped, request.Method+" "+request.URL.Path)
		return true
	}}
}

// registryWriteFixture is a world's namespace, team and one member
// certificate, its controller and team keys stored under HOME.
type registryWriteFixture struct {
	domain      string
	teamKey     ed25519.PrivateKey
	certificate *awid.TeamCertificate
}

func newRegistryWriteFixture(t *testing.T) registryWriteFixture {
	t.Helper()
	world := newRealCommandWorld(t)
	if err := awconfig.SaveControllerKey(world.Domain, world.NamespaceKey); err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveTeamKey(world.Domain, "backend", world.TeamKey); err != nil {
		t.Fatal(err)
	}
	certificate := world.registerMemberCertificate(t, awid.TeamCertificateFields{MemberDIDKey: didOf(newKey(t)), Alias: "alice", IdentityScope: awid.IdentityModeLocal})
	return registryWriteFixture{domain: world.Domain, teamKey: world.TeamKey, certificate: certificate}
}

func requireRegistryNotFound(t *testing.T, what string, err error) {
	t.Helper()
	var registryErr *awid.RegistryError
	if !errors.As(err, &registryErr) || registryErr.StatusCode != http.StatusNotFound {
		t.Fatalf("%s: want the registry's 404 after the write applied, got %v", what, err)
	}
}

// A controller write that is not replay-safe and whose answer is lost after
// AWID applied it says the registry may have applied it, as text and in
// --json, for each class of write: team, certificate and namespace. A team
// key rotation keeps its pending key and says that running it again finishes.
func TestControllerWriteWithALostAnswerSaysTheRegistryMayHaveAppliedIt(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 240*time.Second)
	defer cancel()
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	proxy := &writeDropper{}
	registryURL := newRealCommandWorld(t).frontRegistry(t, proxy.fault())
	registry := awid.NewAWIDRegistryClient(&http.Client{Timeout: 20 * time.Second}, nil)
	if err := registry.TrustRegistryOrigin(registryURL); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	for _, write := range []struct {
		class   string
		args    func(t *testing.T, f registryWriteFixture) []string
		says    string
		applied func(t *testing.T, f registryWriteFixture)
	}{
		{
			class: "team",
			args: func(t *testing.T, f registryWriteFixture) []string {
				// Delete-team needs the team's active certificates revoked first.
				if err := registry.RevokeCertificate(ctx, registryURL, f.domain, "backend", f.certificate.CertificateID, f.teamKey); err != nil {
					t.Fatalf("revoke before team delete: %v", err)
				}
				return []string{"id", "team", "delete", "--namespace", f.domain, "--team", "backend", "--registry", registryURL}
			},
			says: "The registry may have applied this team delete; check its state (for example `aw id team members`) before retrying.",
			applied: func(t *testing.T, f registryWriteFixture) {
				_, err := registry.GetTeam(ctx, registryURL, f.domain, "backend", f.teamKey)
				requireRegistryNotFound(t, "team after delete", err)
			},
		},
		{
			class: "certificate",
			args: func(t *testing.T, f registryWriteFixture) []string {
				return []string{"id", "team", "remove-member", "--namespace", f.domain, "--team", "backend", "--cert-id", f.certificate.CertificateID, "--registry", registryURL}
			},
			says: "The registry may have applied this certificate revocation; check its state (for example `aw id team members --include-revoked`) before retrying.",
			applied: func(t *testing.T, f registryWriteFixture) {
				status, err := registry.GetTeamCertificateStatus(ctx, registryURL, f.domain, "backend", f.certificate.CertificateID)
				if err != nil {
					t.Fatal(err)
				}
				if status.Status != "revoked" {
					t.Fatalf("certificate status %q after the lost revocation, want revoked", status.Status)
				}
			},
		},
		{
			class: "namespace",
			args: func(t *testing.T, f registryWriteFixture) []string {
				if err := registry.RevokeCertificate(ctx, registryURL, f.domain, "backend", f.certificate.CertificateID, f.teamKey); err != nil {
					t.Fatalf("revoke before namespace delete: %v", err)
				}
				return []string{"id", "namespace", "delete", "--domain", f.domain, "--registry", registryURL}
			},
			says: "The registry may have applied this namespace delete; check its state (for example `aw id namespace <domain>`) before retrying.",
			applied: func(t *testing.T, f registryWriteFixture) {
				_, _, err := registry.GetNamespaceAt(ctx, registryURL, f.domain)
				requireRegistryNotFound(t, "namespace after delete", err)
			},
		},
		{
			class: "team key rotation",
			args: func(t *testing.T, f registryWriteFixture) []string {
				return []string{"id", "team", "rotate-key", "--namespace", f.domain, "--team", "backend", "--registry", registryURL}
			},
			says: "the registry may have applied this rotation; the new key is kept as the pending key, and running aw id team rotate-key again finishes it.",
			applied: func(t *testing.T, f registryWriteFixture) {
				pending, err := awconfig.LoadPendingTeamKey(f.domain, "backend")
				if err != nil || pending == nil {
					t.Fatalf("pending team key after the lost rotation: %v", err)
				}
				team, err := registry.GetTeam(ctx, registryURL, f.domain, "backend", pending)
				if err != nil {
					t.Fatal(err)
				}
				pendingDID := awid.ComputeDIDKey(pending.Public().(ed25519.PublicKey))
				if team.TeamDIDKey != pendingDID {
					t.Fatalf("AWID holds %s, not the pending key", team.TeamDIDKey)
				}
				// Running it again finishes the rotation, as the message says.
				again := exec.CommandContext(ctx, bin, "id", "team", "rotate-key", "--namespace", f.domain, "--team", "backend", "--registry", registryURL)
				again.Env = append(idCreateCommandEnv(tmp), "AWID_REGISTRY_URL="+registryURL)
				again.Dir = tmp
				if out, err := again.CombinedOutput(); err != nil {
					t.Fatalf("running rotate-key again: %v\n%s", err, out)
				}
				teamKey, err := awconfig.LoadTeamKey(f.domain, "backend")
				if err != nil || awid.ComputeDIDKey(teamKey.Public().(ed25519.PublicKey)) != pendingDID {
					t.Fatalf("team key after running rotate-key again is not the key AWID holds: %v", err)
				}
			},
		},
	} {
		for _, asJSON := range []bool{false, true} {
			name := write.class + map[bool]string{false: " text", true: " json"}[asJSON]
			t.Run(name, func(t *testing.T) {
				fixture := newRegistryWriteFixture(t)
				args := write.args(t, fixture)
				if asJSON {
					args = append(args, "--json")
				}
				proxy.dropWrites(true)
				defer proxy.dropWrites(false)
				before := len(proxy.droppedWrites())
				run := exec.CommandContext(ctx, bin, args...)
				run.Env = append(idCreateCommandEnv(tmp), "AWID_REGISTRY_URL="+registryURL)
				run.Dir = tmp
				var stdout, stderr bytes.Buffer
				run.Stdout, run.Stderr = &stdout, &stderr
				if err := run.Run(); err == nil {
					t.Fatalf("command succeeded although its answer was dropped:\n%s\n%s", stdout.String(), stderr.String())
				}
				proxy.dropWrites(false)
				if dropped := proxy.droppedWrites()[before:]; len(dropped) != 1 {
					t.Fatalf("dropped answers %v, want exactly the one write", dropped)
				}
				write.applied(t, fixture)
				if !strings.Contains(stderr.String(), write.says) {
					t.Fatalf("text does not say the registry may have applied the write:\n%s", stderr.String())
				}
				if asJSON {
					var envelope struct {
						Error struct {
							Code    string `json:"code"`
							Message string `json:"message"`
						} `json:"error"`
					}
					if err := json.Unmarshal(stdout.Bytes(), &envelope); err != nil {
						t.Fatalf("--json error envelope: %v\n%s", err, stdout.String())
					}
					if !strings.Contains(envelope.Error.Message, write.says) || envelope.Error.Code != "outcome_unknown" {
						t.Fatalf("--json error %+v does not say the registry may have applied the write", envelope.Error)
					}
				}
			})
		}
	}
}
