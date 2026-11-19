package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/awebai/aw/awid"
)

// Every controller write aw makes, against the AWID release production runs
// (scripts/test-egress/production-awid, awid-service 0.5.39) and against this
// repository's AWID: accepted as signed, and refused with 401 when its body is
// changed after signing. Only a signature covering the request's bytes tells
// the two apart; the legacy form signed the operation's claims, not the body.

// changeBodyAfterSigning appends a space to each write's body (an empty body
// becomes {}), keeping the request's headers, and so its signature.
type changeBodyAfterSigning struct{ inner http.RoundTripper }

func (c changeBodyAfterSigning) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method == http.MethodGet {
		return c.inner.RoundTrip(req)
	}
	var sent []byte
	if req.Body != nil {
		var err error
		if sent, err = io.ReadAll(req.Body); err != nil {
			return nil, err
		}
	}
	changed := append(sent, ' ')
	if len(sent) == 0 {
		changed = []byte("{}")
	}
	out := req.Clone(req.Context())
	out.Body = io.NopCloser(bytes.NewReader(changed))
	out.ContentLength = int64(len(changed))
	out.Header.Set("Content-Type", "application/json")
	out.Header.Set("Content-Length", strconv.Itoa(len(changed)))
	return c.inner.RoundTrip(out)
}

// controllerWriteWorld is one registry with a namespace and a team every
// write may use, and the fresh names one write needs. The release runs with
// its production rate limits, so writes share what they do not consume.
type controllerWriteWorld struct {
	ctx                   context.Context
	url, domain, team     string
	namespaceKey, teamKey ed25519.PrivateKey
	setup                 *awid.RegistryClient
	address, addressDIDAW string
	addressID, addressKey string
	certificate           *awid.TeamCertificate
	rotatedKey            ed25519.PrivateKey
	resigned              *awid.ResignedRecords
	memberChanges         []awid.MemberCertificateChange
}

func newKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, key, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func freshName(t *testing.T, prefix string) string {
	t.Helper()
	suffix := make([]byte, 5)
	if _, err := rand.Read(suffix); err != nil {
		t.Fatal(err)
	}
	return prefix + hex.EncodeToString(suffix)
}

func trustedClient(t *testing.T, url string, transport http.RoundTripper) *awid.RegistryClient {
	t.Helper()
	client := awid.NewAWIDRegistryClient(&http.Client{Transport: transport, Timeout: 20 * time.Second}, nil)
	if err := client.TrustRegistryOrigin(url); err != nil {
		t.Fatal(err)
	}
	return client
}

// ownNamespace gives the write a namespace of its own, registered.
func (w *controllerWriteWorld) ownNamespace(t *testing.T) {
	t.Helper()
	w.domain, w.namespaceKey = freshName(t, "cov-")+".test", newKey(t)
	if _, err := w.setup.RegisterNamespaceAt(w.ctx, w.url, w.domain, didOf(w.namespaceKey), w.namespaceKey); err != nil {
		t.Fatalf("setup namespace: %v", err)
	}
}

// ownTeam gives the write a team of its own in the shared namespace.
func (w *controllerWriteWorld) ownTeam(t *testing.T) {
	t.Helper()
	w.team, w.teamKey = freshName(t, "team-"), newKey(t)
	if _, err := w.setup.CreateTeam(w.ctx, w.url, w.domain, w.team, "Team", didOf(w.teamKey), w.namespaceKey); err != nil {
		t.Fatalf("setup team: %v", err)
	}
}

func (w *controllerWriteWorld) newCertificate(t *testing.T) *awid.TeamCertificate {
	t.Helper()
	cert, err := awid.SignTeamCertificate(w.teamKey, awid.TeamCertificateFields{
		Team: awid.BuildTeamID(w.domain, w.team), MemberDIDKey: didOf(newKey(t)), Alias: freshName(t, "m-"), IdentityScope: "local",
	})
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func (w *controllerWriteWorld) identity(t *testing.T) (string, string) {
	t.Helper()
	key := newKey(t)
	pub := key.Public().(ed25519.PublicKey)
	if _, err := w.setup.RegisterIdentity(w.ctx, w.url, didOf(key), awid.ComputeStableID(pub), key); err != nil {
		t.Fatalf("setup identity: %v", err)
	}
	return awid.ComputeStableID(pub), didOf(key)
}

func (w *controllerWriteWorld) ownAddress(t *testing.T) {
	t.Helper()
	w.address = freshName(t, "a-")
	didAW, current := w.identity(t)
	registered, err := w.setup.RegisterAddressAt(w.ctx, w.url, w.domain, w.address, didAW, current, w.namespaceKey)
	if err != nil {
		t.Fatalf("setup address: %v", err)
	}
	w.addressDIDAW, w.addressKey, w.addressID = didAW, current, registered.AddressID
}

var controllerWrites = []struct {
	name     string
	setup    func(*controllerWriteWorld, *testing.T)
	write    func(*controllerWriteWorld, *awid.RegistryClient) error
	mainOnly bool // a shape the released registry does not take
}{
	{name: "register_namespace", setup: func(w *controllerWriteWorld, t *testing.T) {
		w.domain, w.namespaceKey = freshName(t, "cov-")+".test", newKey(t)
	}, write: func(w *controllerWriteWorld, c *awid.RegistryClient) error {
		_, err := c.RegisterNamespaceAt(w.ctx, w.url, w.domain, didOf(w.namespaceKey), w.namespaceKey)
		return err
	}},
	{name: "update_namespace", setup: func(*controllerWriteWorld, *testing.T) {}, write: func(w *controllerWriteWorld, c *awid.RegistryClient) error {
		_, err := c.UpdateNamespaceDeliveryOriginAt(w.ctx, w.url, w.domain, w.namespaceKey, "https://messages.example.com")
		return err
	}},
	{name: "delete_namespace", setup: (*controllerWriteWorld).ownNamespace, write: func(w *controllerWriteWorld, c *awid.RegistryClient) error {
		return c.DeleteNamespaceAt(w.ctx, w.url, w.domain, w.namespaceKey, "retired")
	}},
	{name: "create_team", setup: func(w *controllerWriteWorld, t *testing.T) {
		w.team, w.teamKey = freshName(t, "team-"), newKey(t)
	}, write: func(w *controllerWriteWorld, c *awid.RegistryClient) error {
		_, err := c.CreateTeam(w.ctx, w.url, w.domain, w.team, "Team", didOf(w.teamKey), w.namespaceKey)
		return err
	}},
	{name: "set_team_visibility", setup: func(*controllerWriteWorld, *testing.T) {}, write: func(w *controllerWriteWorld, c *awid.RegistryClient) error {
		_, err := c.SetTeamVisibility(w.ctx, w.url, w.domain, w.team, "public", w.teamKey)
		return err
	}},
	{name: "delete_team", setup: (*controllerWriteWorld).ownTeam, write: func(w *controllerWriteWorld, c *awid.RegistryClient) error {
		return c.DeleteTeam(w.ctx, w.url, w.domain, w.team, w.namespaceKey, "")
	}},
	{name: "rotate_team_key", setup: func(w *controllerWriteWorld, t *testing.T) {
		w.ownTeam(t)
		w.rotatedKey = newKey(t)
	}, write: func(w *controllerWriteWorld, c *awid.RegistryClient) error {
		_, err := c.RotateTeamKeyWithMembers(w.ctx, w.url, w.domain, w.team, didOf(w.rotatedKey), nil, nil, w.namespaceKey)
		return err
	}},
	{name: "rotate_team_key_with_resigned_records", setup: func(w *controllerWriteWorld, t *testing.T) {
		w.ownTeam(t)
		issued := time.Now().Add(-time.Minute)
		teamID := awid.BuildTeamID(w.domain, w.team)
		record := awid.NewTeamServerRecord(teamID, didOf(w.teamKey), "https://coordination.example.com", issued)
		signature, err := awid.SignTeamServerRecord(w.teamKey, record)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.setup.PublishTeamServerRecord(w.ctx, w.url, w.domain, w.team, record, signature); err != nil {
			t.Fatalf("setup team server record: %v", err)
		}
		w.rotatedKey = newKey(t)
		resigned := awid.NewTeamServerRecord(teamID, didOf(w.rotatedKey), "https://coordination.example.com", issued.Add(time.Second))
		resignedSignature, err := awid.SignTeamServerRecord(w.rotatedKey, resigned)
		if err != nil {
			t.Fatal(err)
		}
		w.resigned = &awid.ResignedRecords{TeamServer: &awid.SignedAttestationRecord{Record: resigned, Signature: resignedSignature}}
	}, write: func(w *controllerWriteWorld, c *awid.RegistryClient) error {
		_, err := c.RotateTeamKeyWithMembers(w.ctx, w.url, w.domain, w.team, didOf(w.rotatedKey), w.resigned, nil, w.namespaceKey)
		return err
	}},
	{name: "rotate_team_key_with_member_certificates", mainOnly: true, setup: func(w *controllerWriteWorld, t *testing.T) {
		w.ownTeam(t)
		old := w.newCertificate(t)
		if err := w.setup.RegisterCertificate(w.ctx, w.url, w.domain, w.team, old, w.teamKey); err != nil {
			t.Fatalf("setup certificate: %v", err)
		}
		w.rotatedKey = newKey(t)
		replacement, err := awid.SignTeamCertificate(w.rotatedKey, awid.TeamCertificateFields{
			Team: old.Team, MemberDIDKey: old.MemberDIDKey, Alias: old.Alias, IdentityScope: old.IdentityScope,
		})
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := awid.EncodeTeamCertificateHeader(replacement)
		if err != nil {
			t.Fatal(err)
		}
		w.memberChanges = []awid.MemberCertificateChange{{OldCertificateID: old.CertificateID, Certificate: encoded}}
	}, write: func(w *controllerWriteWorld, c *awid.RegistryClient) error {
		_, err := c.RotateTeamKeyWithMembers(w.ctx, w.url, w.domain, w.team, didOf(w.rotatedKey), nil, w.memberChanges, w.namespaceKey)
		return err
	}},
	{name: "register_global_certificate", setup: func(w *controllerWriteWorld, t *testing.T) {
		w.ownAddress(t)
		cert, err := awid.SignTeamCertificate(w.teamKey, awid.TeamCertificateFields{
			Team: awid.BuildTeamID(w.domain, w.team), MemberDIDKey: w.addressKey, MemberDIDAW: w.addressDIDAW,
			MemberAddress: w.domain + "/" + w.address, Alias: freshName(t, "g-"), IdentityScope: "global",
		})
		if err != nil {
			t.Fatal(err)
		}
		w.certificate = cert
	}, write: func(w *controllerWriteWorld, c *awid.RegistryClient) error {
		return c.RegisterCertificate(w.ctx, w.url, w.domain, w.team, w.certificate, w.teamKey)
	}},
	{name: "register_certificate", setup: func(w *controllerWriteWorld, t *testing.T) {
		w.certificate = w.newCertificate(t)
	}, write: func(w *controllerWriteWorld, c *awid.RegistryClient) error {
		return c.RegisterCertificate(w.ctx, w.url, w.domain, w.team, w.certificate, w.teamKey)
	}},
	{name: "revoke_certificate", setup: func(w *controllerWriteWorld, t *testing.T) {
		w.certificate = w.newCertificate(t)
		if err := w.setup.RegisterCertificate(w.ctx, w.url, w.domain, w.team, w.certificate, w.teamKey); err != nil {
			t.Fatalf("setup certificate: %v", err)
		}
	}, write: func(w *controllerWriteWorld, c *awid.RegistryClient) error {
		return c.RevokeCertificate(w.ctx, w.url, w.domain, w.team, w.certificate.CertificateID, w.teamKey)
	}},
	{name: "register_address", setup: func(w *controllerWriteWorld, t *testing.T) {
		w.address = freshName(t, "a-")
		w.addressDIDAW, w.addressKey = w.identity(t)
	}, write: func(w *controllerWriteWorld, c *awid.RegistryClient) error {
		_, err := c.RegisterAddressAt(w.ctx, w.url, w.domain, w.address, w.addressDIDAW, w.addressKey, w.namespaceKey)
		return err
	}},
	{name: "delete_address", setup: (*controllerWriteWorld).ownAddress, write: func(w *controllerWriteWorld, c *awid.RegistryClient) error {
		return c.DeleteAddressAt(w.ctx, w.url, w.domain, w.address, w.namespaceKey, "")
	}},
	{name: "delete_address_if_matches", setup: (*controllerWriteWorld).ownAddress, write: func(w *controllerWriteWorld, c *awid.RegistryClient) error {
		return c.DeleteAddressIfMatchesAt(w.ctx, w.url, w.domain, w.address, w.addressID, w.addressDIDAW, w.addressKey, w.namespaceKey, "rollback")
	}},
}

func TestControllerWritesCoverTheirBytesAtBothRegistries(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("AWID_SKIP_DNS_VERIFY", "1")
	for _, release := range []struct{ name, env string }{{"main", ""}, {"production", "AWID_FIXTURE_RELEASE=production"}} {
		t.Run(release.name, func(t *testing.T) {
			var url string
			if release.env == "" {
				url, _ = startAWIDFixture(t)
			} else {
				url, _ = startAWIDFixture(t, release.env)
			}
			shared := &controllerWriteWorld{ctx: context.Background(), url: url, setup: trustedClient(t, url, http.DefaultTransport)}
			shared.ownNamespace(t)
			shared.ownTeam(t)
			for _, op := range controllerWrites {
				if op.mainOnly && release.env != "" {
					continue
				}
				for _, changed := range []bool{false, true} {
					label := op.name + "/as_signed"
					if changed {
						label = op.name + "/changed_after_signing"
					}
					t.Run(label, func(t *testing.T) {
						w := *shared
						op.setup(&w, t)
						var transport http.RoundTripper = http.DefaultTransport
						if changed {
							transport = changeBodyAfterSigning{inner: http.DefaultTransport}
						}
						err := op.write(&w, trustedClient(t, url, transport))
						if !changed {
							if err != nil {
								t.Fatalf("write as signed refused: %v", err)
							}
							return
						}
						var refused *awid.RegistryError
						if !errors.As(err, &refused) || refused.StatusCode != http.StatusUnauthorized {
							t.Fatalf("write with its body changed after signing: %v, want 401", err)
						}
					})
				}
			}
		})
	}
}
