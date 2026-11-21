package main

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

// activeMembers reads the team's active certificates at AWID, by alias.
func (f rotateKeyFixture) activeMembers(t *testing.T) map[string]awid.RegistryCertificate {
	t.Helper()
	keys := map[string]awid.RegistryCertificate{}
	teamKey, err := awconfig.LoadTeamKey(f.domain, f.team)
	if err != nil {
		t.Fatal(err)
	}
	certificates, err := f.registry.ListCertificates(context.Background(), f.registryURL, f.domain, f.team, true, teamKey)
	if err != nil {
		t.Fatalf("list certificates: %v", err)
	}
	for _, certificate := range certificates {
		if _, dup := keys[certificate.Alias]; dup {
			t.Fatalf("two active certificates for %s", certificate.Alias)
		}
		keys[certificate.Alias] = certificate
	}
	return keys
}

// requireMembersUnder checks that alice and bob each hold one active
// certificate that replaced the fixture's for the same member key (AWID
// registers it only under the team's key), and that alice's custody and bob's
// person record name it and verify under teamDID.
func (f rotateKeyFixture) requireMembersUnder(t *testing.T, teamDID string) {
	t.Helper()
	ctx := context.Background()
	active := f.activeMembers(t)
	var aliases []string
	for alias := range active {
		aliases = append(aliases, alias)
	}
	sort.Strings(aliases)
	if len(aliases) != 2 || aliases[0] != "alice" || aliases[1] != "bob" {
		t.Fatalf("active members = %v, want alice and bob", aliases)
	}
	for i, alias := range aliases {
		certificate := active[alias]
		if certificate.CertificateID == f.certificates[i].CertificateID || certificate.MemberDIDKey != f.certificates[i].MemberDIDKey {
			t.Fatalf("%s's certificate was not replaced for the same member key: %+v", alias, certificate)
		}
	}
	custody, err := f.registry.GetMemberCustodyRecord(ctx, f.registryURL, f.domain, f.team, active["alice"].CertificateID)
	requireVerifiesUnder(t, custody, err, teamDID)
	if custody.Record["custodian_id"] != "custodian.example" || custody.Record["member_did_key"] != active["alice"].MemberDIDKey {
		t.Fatalf("alice's custody record changed its content: %v", custody.Record)
	}
	person, err := f.registry.GetMemberPersonRecord(ctx, f.registryURL, f.domain, f.team, active["bob"].CertificateID)
	requireVerifiesUnder(t, person, err, teamDID)
	if person.Record["single_person"] != true {
		t.Fatalf("bob's person record changed its content: %v", person.Record)
	}
}

func TestRotateKeyIssuesAndRecordsANewCertificateForEveryMember(t *testing.T) {
	f := newRotateKeyFixture(t, "rotate-members.example")
	f.seedEveryKind(t, time.Now().UTC().Add(-time.Minute))

	out, err := executeTeamRotateKey(context.Background(), f.options())
	if err != nil {
		t.Fatalf("rotate-key: %v", err)
	}

	if out.ReissuedMembers != 2 {
		t.Fatalf("reissued members = %d, want 2", out.ReissuedMembers)
	}
	f.requireMembersUnder(t, out.NewTeamDIDKey)
}

func TestRotateKeyRefusesARegistryThatCannotChangeMembersCertificatesWithTheKey(t *testing.T) {
	f := newRotateKeyFixture(t, "rotate-members-old.example")
	opts := f.options()
	// A registry that predates member_certificates refuses the field.
	opts.HTTPClient = &http.Client{Transport: refuseMemberCertificates{http.DefaultTransport}}

	_, err := executeTeamRotateKey(context.Background(), opts)

	if err == nil || !strings.Contains(err.Error(), "this registry cannot change a team key together with its members' certificates") {
		t.Fatalf("rotate-key = %v, want the registry refusal", err)
	}
	if f.currentTeamDID(t) != f.teamDID {
		t.Fatal("the team key changed")
	}
}

// refuseMemberCertificates answers a rotation that carries member
// certificates as a registry without the field does.
type refuseMemberCertificates struct{ next http.RoundTripper }

func (r refuseMemberCertificates) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method == http.MethodPost && strings.HasSuffix(req.URL.Path, "/rotate") && req.Body != nil {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		if strings.Contains(string(body), `"member_certificates"`) {
			return &http.Response{
				StatusCode: http.StatusUnprocessableEntity,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(strings.NewReader(`{"detail":[{"type":"extra_forbidden","loc":["member_certificates"],"msg":"Extra inputs are not permitted"}]}`)),
				Request:    req,
			}, nil
		}
		req.Body = io.NopCloser(bytes.NewReader(body))
	}
	return r.next.RoundTrip(req)
}
