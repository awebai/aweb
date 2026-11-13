package awid

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// signTeamCertificateAsGivenForTest signs cert's fields exactly as given,
// including values SignTeamCertificate itself refuses to issue, so a test can
// present a well-signed certificate that the strict check must still refuse.
func signTeamCertificateAsGivenForTest(t *testing.T, teamKey ed25519.PrivateKey, cert TeamCertificate) *TeamCertificate {
	t.Helper()
	cert.TeamDIDKey = ComputeDIDKey(teamKey.Public().(ed25519.PublicKey))
	payload := canonicalCertificatePayload(cert.CertificateID, cert.Team, cert.TeamDIDKey, cert.MemberDIDKey, cert.MemberDIDAW, cert.MemberAddress, cert.Alias, cert.IdentityScope, cert.IssuedAt, false)
	cert.Signature = base64.RawStdEncoding.EncodeToString(ed25519.Sign(teamKey, []byte(payload)))
	return &cert
}

func TestFetchTeamCertificateRefusesAWellSignedCertificateWithoutAnAlias(t *testing.T) {
	t.Parallel()

	_, teamKey, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	memberPub, memberKey, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	cert := signTeamCertificateAsGivenForTest(t, teamKey, TeamCertificate{
		Version:       1,
		CertificateID: "cert-1",
		Team:          "backend:acme.com",
		MemberDIDKey:  ComputeDIDKey(memberPub),
		Alias:         "",
		IdentityScope: IdentityModeGlobal,
		IssuedAt:      "2026-11-12T00:00:00Z",
	})
	encoded, err := EncodeTeamCertificateHeader(cert)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"certificate_id": cert.CertificateID,
			"team_id":        cert.Team,
			"certificate":    encoded,
		})
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = NewAWIDRegistryClient(nil, nil).FetchTeamCertificate(ctx, server.URL, "acme.com", "backend", cert.CertificateID, memberKey)
	if err == nil {
		t.Fatal("fetched a certificate without an alias")
	}
}
