package awid

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

type teamCertificateVectorFile struct {
	Version        int      `json:"version"`
	Reasons        []string `json:"reasons"`
	RefusalAnswers []struct {
		Reason string `json:"reason"`
		Field  string `json:"field"`
		Detail string `json:"detail"`
	} `json:"refusal_answers"`
	Cases []struct {
		Name                     string   `json:"name"`
		CertificateHeader        string   `json:"certificate_header"`
		RequestDIDKey            string   `json:"request_did_key"`
		TeamDIDKey               string   `json:"team_did_key"`
		RevokedCertificateIDs    []string `json:"revoked_certificate_ids"`
		RegisteredCertificateIDs []string `json:"registered_certificate_ids"`
		Expected                 *struct {
			Reason string `json:"reason"`
			Field  string `json:"field"`
		} `json:"expected"`
	} `json:"cases"`
}

func readTeamCertificateVectors(t *testing.T) teamCertificateVectorFile {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "vectors", "team-certificate-verification-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vectors teamCertificateVectorFile
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	if vectors.Version != 1 || len(vectors.Cases) == 0 {
		t.Fatalf("version=%d cases=%d", vectors.Version, len(vectors.Cases))
	}
	return vectors
}

// Every verifier of a team certificate, in every language, gives each shared
// case the same verdict.
func TestCheckTeamCertificateGivesEachCaseItsExpectedVerdict(t *testing.T) {
	vectors := readTeamCertificateVectors(t)
	if !reflect.DeepEqual(vectors.Reasons, TeamCertificateReasons) {
		t.Fatalf("reasons=%v want %v", TeamCertificateReasons, vectors.Reasons)
	}
	for _, c := range vectors.Cases {
		t.Run(c.Name, func(t *testing.T) {
			certificate, err := CheckTeamCertificate(c.CertificateHeader, TeamCertificateFacts{
				SubjectDIDKey:         c.RequestDIDKey,
				TeamDIDKey:            c.TeamDIDKey,
				RevokedCertificateIDs: c.RevokedCertificateIDs,
				Registered:            RegisteredCertificateIDs(c.RegisteredCertificateIDs),
			})
			if c.Expected == nil {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				if certificate["certificate_id"] != "cert-001" {
					t.Fatalf("certificate_id=%v", certificate["certificate_id"])
				}
				return
			}
			var refused *TeamCertificateError
			if !errors.As(err, &refused) {
				t.Fatalf("err=%v, want a refusal for %s", err, c.Expected.Reason)
			}
			if refused.Reason != c.Expected.Reason || refused.Field != c.Expected.Field {
				t.Fatalf("refused %q field %q, want %q field %q", refused.Reason, refused.Field, c.Expected.Reason, c.Expected.Field)
			}
			// A refusal says its reason and the field's name, and nothing the certificate carries.
			want := c.Expected.Reason
			if c.Expected.Field != "" {
				want += ": " + c.Expected.Field
			}
			if refused.Error() != want {
				t.Fatalf("message %q, want %q", refused.Error(), want)
			}
		})
	}
}

// A caller with no registered set says so, and only registration goes unchecked.
func TestCheckTeamCertificateWithoutARegisteredSet(t *testing.T) {
	vectors := readTeamCertificateVectors(t)
	for _, c := range vectors.Cases {
		_, err := CheckTeamCertificate(c.CertificateHeader, TeamCertificateFacts{
			SubjectDIDKey:         c.RequestDIDKey,
			TeamDIDKey:            c.TeamDIDKey,
			RevokedCertificateIDs: c.RevokedCertificateIDs,
			Registered:            RegistrationNotRequired(),
		})
		accepted := c.Expected == nil || c.Expected.Reason == "unregistered"
		if accepted != (err == nil) {
			t.Fatalf("%s: err=%v", c.Name, err)
		}
	}
}

// A team key that does not decode is the caller's registry answer, not a
// fault of the certificate.
func TestCheckTeamCertificateWithATeamKeyThatDoesNotDecode(t *testing.T) {
	vectors := readTeamCertificateVectors(t)
	valid := vectors.Cases[0]
	_, err := CheckTeamCertificate(valid.CertificateHeader, TeamCertificateFacts{
		SubjectDIDKey: valid.RequestDIDKey, TeamDIDKey: "did:key:not-a-key", Registered: RegistrationNotRequired(),
	})
	var refused *TeamCertificateError
	if !errors.As(err, &refused) || refused.Reason != "invalid_team_key" {
		t.Fatalf("err=%v", err)
	}
}

// A caller that states nothing about registration is a mistake in the
// caller, never an acceptance.
func TestCheckTeamCertificateRequiresRegistrationToBeStated(t *testing.T) {
	vectors := readTeamCertificateVectors(t)
	valid := vectors.Cases[0]
	certificate, err := CheckTeamCertificate(valid.CertificateHeader, TeamCertificateFacts{
		SubjectDIDKey: valid.RequestDIDKey, TeamDIDKey: valid.TeamDIDKey,
	})
	var refused *TeamCertificateError
	if err == nil || certificate != nil || errors.As(err, &refused) {
		t.Fatalf("certificate=%v err=%v", certificate, err)
	}
}

// Every catalog reason has one shared, input-free refusal text, including the
// protected registry binding reason that primitive facts alone cannot produce.
func TestTeamCertificateRefusalTextUsesSharedVectors(t *testing.T) {
	vectors := readTeamCertificateVectors(t)
	var reasons []string
	for _, c := range vectors.RefusalAnswers {
		reasons = append(reasons, c.Reason)
		refused := &TeamCertificateError{Reason: c.Reason, Field: c.Field}
		if refused.Error() != c.Detail {
			t.Fatalf("reason %s: text=%q want %q", c.Reason, refused.Error(), c.Detail)
		}
	}
	if !reflect.DeepEqual(reasons, TeamCertificateReasons) {
		t.Fatalf("refusal reasons=%v want %v", reasons, TeamCertificateReasons)
	}
}
