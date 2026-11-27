package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"testing"

	aweb "github.com/awebai/aw"
	"github.com/awebai/aw/awid"
)

const testGrantID = "6f1c2b9e-1d2a-4c3b-9e8f-0a1b2c3d4e5f"

func TestGrantRevocationPrecondition(t *testing.T) {
	for _, tc := range []struct {
		name    string
		subject releaseSubject
		expect  string
		refused bool
	}{
		{"no expectation", releaseSubject{Alias: "resident"}, "", false},
		{"expected alias", releaseSubject{Alias: "resident"}, "resident", false},
		{"expected alias case", releaseSubject{Alias: "resident"}, " Resident ", false},
		{"another alias", releaseSubject{Alias: "resident"}, "other", true},
		{"alias not provable", releaseSubject{DID: "did:key:z6MkResident"}, "resident", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := grantRevocationPrecondition(tc.subject, tc.expect)
			if (err != nil) != tc.refused {
				t.Fatalf("err=%v, want refused=%t", err, tc.refused)
			}
			if err != nil && errorCodeOf(err) != releaseSubjectMismatch {
				t.Fatalf("code=%q, want %q", errorCodeOf(err), releaseSubjectMismatch)
			}
		})
	}
}

func TestGrantRevocationAttemptClassification(t *testing.T) {
	reply := func(id, status, at string) *aweb.IdentityGrantRevocation {
		return &aweb.IdentityGrantRevocation{GrantID: id, Status: status, RevokedAt: at}
	}
	const at = "2026-11-26T22:00:00+00:00"
	httpErr := func(status int, body string) error { return &awid.APIError{StatusCode: status, Body: body} }
	dial := &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")}
	for _, tc := range []struct {
		name      string
		reply     *aweb.IdentityGrantRevocation
		err       error
		kind      revocationAttemptKind
		revokedAt string
	}{
		{"exact reply", reply(testGrantID, "revoked", at), nil, revocationConfirmed, at},
		{"reply in another case", reply("6F1C2B9E-1D2A-4C3B-9E8F-0A1B2C3D4E5F", "revoked", at), nil, revocationConfirmed, at},
		{"reply for another grant", reply("00000000-0000-4000-8000-000000000001", "revoked", at), nil, revocationAmbiguous, ""},
		{"reply without status", reply(testGrantID, "", at), nil, revocationAmbiguous, ""},
		{"reply without revocation time", reply(testGrantID, "revoked", ""), nil, revocationAmbiguous, ""},
		{"empty reply", nil, nil, revocationAmbiguous, ""},
		{"definitive not found", nil, httpErr(http.StatusNotFound, `{"detail":"grant not found"}`), revocationRefused, ""},
		{"definitive forbidden", nil, httpErr(http.StatusForbidden, `{"detail":"forbidden"}`), revocationRefused, ""},
		{"server failure", nil, httpErr(http.StatusInternalServerError, `{"detail":"boom"}`), revocationAmbiguous, ""},
		{"never connected", nil, fmt.Errorf("post: %w", dial), revocationNotSent, ""},
		{"connection lost", nil, fmt.Errorf("post: %w", io.ErrUnexpectedEOF), revocationAmbiguous, ""},
		{"timed out", nil, &awid.OutcomeUnknownError{}, revocationAmbiguous, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			kind, revokedAt := classifyGrantRevocation(testGrantID, tc.reply, tc.err)
			if kind != tc.kind || revokedAt != tc.revokedAt {
				t.Fatalf("kind=%v revoked_at=%q, want %v %q", kind, revokedAt, tc.kind, tc.revokedAt)
			}
		})
	}
}

func TestGrantRevocationReadBack(t *testing.T) {
	const at = "2026-11-26T22:00:00+00:00"
	const team = "backend:example.com"
	grant := func(id, teamID, revokedAt string) aweb.IdentityGrantView {
		return aweb.IdentityGrantView{GrantID: id, TeamID: teamID, RevokedAt: revokedAt}
	}
	other := "00000000-0000-4000-8000-000000000001"
	for _, tc := range []struct {
		name      string
		grants    []aweb.IdentityGrantView
		err       error
		revokedAt string
		confirmed bool
	}{
		{"recorded revocation", []aweb.IdentityGrantView{grant(other, team, ""), grant(testGrantID, team, at)}, nil, at, true},
		{"still active", []aweb.IdentityGrantView{grant(testGrantID, team, "")}, nil, "", false},
		{"not listed", []aweb.IdentityGrantView{grant(other, team, at)}, nil, "", false},
		{"listed under another team", []aweb.IdentityGrantView{grant(testGrantID, "ops:example.com", at)}, nil, "", false},
		{"read failed", nil, errors.New("unavailable"), "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			revokedAt, confirmed := confirmRevocationByReadBack(testGrantID, team, tc.grants, tc.err)
			if confirmed != tc.confirmed || revokedAt != tc.revokedAt {
				t.Fatalf("confirmed=%t revoked_at=%q, want %t %q", confirmed, revokedAt, tc.confirmed, tc.revokedAt)
			}
		})
	}
}

func TestReleaseVocabularyIsPublished(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "docs", "vectors", "cli-integration-codes-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		Codes   []string `json:"cli_error_codes"`
		Release struct {
			Effects  []string `json:"effects"`
			Outcomes []string `json:"outcomes"`
		} `json:"release"`
	}
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(vector.Codes, releaseSubjectMismatch) {
		t.Fatalf("code %s is not published", releaseSubjectMismatch)
	}
	if !slices.Equal(vector.Release.Effects, []string{string(releaseRevokeGrant)}) {
		t.Fatalf("published effects=%v", vector.Release.Effects)
	}
	if !slices.Equal(vector.Release.Outcomes, []string{string(releaseConfirmed), string(releaseUnknown), string(releaseRefused)}) {
		t.Fatalf("published outcomes=%v", vector.Release.Outcomes)
	}
}
