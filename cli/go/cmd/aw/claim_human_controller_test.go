package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/awid"
)

func controllerClaimVectorForCarrier(t *testing.T) ([]byte, awid.SignedUnownedTeamClaim) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "docs", "vectors", "team-control-requests-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		Cases []struct {
			Artifact json.RawMessage `json:"artifact"`
		} `json:"claim_cases"`
	}
	if err := json.Unmarshal(raw, &vector); err != nil || len(vector.Cases) == 0 {
		t.Fatalf("read shared claim vector: %v", err)
	}
	artifact, err := awid.ParseUnownedTeamClaim(vector.Cases[0].Artifact)
	if err != nil {
		t.Fatal(err)
	}
	return vector.Cases[0].Artifact, artifact
}

func TestClaimHumanControllerFileUsesSharedIntegrityAndTargetRules(t *testing.T) {
	raw, artifact := controllerClaimVectorForCarrier(t)
	issued, err := time.Parse(time.RFC3339, artifact.Request.Timestamp)
	if err != nil {
		t.Fatal(err)
	}
	for _, sample := range []struct {
		Name     string
		Email    string
		Username string
		Now      time.Time
		Bytes    []byte
		Want     string
	}{
		{Name: "normalized input", Email: " OWNER@EXAMPLE.COM ", Username: " OWNER ", Now: issued, Bytes: raw},
		{Name: "freshness boundary", Email: artifact.Request.Email, Username: artifact.Request.Username, Now: issued.Add(300 * time.Second), Bytes: raw},
		{Name: "another email", Email: "other@example.com", Username: artifact.Request.Username, Now: issued, Bytes: raw, Want: "email"},
		{Name: "another username", Email: artifact.Request.Email, Username: "other-owner", Now: issued, Bytes: raw, Want: "username"},
		{Name: "expired", Email: artifact.Request.Email, Username: artifact.Request.Username, Now: issued.Add(301 * time.Second), Bytes: raw, Want: "timestamp"},
		{Name: "future", Email: artifact.Request.Email, Username: artifact.Request.Username, Now: issued.Add(-301 * time.Second), Bytes: raw, Want: "timestamp"},
		{Name: "tampered target", Email: artifact.Request.Email, Username: artifact.Request.Username, Now: issued, Bytes: bytes.Replace(raw, []byte("owner@example.com"), []byte("other@example.com"), 1), Want: "signature"},
		{Name: "wrong purpose", Email: artifact.Request.Email, Username: artifact.Request.Username, Now: issued, Bytes: bytes.Replace(raw, []byte("claim_unowned_team"), []byte("byoidt_import"), 1), Want: "operation"},
	} {
		t.Run(sample.Name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "controller-claim.json")
			if err := os.WriteFile(path, sample.Bytes, 0o600); err != nil {
				t.Fatal(err)
			}
			claim, err := readClaimHumanControllerFile(claimHumanControllerInput{Path: path, Target: normalizeClaimHumanTarget(claimHumanTarget{Username: sample.Username, Email: sample.Email}), Now: sample.Now})
			if sample.Want != "" {
				if err == nil || !strings.Contains(err.Error(), sample.Want) {
					t.Fatalf("wrong refusal: %v", err)
				}
				return
			}
			if err != nil || claim != artifact {
				t.Fatalf("shared signed artifact changed: %v", err)
			}
		})
	}
}

func TestClaimHumanControllerFilePreservesReadFailures(t *testing.T) {
	for _, directory := range []bool{false, true} {
		path := filepath.Join(t.TempDir(), "claim.json")
		if directory {
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
		}
		_, err := readClaimHumanControllerFile(claimHumanControllerInput{Path: path, Target: claimHumanTarget{Username: "owner", Email: "owner@example.com"}, Now: time.Now()})
		if err == nil || !strings.Contains(err.Error(), path) {
			t.Fatalf("file failure lost its path: %v", err)
		}
	}
}
