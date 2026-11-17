package main

import (
	"bytes"
	"encoding/json"
	"github.com/awebai/aw/awconfig"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestEnrollmentKeyReviewRequiresIndependentCountAndConsent(t *testing.T) {
	material := map[string]any{"registrations": []any{
		map[string]any{"registration": map[string]any{"id": "person-key"}},
		map[string]any{"registration": map[string]any{"id": "unexpected-key"}},
	}}
	for _, tc := range []struct {
		count  int
		yes    bool
		reason string
	}{{1, true, "registration_count_mismatch"}, {2, false, "not approved"}, {2, true, ""}} {
		var out bytes.Buffer
		asked := false
		err := reviewEnrollmentKeys(material, tc.count, &out, func(string) (bool, error) { asked = true; return tc.yes, nil })
		if tc.reason == "" {
			if err != nil {
				t.Fatal(err)
			}
		} else if err == nil || !strings.Contains(err.Error(), tc.reason) {
			t.Fatalf("count %d: %v", tc.count, err)
		}
		if tc.count == 2 && (!asked || !strings.Contains(out.String(), "person-key") || !strings.Contains(out.String(), "unexpected-key")) {
			t.Fatalf("keys not reviewed: %s", out.String())
		}
	}
}

func TestExpiredHumanAttemptRestartPreservesOriginal(t *testing.T) {
	for _, tc := range []struct {
		name           string
		deadline       int64
		restart, final bool
		want           string
	}{
		{"expired requires explicit restart", 99, false, false, "--restart"},
		{"live cannot be replaced", 101, true, false, "not expired"},
		{"checked enrollment proof must activate", 99, true, true, "activation"},
		{"expired restart", 100, true, false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "attempt.json")
			raw := []byte(`{"saved":"original proof and bytes"}`)
			if err := os.WriteFile(p, raw, 0600); err != nil {
				t.Fatal(err)
			}
			archived, err := restartHumanAttempt(p, map[string]any{"deadline": json.Number(strings.TrimSpace(strconv.FormatInt(tc.deadline, 10)))}, 100, tc.restart, tc.final)
			if tc.want != "" {
				if err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Fatal(err)
				}
				got, _ := os.ReadFile(p)
				if !bytes.Equal(got, raw) {
					t.Fatal("refusal changed saved attempt")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(archived)
			if err != nil || !bytes.Equal(got, raw) {
				t.Fatal("restart lost original")
			}
			if _, err := os.Stat(p); !os.IsNotExist(err) {
				t.Fatal("fresh attempt still conflicts")
			}
			info, _ := os.Stat(archived)
			if info.Mode().Perm() != 0600 {
				t.Fatal("archive exposed")
			}
		})
	}
}

func TestOneEnrollmentKeyAdvice(t *testing.T) {
	one := enrollmentKeyAdvice(1)
	for _, part := range []string{"not implemented", "second key", "new ID", "revok"} {
		if !strings.Contains(one, part) {
			t.Fatal(one)
		}
	}
	if enrollmentKeyAdvice(2) != "" {
		t.Fatal("multi-key warning")
	}
}

func TestHumanParentCommandUsesOneUnlock(t *testing.T) {
	h, _, _ := commandUnlockFixture(t, humanPassphrase)
	p := &humanParent{record: h.record, dir: h.dir, chain: &awconfig.InstalledIDChain{Bundle: map[string]any{"certificates": []any{}}}}
	count := 0
	issuer := p.issuer(humanBackupFile{h.record.StableID, filepath.Join(os.Getenv("HOME"), "backup.pbes2")}, func(string) ([]byte, error) { count++; return []byte(humanPassphrase), nil }, nil, nil, "")
	for _, description := range []string{"first certificate", "second certificate"} {
		if _, _, err := issuer.signer(description)([]byte(description)); err != nil {
			t.Fatal(err)
		}
	}
	if count != 1 {
		t.Fatalf("human parent unlocked %d times in one command", count)
	}
}
