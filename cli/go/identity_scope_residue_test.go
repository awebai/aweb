package aweb

import (
	"bufio"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestIdentityLifetimeResidueIsConfinedToCompatibilityBoundaries(t *testing.T) {
	t.Parallel()

	allowed := map[string]map[string]int{
		"awconfig/workspace.go": {
			`"lifetime":        {},`: 1,
		},
		"awconfig/identity.go": {
			`// worktreeIdentityWire is the pre-v2 identity.yaml decode boundary. Lifetime`:               1,
			"Lifetime       string `yaml:\"lifetime,omitempty\"`":                                         1,
			`if err := normalizeWorktreeIdentityScope(&state, wire.Lifetime); err != nil {`:               1,
			`func normalizeWorktreeIdentityScope(state *WorktreeIdentity, legacyLifetime string) error {`: 1,
			`rawLifetime := strings.TrimSpace(legacyLifetime)`:                                            1,
			`if rawScope == "" && rawLifetime == "" {`:                                                    1,
			`if rawLifetime != "" {`: 1,
			`compatScope := awid.IdentityScopeFromLegacyLifetime(rawLifetime)`:                                    1,
			`return fmt.Errorf("deprecated lifetime must be %q or %q", "ephemeral", "persistent")`:                1,
			`return fmt.Errorf("identity_scope %q conflicts with deprecated lifetime %q", rawScope, rawLifetime)`: 1,
		},
		"awid/identity_model.go": {
			`// IdentityScopeFromLegacyLifetime is the explicit compatibility adapter for`: 1,
			`func IdentityScopeFromLegacyLifetime(lifetime string) string {`:               1,
			`switch strings.TrimSpace(strings.ToLower(lifetime)) {`:                        1,
		},
		"awid/certificate.go": {
			`legacyLifetime string`:                    1,
			`cert.legacyLifetime,`:                     1,
			`if c.scopeWireKey == "lifetime" {`:        1,
			"Lifetime      string `json:\"lifetime\"`": 2,
			`Lifetime:      c.legacyLifetime,`:         1,
			`if strings.TrimSpace(w.IdentityScope) == "" && strings.TrimSpace(w.Lifetime) != "" {`: 1,
			`identityScope = IdentityScopeFromLegacyLifetime(w.Lifetime)`:                          1,
			`scopeWireKey = "lifetime"`:                      1,
			`legacyLifetime: strings.TrimSpace(w.Lifetime),`: 1,
			`func canonicalCertificatePayload(certID, team, teamDIDKey, memberDIDKey, memberDIDAW, memberAddress, alias, scopeOrLifetime, issuedAt string, legacyLifetime bool) string {`: 1,
			`if legacyLifetime {`:                      1,
			`scopeKey = "lifetime"`:                    1,
			`{scopeKey, jsonString(scopeOrLifetime)},`: 1,
		},
		"cmd/aw/a2a.go": {
			`a2aPublishCmd.Flags().IntVar(&a2aPublishExpiresDays, "expires-days", 30, "Publication/delegation lifetime in days")`: 1,
		},
	}
	reasons := map[string]string{
		"awconfig/workspace.go":  "rejects removed pre-v2 workspace identity fields",
		"awconfig/identity.go":   "decodes pre-v2 identity.yaml and normalizes immediately",
		"awid/identity_model.go": "normalizes the two legacy wire spellings at compatibility decoders",
		"awid/certificate.go":    "preserves and verifies historically signed certificate bytes",
		"cmd/aw/a2a.go":          "uses lifetime for an independent publication expiration duration",
	}

	var unexpected []string
	err := filepath.WalkDir(".", func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if entry.Name() == "vendor" || entry.Name() == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".go" || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel := filepath.ToSlash(strings.TrimPrefix(path, "./"))
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for lineNumber := 1; scanner.Scan(); lineNumber++ {
			line := strings.TrimSpace(scanner.Text())
			if !strings.Contains(strings.ToLower(line), "lifetime") {
				continue
			}
			if remaining := allowed[rel][line]; remaining > 0 {
				allowed[rel][line] = remaining - 1
				continue
			}
			unexpected = append(unexpected, rel+":"+line)
		}
		return scanner.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	for path, lines := range allowed {
		for line, remaining := range lines {
			if remaining != 0 {
				unexpected = append(unexpected, path+": missing allowlisted residue "+line+" (reason: "+reasons[path]+")")
			}
		}
	}
	if len(unexpected) > 0 {
		sort.Strings(unexpected)
		t.Fatalf("identity lifetime residue escaped or changed its reviewed compatibility boundary:\n%s", strings.Join(unexpected, "\n"))
	}
}
