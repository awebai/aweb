package aweb

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestRetiredIdentityVocabularyIsConfinedToCompatibilityBoundaries(t *testing.T) {
	t.Parallel()

	allowed := map[string]map[string]int{
		"awconfig/workspace.go": {
			`"lifetime":        {},`: 1,
		},
		"awconfig/team_invites.go": {
			"LegacyEphemeral *bool `json:\"ephemeral\"`": 1,
			`if wire.LegacyEphemeral != nil {`:           1,
			`if *wire.LegacyEphemeral {`:                 1,
			`return fmt.Errorf("identity_scope %q conflicts with deprecated ephemeral value", scope)`: 1,
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
			`case "ephemeral":`:  1,
			`case "persistent":`: 1,
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
		"awid/e2ee_messages.go": {
			`return nil, nil, fmt.Errorf("generate hpke ephemeral key: %w", err)`:                                                 1,
			`ephemeralPub, err := ecdh.X25519().NewPublicKey(enc)`:                                                                1,
			`sharedSecret, err := hpkeDHKEMExtractAndExpand(recipientPriv, ephemeralPub, enc, recipientPriv.PublicKey().Bytes())`: 1,
		},
		"cmd/aw/a2a.go": {
			`a2aPublishCmd.Flags().IntVar(&a2aPublishExpiresDays, "expires-days", 30, "Publication/delegation lifetime in days")`: 1,
		},
		"cmd/aw/connect.go": {
			`if strings.Contains(body, "did_aw") || strings.Contains(body, "address") || strings.Contains(body, "persistent") {`: 1,
		},
		"cmd/aw/id_team.go": {
			`teamInviteCmd.Flags().BoolVar(&teamInviteDeprecatedLocalScope, "ephemeral", false, "Deprecated alias for --member-local")`:    1,
			`teamInviteCmd.Flags().BoolVar(&teamInviteDeprecatedGlobalScope, "persistent", false, "Deprecated alias for --member-global")`: 1,
			`markDeprecatedHiddenFlag(teamInviteCmd, "ephemeral", "member-local")`:                                                         1,
			`markDeprecatedHiddenFlag(teamInviteCmd, "persistent", "member-global")`:                                                       1,
			`teamAddMemberCmd.Flags().StringVar(&teamAddMemberDeprecatedScopeValue, "lifetime", "", "Deprecated identity scope selector")`: 1,
			`markDeprecatedHiddenFlag(teamAddMemberCmd, "lifetime", "global or --local")`:                                                  1,
			`if cmd.Flags().Changed("lifetime") {`:                                                   1,
			`legacyScope := awid.IdentityScopeFromLegacyLifetime(teamAddMemberDeprecatedScopeValue)`: 1,
			`return "", usageError("--lifetime must be ephemeral or persistent")`:                    1,
			`return "", usageError("--lifetime conflicts with --global or --local")`:                 1,
		},
		"cmd/aw/init.go": {
			`PersistentPreRun: func(cmd *cobra.Command, args []string) {`:                                1,
			`initCmd.Flags().BoolVar(&initGlobal, "persistent", false, "Deprecated alias for --global")`: 1,
			`markDeprecatedHiddenFlag(initCmd, "persistent", "global")`:                                  1,
		},
		"cmd/aw/root.go": {
			`PersistentPreRunE: func(cmd *cobra.Command, args []string) error {`:                                                                       1,
			`PersistentPreRun: func(cmd *cobra.Command, args []string) {`:                                                                              1,
			`// Cobra normally runs only the nearest persistent hook. Traversal makes the`:                                                             1,
			`rootCmd.PersistentFlags().StringVar(&serverFlag, "server-name", "", "Override the server host or name for this command")`:                 1,
			`rootCmd.PersistentFlags().StringVar(&identityHomeFlag, "identity-home", "", "Use identity authority from this absolute credential root")`: 1,
			`rootCmd.PersistentFlags().BoolVar(&debugFlag, "debug", false, "Log background errors to stderr")`:                                         1,
			`rootCmd.PersistentFlags().BoolVar(&traceFlag, "trace", false, "Trace redacted HTTP requests and responses to stderr")`:                    1,
			`rootCmd.PersistentFlags().BoolVar(&jsonFlag, "json", false, "Output as JSON")`:                                                            1,
			`cmd.PersistentFlags().StringVar(&teamFlag, "team", "", "Override the selected team_id for this command")`:                                 1,
		},
		"cmd/aw/doctor.go": {
			`cmd.PersistentFlags().BoolVar(&doctorVerbose, "verbose", false, "Include verbose diagnostic details")`: 1,
			`cmd.PersistentFlags().BoolVar(&doctorOffline, "offline", false, "Run without network checks")`:         1,
			`cmd.PersistentFlags().BoolVar(&doctorOnline, "online", false, "Allow online checks")`:                  1,
		},
		"cmd/aw/upgrade.go": {
			`PersistentPreRun: func(cmd *cobra.Command, args []string) {`: 1,
		},
		"run/eventbus.go": {
			`// EventBus maintains a persistent SSE connection and delivers events`:   1,
			`// Start opens the persistent SSE connection in a background goroutine.`: 1,
		},
		"run/wake.go": {
			`// repeatedly with backoff to maintain a persistent stream.`: 1,
		},
		"run/loop.go": {
			`l.println("done: initial prompt consumed; use a persistent base prompt.")`: 1,
		},
	}
	reasons := map[string]string{
		"awconfig/workspace.go":    "rejects removed pre-v2 workspace identity fields",
		"awconfig/team_invites.go": "decodes prior pending-invite files and rejects scope conflicts",
		"awconfig/identity.go":     "decodes pre-v2 identity.yaml and normalizes immediately",
		"awid/identity_model.go":   "normalizes the two legacy wire spellings at compatibility decoders",
		"awid/certificate.go":      "preserves and verifies historically signed certificate bytes",
		"awid/e2ee_messages.go":    "uses ephemeral for HPKE cryptographic keys",
		"cmd/aw/a2a.go":            "uses lifetime for an independent publication expiration duration",
		"cmd/aw/connect.go":        "recognizes a deprecated server error spelling",
		"cmd/aw/id_team.go":        "accepts and immediately normalizes hidden deprecated flags",
		"cmd/aw/init.go":           "keeps a hidden deprecated flag; PersistentPreRun is Cobra terminology",
		"cmd/aw/root.go":           "uses Cobra persistent hooks and flags",
		"cmd/aw/doctor.go":         "uses Cobra persistent flags",
		"cmd/aw/upgrade.go":        "uses a Cobra persistent hook",
		"run/eventbus.go":          "describes a durable network connection",
		"run/wake.go":              "describes a durable network stream",
		"run/loop.go":              "describes a retained prompt",
	}

	unexpected, err := scanRetiredIdentityVocabulary(".", allowed)
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
		t.Fatalf("retired identity vocabulary escaped or changed its reviewed compatibility boundary:\n%s", strings.Join(unexpected, "\n"))
	}
}

const maxRetiredIdentityVocabularyLineBytes = 4 << 20

func scanRetiredIdentityVocabulary(root string, allowed map[string]map[string]int) ([]string, error) {
	var unexpected []string
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if entry.Name() == ".cache" || entry.Name() == "vendor" || entry.Name() == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".go" || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		scanner.Buffer(make([]byte, bufio.MaxScanTokenSize), maxRetiredIdentityVocabularyLineBytes)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if !hasRetiredIdentityVocabulary(line) {
				continue
			}
			if remaining := allowed[rel][line]; remaining > 0 {
				allowed[rel][line] = remaining - 1
				continue
			}
			unexpected = append(unexpected, rel+":"+line)
		}
		if err := scanner.Err(); err != nil {
			return fmt.Errorf("scan %s: %w", rel, err)
		}
		return nil
	})
	return unexpected, err
}

func hasRetiredIdentityVocabulary(line string) bool {
	lower := strings.ToLower(line)
	return strings.Contains(lower, "lifetime") || strings.Contains(lower, "persistent") || strings.Contains(lower, "ephemeral")
}

func TestRetiredIdentityVocabularyDetectorIncludesScopeMirrors(t *testing.T) {
	t.Parallel()

	for _, line := range []string{"var PersistentScopeMirror string", "ephemeral := identityScope == local", "json:\"lifetime\""} {
		if !hasRetiredIdentityVocabulary(line) {
			t.Fatalf("detector missed %q", line)
		}
	}
}

func TestRetiredIdentityVocabularyScanSkipsOnlyRepositoryCacheState(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeResidueScanFixture(t, root, ".cache/go-mod/cache.go", strings.Repeat("x", 2<<20)+" PersistentScopeMirror")
	writeResidueScanFixture(t, root, ".cache-source/tracked.go", "var PersistentScopeMirror string")

	unexpected, err := scanRetiredIdentityVocabulary(root, map[string]map[string]int{})
	if err != nil {
		t.Fatal(err)
	}
	if len(unexpected) != 1 || unexpected[0] != ".cache-source/tracked.go:var PersistentScopeMirror string" {
		t.Fatalf("unexpected residue findings: %q", unexpected)
	}
}

func TestRetiredIdentityVocabularyScanExaminesLongTrackedSourceLine(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeResidueScanFixture(t, root, "awid/long.go", strings.Repeat("x", 256<<10)+" PersistentScopeMirror")

	unexpected, err := scanRetiredIdentityVocabulary(root, map[string]map[string]int{})
	if err != nil {
		t.Fatal(err)
	}
	if len(unexpected) != 1 || !strings.HasPrefix(unexpected[0], "awid/long.go:") || !strings.Contains(unexpected[0], "PersistentScopeMirror") {
		t.Fatalf("long tracked residue was not classified: findings=%d", len(unexpected))
	}
}

func writeResidueScanFixture(t *testing.T, root, relativePath, content string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(relativePath))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}
