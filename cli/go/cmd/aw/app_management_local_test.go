package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

func TestPluginManagementLocalHomeBoundaries(t *testing.T) {
	resetGrantCommandGlobals(t)
	for _, tc := range []struct {
		name                                  string
		key, membership, emptyIdentity, grant bool
		refusal                               string
	}{
		{name: "shell"},
		{name: "key_without_membership", key: true},
		{name: "membership_without_key", membership: true},
		{name: "empty_identity_is_not_local_bootstrap", key: true, membership: true, emptyIdentity: true, refusal: "app_resident_required"},
		{name: "grant_cannot_use_resident_files", key: true, membership: true, grant: true, refusal: "app_management_denied"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			t.Chdir(root)
			setGrantTestEnv(t, root)
			home := filepath.Join(root, ".aw")
			if err := os.MkdirAll(home, 0700); err != nil {
				t.Fatal(err)
			}
			if tc.key {
				_, key, err := awid.GenerateKeypair()
				if err != nil {
					t.Fatal(err)
				}
				if err := awid.SaveSigningKey(filepath.Join(home, "signing.key"), key); err != nil {
					t.Fatal(err)
				}
			}
			if tc.membership {
				if err := awconfig.SaveTeamStateToIdentityHome(home, &awconfig.TeamState{ActiveTeam: "test:example.test", Memberships: []awconfig.TeamMembership{{TeamID: "test:example.test", CertPath: "team-certs/test.pem"}}}); err != nil {
					t.Fatal(err)
				}
			}
			if tc.emptyIdentity {
				if err := os.WriteFile(filepath.Join(home, "identity.yaml"), []byte("did: ''\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if tc.grant {
				if err := os.WriteFile(awconfig.GrantHomeStatePath(home), []byte("{}"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			_, resident, err := pluginManagementHome()
			if tc.refusal != "" {
				if err == nil || !strings.Contains(err.Error(), tc.refusal) {
					t.Fatalf("want %s, got resident=%v err=%v", tc.refusal, resident, err)
				}
			} else if err != nil || resident {
				t.Fatalf("shell should remain discovery-only: resident=%v err=%v", resident, err)
			}
		})
	}
}
