package main

import (
	"context"
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/awebai/aw/awid"
)

func TestLocalMemberBootstrapRejectsMalformedKeysBeforeRegistryEffect(t *testing.T) {
	for _, which := range []string{"controller", "member"} {
		t.Run(which, func(t *testing.T) {
			t.Setenv("HOME", t.TempDir())
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				http.Error(w, "must validate before registry", 500)
			}))
			defer server.Close()
			t.Setenv("AWID_REGISTRY_URL", server.URL)
			registry, err := newConfiguredRegistryClient(nil)
			if err != nil {
				t.Fatal(err)
			}
			_, controller, err := awid.GenerateKeypair()
			if err != nil {
				t.Fatal(err)
			}
			_, member, err := awid.GenerateKeypair()
			if err != nil {
				t.Fatal(err)
			}
			if which == "controller" {
				controller = ed25519.PrivateKey{1}
			} else {
				member = ed25519.PrivateKey{1}
			}
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Fatalf("malformed %s key panicked: %v", which, recovered)
				}
			}()
			_, err = bootstrapLocalTeamMember(context.Background(), localTeamMemberBootstrap{Registry: registry, RegistryURL: server.URL, Domain: "example.test", TeamName: "default", ControllerKey: controller, MemberKey: member, Alias: "child", Scope: awid.IdentityScopeLocal})
			if err == nil || !strings.Contains(err.Error(), which+" signing key is malformed") || calls != 0 {
				t.Fatalf("error=%v registry calls=%d", err, calls)
			}
		})
	}
}
