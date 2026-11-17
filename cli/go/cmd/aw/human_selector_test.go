package main

import (
	"context"
	"errors"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
)

func TestIDHumanSelectorsHaveNoLocalShadows(t *testing.T) {
	for _, cmd := range []*cobra.Command{idParentRequestCmd, idParentImportCmd, idParentInstallCmd, idParentRefreshCmd, idChildInviteCmd, idChildReceiveCmd, idChildPendingCmd, idChildShowCmd, idChildApproveCmd, idChildRefuseCmd, idRevokeCmd} {
		if cmd.LocalNonPersistentFlags().Lookup("human") != nil || cmd.LocalNonPersistentFlags().Lookup("domain") != nil {
			t.Errorf("%s still shadows the shared selector", cmd.CommandPath())
		}
		err := cmd.FlagErrorFunc()(cmd, errors.New("unknown flag: --domain"))
		if err == nil || !strings.Contains(err.Error(), "--human-domain") {
			t.Errorf("%s old spelling lacks migration help: %v", cmd.CommandPath(), err)
		}
	}
}

func TestIDHumanOptionsUseTheSharedSelection(t *testing.T) {
	oldHuman, oldDomain := humanFlag, humanDomainFlag
	humanFlag, humanDomainFlag = "did:aw:explicit", "example.com"
	t.Cleanup(func() { humanFlag, humanDomainFlag = oldHuman, oldDomain })
	parent := idParentOptionsFromFlags()
	child := idChildOptionsFromFlags()
	if parent.Human != humanFlag || parent.Domain != humanDomainFlag || child.Issuer.Human != humanFlag || child.Issuer.Domain != humanDomainFlag {
		t.Fatal("commands selected a separate human/domain")
	}
}

func TestHumanSelectorCLIRefusesOldSpellingAndDifferentPerson(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	bin := filepath.Join(t.TempDir(), "aw")
	buildAwBinary(t, ctx, bin)
	for _, tc := range []struct {
		args   []string
		reason string
	}{
		{[]string{"id", "parent", "request", "--domain", "example.com"}, "use --human-domain"},
		{[]string{"id", "child", "invite", "--domain", "example.com"}, "use --human-domain"},
		{[]string{"id", "revoke", "did:aw:target", "--domain", "example.com"}, "use --human-domain"},
		{[]string{"id", "create", "--name", "child", "--domain", "example.com", "--human-parent", "did:aw:other", "--human", "did:aw:selected", "--human-domain", "example.com"}, "same person"},
		{[]string{"id", "create", "--name", "child", "--domain", "other.example", "--human-parent", "did:aw:selected", "--human", "did:aw:selected", "--human-domain", "example.com"}, "cannot cross domains"},
		{[]string{"id", "create", "--name", "child", "--domain", "example.com", "--human-parent", "did:aw:selected"}, "--human ID --human-domain DOMAIN"},
		{[]string{"id", "child", "invite", "--as-root", "--human-domain", "example.com", "--kind", "agent", "--recipient", "one child"}, "load namespace controller key"},
	} {
		t.Run(strings.Join(tc.args, " "), func(t *testing.T) {
			home := t.TempDir()
			before := homeContents(t, home)
			cmd := exec.CommandContext(ctx, bin, tc.args...)
			cmd.Env = testCommandEnv(home)
			cmd.Dir = home
			out, err := cmd.CombinedOutput()
			if err == nil || !strings.Contains(string(out), tc.reason) {
				t.Fatalf("expected %q: %v\n%s", tc.reason, err, out)
			}
			after := homeContents(t, home)
			if len(before) != len(after) {
				t.Fatal("selection refusal created identity state")
			}
		})
	}
}
