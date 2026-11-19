package main

import (
	"context"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
)

func TestIDHumanSelectorsHaveNoLocalShadows(t *testing.T) {
	for _, cmd := range []*cobra.Command{idParentRequestCmd, idParentImportCmd, idParentInstallCmd, idParentRefreshCmd, idChildInviteCmd, idChildReceiveCmd, idChildPendingCmd, idChildShowCmd, idChildApproveCmd, idChildRefuseCmd, idRevokeCmd} {
		if cmd.LocalNonPersistentFlags().Lookup("human") != nil {
			t.Errorf("%s shadows the global person selector", cmd.CommandPath())
		}
		if cmd.LocalNonPersistentFlags().Lookup("domain") == nil {
			t.Errorf("%s lost its organization input", cmd.CommandPath())
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

func TestHumanSelectorCLIKeepsActorAndOrganizationSeparate(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	bin := filepath.Join(t.TempDir(), "aw")
	buildAwBinary(t, ctx, bin)
	for _, tc := range []struct {
		args   []string
		reason string
	}{
		{[]string{"id", "parent", "request", "--domain", "other.example", "--human", "did:aw:selected", "--human-domain", "example.com"}, "--domain and --human-domain name different domains"},
		{[]string{"id", "child", "invite", "--domain", "other.example", "--human", "did:aw:selected", "--human-domain", "example.com"}, "--domain and --human-domain name different domains"},
		{[]string{"id", "revoke", "did:aw:target", "--domain", "other.example", "--human", "did:aw:selected", "--human-domain", "example.com"}, "--domain and --human-domain name different domains"},
		{[]string{"id", "create", "--name", "child", "--domain", "example.com", "--human-parent", "did:aw:other", "--human", "did:aw:selected", "--human-domain", "example.com"}, "same person"},
		{[]string{"id", "create", "--name", "child", "--domain", "other.example", "--human-parent", "did:aw:selected", "--human", "did:aw:selected", "--human-domain", "example.com"}, "cannot cross domains"},
		{[]string{"id", "child", "invite", "--as-root", "--domain", "example.com", "--kind", "agent", "--recipient", "one child"}, "load namespace controller key"},
		{[]string{"id", "parent", "request", "--human-domain", "example.com"}, "--human-domain requires --human"},
		{[]string{"id", "child", "invite", "--as-root", "--human-domain", "example.com"}, "--human-domain requires --human"},
		{[]string{"id", "revoke", "did:aw:target", "--human-domain", "example.com"}, "--human-domain requires --human"},
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

// The released per-command form --human ID --domain DOMAIN keeps working
// beside the global selector: --domain names the person's domain, and it
// reaches the same point as --human ID --human-domain DOMAIN.
func TestReleasedHumanDomainFormStillSelectsThePerson(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	bin := filepath.Join(t.TempDir(), "aw")
	buildAwBinary(t, ctx, bin)
	type invocation struct{ prefix, form []string }
	var invocations []invocation
	for _, prefix := range [][]string{
		{"id", "parent", "request"},
		{"id", "child", "invite"},
		{"id", "child", "pending"},
		{"id", "revoke", "did:aw:target"},
	} {
		for _, form := range [][]string{
			{"--human", "did:aw:selected", "--domain", "example.com"},
			{"--human", "did:aw:selected", "--human-domain", "example.com"},
			{"--human", "did:aw:selected", "--domain", "example.com", "--human-domain", "example.com"},
		} {
			invocations = append(invocations, invocation{prefix, form})
		}
	}
	// aw 1.36.58's id create took the signing person from --human-parent and
	// the domain from --domain; the global selector may still name them.
	for _, form := range [][]string{
		{"--human-parent", "did:aw:selected"},
		{"--human-parent", "did:aw:selected", "--human", "did:aw:selected", "--human-domain", "example.com"},
	} {
		invocations = append(invocations, invocation{[]string{"id", "create", "--name", "child", "--domain", "example.com"}, form})
	}
	for _, inv := range invocations {
		prefix, form := inv.prefix, inv.form
		{
			args := append(append([]string{}, prefix...), form...)
			t.Run(strings.Join(args, " "), func(t *testing.T) {
				home := t.TempDir()
				cmd := exec.CommandContext(ctx, bin, args...)
				cmd.Env = testCommandEnv(home)
				cmd.Dir = home
				out, err := cmd.CombinedOutput()
				if err == nil || !strings.Contains(string(out), "needs a human at") {
					t.Fatalf("the person was not selected (want the terminal requirement next): %v\n%s", err, out)
				}
			})
		}
	}
}

func TestReleasedHumanDomainFormSetsThePersonsDomain(t *testing.T) {
	oldH, oldHD, oldPD, oldCD := humanFlag, humanDomainFlag, idParentDomain, idChildDomain
	t.Cleanup(func() { humanFlag, humanDomainFlag, idParentDomain, idChildDomain = oldH, oldHD, oldPD, oldCD })
	for _, cmd := range []*cobra.Command{idParentRequestCmd, idChildInviteCmd, idRevokeCmd} {
		humanFlag, humanDomainFlag = "did:aw:selected", ""
		if err := cmd.Flags().Set("domain", "example.com"); err != nil {
			t.Fatal(err)
		}
		if _, err := prepareIDHumanSelection(cmd); err != nil && !strings.Contains(err.Error(), "needs a human at") {
			t.Fatalf("%s: %v", cmd.CommandPath(), err)
		}
		if humanDomainFlag != "example.com" {
			t.Fatalf("%s: person domain %q, want example.com from --domain", cmd.CommandPath(), humanDomainFlag)
		}
		if got := idParentOptionsFromFlags(); got.Domain != "example.com" || got.Human != "did:aw:selected" {
			t.Fatalf("parent options %+v", got)
		}
		if got := idChildOptionsFromFlags(); got.Issuer.Domain != "example.com" || got.Issuer.Human != "did:aw:selected" {
			t.Fatalf("child options %+v", got.Issuer)
		}
		cmd.Flags().Lookup("domain").Changed = false
		_ = cmd.Flags().Set("domain", "")
		cmd.Flags().Lookup("domain").Changed = false
	}
}

func TestIDAgentOptionsKeepTheirOrganizationInput(t *testing.T) {
	oldH, oldHD, oldPD, oldCD := humanFlag, humanDomainFlag, idParentDomain, idChildDomain
	humanFlag, humanDomainFlag = "", ""
	idParentDomain, idChildDomain = "parent.example", "child.example"
	t.Cleanup(func() { humanFlag, humanDomainFlag, idParentDomain, idChildDomain = oldH, oldHD, oldPD, oldCD })
	if got := idParentOptionsFromFlags(); got.Human != "" || got.Domain != "parent.example" {
		t.Fatalf("parent selected another principal: %+v", got)
	}
	if got := idChildOptionsFromFlags(); got.Issuer.Human != "" || got.Issuer.Domain != "child.example" {
		t.Fatalf("child selected another principal: %+v", got.Issuer)
	}
}
