package main

import (
	"errors"
	"strings"
	"testing"

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
