package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// groupingCommands returns every command that exists only to gather subcommands - it has
// children and nothing of its own to run. Collected BEFORE the policy is applied, because
// applying it gives each of them a RunE and this predicate would then match none of them.
func groupingCommands(root *cobra.Command) []*cobra.Command {
	var found []*cobra.Command
	var walk func(*cobra.Command)
	walk = func(c *cobra.Command) {
		if c.HasSubCommands() && c.Run == nil && c.RunE == nil {
			found = append(found, c)
		}
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(root)
	return found
}

// aweb-aaxl: `aw id pin-store list` printed the help for `aw id pin-store` and EXITED 0
// on a binary without `list`. A missing subcommand did not fail - it answered with a
// success code and a plausible page of text - which is why the author of that command
// read the file by hand rather than noticing it was absent from the binary they ran.
//
// These assertions go through RunE, which is what cobra actually calls. An earlier
// version of this test asserted on ValidateArgs and PASSED WHILE THE BINARY WAS
// UNCHANGED: cobra returns flag.ErrHelp for a non-runnable command BEFORE validating
// arguments, so the argument policy of a grouping command is never consulted.
func TestAnUnknownSubcommandIsRefusedRatherThanAnsweredWithParentHelp(t *testing.T) {
	groups := groupingCommands(rootCmd)
	if len(groups) < 10 {
		t.Fatalf("found %d grouping commands - the walk is broken and every assertion below would be vacuous", len(groups))
	}
	refuseUnknownSubcommands(rootCmd)

	for _, group := range groups {
		t.Run(group.CommandPath(), func(t *testing.T) {
			if group.RunE == nil {
				t.Fatalf("%s has no RunE, so cobra will answer flag.ErrHelp and never consult any argument policy", group.CommandPath())
			}
			err := group.RunE(group, []string{"definitely-not-a-subcommand"})
			if err == nil {
				t.Fatalf("%s accepted an unknown subcommand, so it prints its own help and exits 0", group.CommandPath())
			}
			if !strings.Contains(err.Error(), "definitely-not-a-subcommand") {
				t.Fatalf("%s refused without naming the unknown token: %v", group.CommandPath(), err)
			}
			if !strings.Contains(err.Error(), group.CommandPath()) {
				t.Fatalf("%s refused without naming which command was asked: %v", group.CommandPath(), err)
			}
		})
	}
}

// The direction this change would most easily break: a grouping command invoked BARE is
// how a reader asks what it offers. It must still succeed and print its own help.
func TestAGroupingCommandInvokedBareStillPrintsItsHelpAndSucceeds(t *testing.T) {
	groups := groupingCommands(rootCmd)
	refuseUnknownSubcommands(rootCmd)

	for _, group := range groups {
		t.Run(group.CommandPath(), func(t *testing.T) {
			var out bytes.Buffer
			group.SetOut(&out)
			t.Cleanup(func() { group.SetOut(nil) })
			if err := group.RunE(group, nil); err != nil {
				t.Fatalf("%s failed when invoked with no arguments: %v", group.CommandPath(), err)
			}
			if !strings.Contains(out.String(), group.CommandPath()) {
				t.Fatalf("%s succeeded but printed no help naming itself: %q", group.CommandPath(), out.String())
			}
		})
	}
}
