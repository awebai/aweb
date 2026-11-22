package main

import (
	"errors"
	"os"

	"github.com/awebai/aw/awconfig"
	"github.com/spf13/cobra"
)

type identityHomeEnvironment struct {
	Value   string
	Present bool
	Active  awconfig.IdentityHome
}

func captureIdentityHomeEnvironment() identityHomeEnvironment {
	value, present := os.LookupEnv(awconfig.IdentityHomeEnv)
	return identityHomeEnvironment{Value: value, Present: present, Active: activeIdentityHome}
}

func (previous identityHomeEnvironment) restore() error {
	activeIdentityHome = previous.Active
	if previous.Present {
		return os.Setenv(awconfig.IdentityHomeEnv, previous.Value)
	}
	return os.Unsetenv(awconfig.IdentityHomeEnv)
}

// restoreIdentityHomeAfterCommand scopes selected-principal compatibility state
// to one command. A restoration error is returned along with a command failure.
func restoreIdentityHomeAfterCommand(command *cobra.Command, previous identityHomeEnvironment) {
	if run := command.RunE; run != nil {
		command.RunE = func(command *cobra.Command, args []string) (err error) {
			defer func() {
				err = errors.Join(err, previous.restore())
				command.RunE = run
			}()
			return run(command, args)
		}
		return
	}
	if run := command.Run; run != nil {
		command.RunE = func(command *cobra.Command, args []string) (err error) {
			defer func() {
				err = previous.restore()
				command.RunE = nil
			}()
			run(command, args)
			return nil
		}
	}
}
