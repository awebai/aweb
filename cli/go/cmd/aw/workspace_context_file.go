package main

import "errors"

type workspaceContextPolicy uint8

const (
	workspaceContextEnsure workspaceContextPolicy = iota
	workspaceContextPreserve
)

func (policy workspaceContextPolicy) validate() error {
	if policy != workspaceContextEnsure && policy != workspaceContextPreserve {
		return errors.New("workspace context policy is unknown")
	}
	return nil
}

// apply honors the init context-file opt-out without deleting an existing
// pointer or changing identity selection (docs/configuration.md:275-277).
func (policy workspaceContextPolicy) apply(home string) error {
	if err := policy.validate(); err != nil {
		return err
	}
	if policy == workspaceContextPreserve {
		return nil
	}
	return ensureWorktreeContextAtIdentityHome(home)
}

// requestedInitContextPolicy adapts init's parsed flag at the command boundary.
func requestedInitContextPolicy() workspaceContextPolicy {
	if !initWriteContext {
		return workspaceContextPreserve
	}
	return workspaceContextEnsure
}
