package main

import "github.com/awebai/aw/awid"

type identityScopeFlags struct {
	Global bool
}

// identityScopeFromFlags adapts the released --global flag to the shared scope
// vocabulary. Request/state wire fields keep their published string encoding.
func identityScopeFromFlags(flags identityScopeFlags) awid.IdentityScope {
	if flags.Global {
		return awid.IdentityScopeGlobal
	}
	return awid.IdentityScopeLocal
}
