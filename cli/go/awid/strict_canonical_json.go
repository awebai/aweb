package awid

import "github.com/awebai/aw/canonicaljson"

// StrictCanonicalJSON encodes the safe-integer UTF-8 profile for pages/tasks.
func StrictCanonicalJSON(value any) ([]byte, error) { return canonicaljson.Strict(value) }
