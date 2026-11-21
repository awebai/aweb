package awid

import (
	"os"
	"strings"
)

// TraceEnabled reads AW_TRACE with the released HTTP trace setting's accepted
// true forms. Callers with an explicit --trace flag may OR that value with it.
// This selects diagnostics only; each trace writer still owns redaction.
func TraceEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("AW_TRACE"))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}
