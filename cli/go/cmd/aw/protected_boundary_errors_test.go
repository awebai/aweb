package main

import (
	"github.com/awebai/aw/awid"
	"strings"
	"testing"
)

func TestProtectedBoundaryRefusalsExplainConfiguredPath(t *testing.T) {
	for _, code := range []string{"protected_admission_required", "protected_controller_required", "protected_state_unavailable"} {
		err := &awid.RegistryError{StatusCode: 403, Detail: `{"detail":{"code":"` + code + `","message":"` + code + `"}}`}
		text := codedRefusalText(err, err.Error())
		if !strings.Contains(text, code) || !strings.Contains(text, "configured") {
			t.Fatalf("%s: %s", code, text)
		}
		if code != "protected_state_unavailable" && !strings.Contains(text, "protected-profile") {
			t.Fatalf("%s", text)
		}
	}
}
