package aweb

import (
	"testing"

	"github.com/awebai/aw/awid"
)

func TestResourceNotFoundIsNotAnUnsupportedServer(t *testing.T) {
	for _, test := range []struct {
		name     string
		classify func(error) error
		body     string
	}{
		{name: "missing grant", classify: identityGrantCompatibilityError, body: `{"detail":"grant not found"}`},
		{name: "grant outside selected team", classify: identityGrantCompatibilityError, body: `{"code":"grant_not_found","contract":"identity-grant-status.v1"}`},
		{name: "expired lease", classify: sessionLeaseCompatibilityError, body: `{"detail":"session admission lease not found or expired"}`},
		{name: "missing lease", classify: sessionLeaseCompatibilityError, body: `{"detail":"session admission lease not found"}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			original := &awid.APIError{StatusCode: 404, Body: test.body}
			if got := test.classify(original); got != original {
				t.Fatalf("resource miss rewritten as server compatibility: %v", got)
			}
		})
	}
}
