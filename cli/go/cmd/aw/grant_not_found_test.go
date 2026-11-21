package main

import (
	"errors"
	"testing"

	"github.com/awebai/aw/awid"
)

func TestGrantNotFoundRecoveryNamesTheSelectedTeam(t *testing.T) {
	lookup := grantLookup{grantID: "absent", teamID: "backend:example.test"}
	want := "Grant absent was not found in team backend:example.test. Run `aw --team backend:example.test id grant list` with the same identity home to choose a grant ID."
	cause := &awid.APIError{StatusCode: 404, Body: `{"detail":"grant not found"}`}
	err := grantNotFoundInTeam(lookup, cause)
	if err.Error() != want || !errors.Is(err, cause) {
		t.Fatalf("selected-team recovery lost its context or original refusal: %v", err)
	}
	envelope := errorEnvelope(err, err.Error())
	if envelope.Error.Code != "grant_not_found" || envelope.Error.HTTPStatus != 404 || envelope.Error.Detail != "grant not found" || envelope.Error.Message != want {
		t.Fatalf("grant not-found error metadata changed: %+v", envelope.Error)
	}
	// Show reads a successful list, so a missing item has no HTTP failure.
	missingFromList := errorEnvelope(grantNotFoundInTeam(lookup, nil), want)
	if missingFromList.Error.Code != "grant_not_found" || missingFromList.Error.HTTPStatus != 0 || missingFromList.Error.Message != want {
		t.Fatalf("missing list item invented an HTTP refusal: %+v", missingFromList.Error)
	}
}
