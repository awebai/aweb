package awid

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

// AWID's coded alias conflict, as released aw clients parse it: the code and
// message reach RegistryError, and the error still prints the response body.
func TestRegistryCodedAliasConflictParsesAndDescribes(t *testing.T) {
	body := `{"detail":{"code":"alias_active","message":"Alias already active in team"}}`
	err := parseRegistryError(&http.Response{StatusCode: http.StatusConflict, Body: io.NopCloser(strings.NewReader(body))})
	registryErr, ok := err.(*RegistryError)
	if !ok || registryErr.Code != "alias_active" || registryErr.Message != "Alias already active in team" || registryErr.Error() != "registry http 409: "+body {
		t.Fatalf("parsed %#v: %v", err, err)
	}
	if got := DescribeError(err); got != (ErrorDetail{Code: "alias_conflict", HTTPStatus: 409, Detail: "Alias already active in team", Reason: "alias_active"}) {
		t.Fatalf("described %+v", got)
	}
}

// The server's coded alias conflicts: only alias_active is an alias conflict.
func TestServerCodedAliasConflictDescribes(t *testing.T) {
	for _, tc := range []struct {
		code, want string
	}{{"alias_active", "alias_conflict"}, {"alias_mismatch", "http_error"}} {
		err := &APIError{StatusCode: http.StatusConflict, Body: `{"detail":{"code":"` + tc.code + `","message":"refused"}}`}
		if got := DescribeError(err); got != (ErrorDetail{Code: tc.want, HTTPStatus: 409, Detail: "refused", Reason: tc.code}) {
			t.Fatalf("%s: described %+v", tc.code, got)
		}
	}
}
