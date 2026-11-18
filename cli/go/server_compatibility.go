package aweb

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/awebai/aw/awid"
)

type serverFeature struct {
	name           string
	minimumVersion string
}

var (
	identityGrantEndpoint = serverFeature{name: "identity grants", minimumVersion: "1.27.2"}
	sessionLeaseEndpoint  = serverFeature{name: "session leases", minimumVersion: "1.26.28"}
)

// missingEndpointDiagnostic implements the authentication error diagnostics in
// docs/aweb-sot.md:346: a resource miss is preserved; only the router's missing-endpoint
// answer supports a minimum-server diagnostic.
func missingEndpointDiagnostic(err error, feature serverFeature) error {
	if !IsMissingEndpointError(err) {
		return err
	}
	return fmt.Errorf("%s require aweb server %s or later: %w. Upgrade the server or select the intended service URL.", feature.name, feature.minimumVersion, err)
}

// IsMissingEndpointError distinguishes the router's missing-endpoint answer from
// a resource miss, as required by docs/aweb-sot.md:346. A status alone is not
// evidence that the server lacks a feature.
func IsMissingEndpointError(err error) bool {
	status, isHTTP := awid.HTTPStatusCode(err)
	if !isHTTP || status != http.StatusNotFound {
		return false
	}
	body, hasBody := awid.HTTPErrorBody(err)
	var answer struct {
		Detail string `json:"detail"`
	}
	return hasBody && json.Unmarshal([]byte(body), &answer) == nil && answer.Detail == "Not Found"
}
