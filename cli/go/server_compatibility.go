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
	status, isHTTP := awid.HTTPStatusCode(err)
	if !isHTTP || status != http.StatusNotFound {
		return err
	}
	body, hasBody := awid.HTTPErrorBody(err)
	var answer struct {
		Detail string `json:"detail"`
	}
	if !hasBody || json.Unmarshal([]byte(body), &answer) != nil || answer.Detail != "Not Found" {
		return err
	}
	return fmt.Errorf("%s require aweb server %s or later: %w. Upgrade the server or select the intended service URL.", feature.name, feature.minimumVersion, err)
}
