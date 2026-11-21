package main

import "os"

type serviceURLSelection struct {
	AwebURL   string
	URL       string
	StoredURL string
}

// selectedAwebServiceURL implements docs/configuration.md's Resolution
// Order: explicit service flags, environment, then the stored service URL.
func selectedAwebServiceURL(input serviceURLSelection) string {
	return firstNonEmptyString(input.AwebURL, input.URL, os.Getenv("AWEB_URL"), input.StoredURL)
}
