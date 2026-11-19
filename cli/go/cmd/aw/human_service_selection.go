package main

import "os"

type humanServiceSelection struct {
	AwebURL       string
	URL           string
	MembershipURL string
}

// humanParticipationServiceURL implements docs/configuration.md's Resolution
// Order: explicit service flags, environment, then the selected membership.
func humanParticipationServiceURL(input humanServiceSelection) string {
	return firstNonEmptyString(input.AwebURL, input.URL, os.Getenv("AWEB_URL"), input.MembershipURL)
}
