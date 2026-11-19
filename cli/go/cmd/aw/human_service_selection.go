package main

import (
	"os"
	"strings"
)

type humanServiceSelection struct {
	AwebURL       string
	URL           string
	MembershipURL string
}

func humanParticipationServiceURL(input humanServiceSelection) string {
	return firstNonEmpty(input.AwebURL, input.URL, input.MembershipURL, strings.TrimSpace(os.Getenv("AWEB_URL")))
}
