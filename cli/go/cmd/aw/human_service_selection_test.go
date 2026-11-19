package main

import "testing"

func TestHumanConnectUsesExplicitThenEnvironmentThenStoredService(t *testing.T) {
	for _, sample := range []struct {
		name, environment string
		input             humanServiceSelection
		want              string
	}{
		{"explicit aweb URL", "https://environment.example", humanServiceSelection{AwebURL: "https://flag.example", URL: "https://alias.example", MembershipURL: "https://stored.example"}, "https://flag.example"},
		{"explicit URL alias", "https://environment.example", humanServiceSelection{URL: "https://alias.example", MembershipURL: "https://stored.example"}, "https://alias.example"},
		{"environment override", "https://environment.example", humanServiceSelection{MembershipURL: "https://stored.example"}, "https://environment.example"},
		{"stored service", "", humanServiceSelection{MembershipURL: "https://stored.example"}, "https://stored.example"},
	} {
		t.Run(sample.name, func(t *testing.T) {
			t.Setenv("AWEB_URL", sample.environment)
			if got := humanParticipationServiceURL(sample.input); got != sample.want {
				t.Fatalf("selected service=%q want=%q", got, sample.want)
			}
		})
	}
}
