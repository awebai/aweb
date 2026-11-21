package main

import "testing"

func TestHumanConnectUsesExplicitThenEnvironmentThenStoredService(t *testing.T) {
	for _, sample := range []struct {
		name, environment string
		input             serviceURLSelection
		want              string
	}{
		{"explicit aweb URL", "https://environment.example", serviceURLSelection{AwebURL: "https://flag.example", URL: "https://alias.example", StoredURL: "https://stored.example"}, "https://flag.example"},
		{"explicit URL alias", "https://environment.example", serviceURLSelection{URL: "https://alias.example", StoredURL: "https://stored.example"}, "https://alias.example"},
		{"environment override", "https://environment.example", serviceURLSelection{StoredURL: "https://stored.example"}, "https://environment.example"},
		{"stored service", "", serviceURLSelection{StoredURL: "https://stored.example"}, "https://stored.example"},
	} {
		t.Run(sample.name, func(t *testing.T) {
			t.Setenv("AWEB_URL", sample.environment)
			if got := selectedAwebServiceURL(sample.input); got != sample.want {
				t.Fatalf("selected service=%q want=%q", got, sample.want)
			}
		})
	}
}
