package main

import "testing"

func resetAwebURLResolverGlobalsForTest(t *testing.T) {
	t.Helper()
	oldInitAwebURL := initAwebURL
	oldInitURL := initURL
	t.Cleanup(func() {
		initAwebURL = oldInitAwebURL
		initURL = oldInitURL
	})
	initAwebURL = ""
	initURL = ""
}

func TestResolveInitAwebURLOverrideCharacterization(t *testing.T) {
	resetAwebURLResolverGlobalsForTest(t)
	t.Setenv("AWEB_URL", "")
	if got := resolveInitAwebURLOverride(); got != "" {
		t.Fatalf("empty override=%q, want empty", got)
	}

	t.Setenv("AWEB_URL", "https://env.example")
	if got := resolveInitAwebURLOverride(); got != "https://env.example" {
		t.Fatalf("env override=%q", got)
	}

	initURL = "https://compat.example"
	if got := resolveInitAwebURLOverride(); got != "https://compat.example" {
		t.Fatalf("compat --url override=%q", got)
	}

	initAwebURL = "https://flag.example"
	if got := resolveInitAwebURLOverride(); got != "https://flag.example" {
		t.Fatalf("--aweb-url override=%q", got)
	}
}

func TestAwebURLResolversCharacterization(t *testing.T) {
	t.Run("init resolver defaults and normalizes with api suffix preserved", func(t *testing.T) {
		resetAwebURLResolverGlobalsForTest(t)
		t.Setenv("AWEB_URL", "")
		got, err := resolveInitAwebURL()
		if err != nil {
			t.Fatalf("resolveInitAwebURL default: %v", err)
		}
		if got != DefaultAwebURL {
			t.Fatalf("default init url=%q want %q", got, DefaultAwebURL)
		}
		initAwebURL = "https://app.example/api/"
		got, err = resolveInitAwebURL()
		if err != nil {
			t.Fatalf("resolveInitAwebURL flag: %v", err)
		}
		if got != "https://app.example/api" {
			t.Fatalf("init url with /api=%q", got)
		}
	})

	t.Run("api key resolver shares override precedence but strips api suffix", func(t *testing.T) {
		resetAwebURLResolverGlobalsForTest(t)
		t.Setenv("AWEB_URL", "https://env.example/api")
		got, err := resolveAPIKeyInitAwebURL()
		if err != nil {
			t.Fatalf("resolveAPIKeyInitAwebURL env: %v", err)
		}
		if got != "https://env.example" {
			t.Fatalf("api key env url=%q", got)
		}
		initAwebURL = "https://flag.example/api"
		got, err = resolveAPIKeyInitAwebURL()
		if err != nil {
			t.Fatalf("resolveAPIKeyInitAwebURL flag: %v", err)
		}
		if got != "https://flag.example" {
			t.Fatalf("api key flag url=%q", got)
		}
	})

	t.Run("wizard default reads env only and leaves normalization to caller", func(t *testing.T) {
		resetAwebURLResolverGlobalsForTest(t)
		initAwebURL = "https://flag-ignored.example"
		t.Setenv("AWEB_URL", "https://env.example/api/")
		if got := defaultWizardAwebURL(); got != "https://env.example/api/" {
			t.Fatalf("wizard default env=%q", got)
		}
		t.Setenv("AWEB_URL", "")
		if got := defaultWizardAwebURL(); got != DefaultAwebURL {
			t.Fatalf("wizard default=%q want %q", got, DefaultAwebURL)
		}
	})

	t.Run("guided onboarding raw beats env and empty uses wizard default", func(t *testing.T) {
		resetAwebURLResolverGlobalsForTest(t)
		t.Setenv("AWEB_URL", "https://env.example/api/")
		got, err := resolveGuidedOnboardingAwebURL("https://raw.example/api/")
		if err != nil {
			t.Fatalf("resolveGuidedOnboardingAwebURL raw: %v", err)
		}
		if got != "https://raw.example/api" {
			t.Fatalf("guided raw url=%q", got)
		}
		got, err = resolveGuidedOnboardingAwebURL("")
		if err != nil {
			t.Fatalf("resolveGuidedOnboardingAwebURL env: %v", err)
		}
		if got != "https://env.example/api" {
			t.Fatalf("guided env url=%q", got)
		}
	})
}
