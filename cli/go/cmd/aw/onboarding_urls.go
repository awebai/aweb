package main

import (
	"context"
	"strings"
	"time"

	"github.com/awebai/aw/awid"
)

type onboardingServiceURLs struct {
	OnboardingURL string
	AwebURL       string
	RegistryURL   string
}

func resolveOnboardingServiceURLs(raw string) (onboardingServiceURLs, error) {
	if v := strings.TrimSpace(raw); v != "" {
		urls, err := discoverOnboardingServiceURLs(v)
		if err == nil {
			return urls, nil
		}
		fallbackURL, ferr := resolveGuidedOnboardingServerURL(v)
		if ferr != nil {
			return onboardingServiceURLs{}, ferr
		}
		return onboardingServiceURLs{
			OnboardingURL: fallbackURL,
			AwebURL:       fallbackURL,
		}, nil
	}

	if sel, err := resolveSelectionForDir(""); err == nil {
		urls, err := normalizeOnboardingServiceURLs(onboardingServiceURLs{
			AwebURL:     sel.AwebURL,
			RegistryURL: sel.RegistryURL,
		})
		if err == nil && strings.TrimSpace(urls.AwebURL) != "" {
			return urls, nil
		}
		if strings.TrimSpace(sel.BaseURL) != "" {
			return onboardingServiceURLs{
				AwebURL:     strings.TrimSpace(sel.BaseURL),
				RegistryURL: strings.TrimSpace(sel.RegistryURL),
			}, nil
		}
	}

	urls, err := discoverOnboardingServiceURLs(DefaultServerURL)
	if err == nil {
		return urls, nil
	}
	fallbackURL, ferr := resolveGuidedOnboardingServerURL(DefaultServerURL)
	if ferr != nil {
		return onboardingServiceURLs{}, ferr
	}
	return onboardingServiceURLs{
		OnboardingURL: fallbackURL,
		AwebURL:       fallbackURL,
	}, nil
}

func discoverOnboardingServiceURLs(raw string) (onboardingServiceURLs, error) {
	baseURL, err := resolveGuidedOnboardingServerURL(raw)
	if err != nil {
		return onboardingServiceURLs{}, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	resp, err := awid.DiscoverServices(ctx, baseURL)
	if err != nil {
		return onboardingServiceURLs{}, err
	}
	urls, err := normalizeOnboardingServiceURLs(onboardingServiceURLs{
		OnboardingURL: resp.OnboardingURL,
		AwebURL:       resp.AwebURL,
		RegistryURL:   resp.RegistryURL,
	})
	if err != nil {
		return onboardingServiceURLs{}, err
	}
	if urls.OnboardingURL == "" {
		urls.OnboardingURL = baseURL
	}
	if urls.AwebURL == "" {
		urls.AwebURL = baseURL
	}
	return urls, nil
}

func normalizeOnboardingServiceURLs(urls onboardingServiceURLs) (onboardingServiceURLs, error) {
	var err error
	if strings.TrimSpace(urls.OnboardingURL) != "" {
		urls.OnboardingURL, err = cleanBaseURL(urls.OnboardingURL)
		if err != nil {
			return onboardingServiceURLs{}, err
		}
	}
	if strings.TrimSpace(urls.AwebURL) != "" {
		urls.AwebURL, err = cleanBaseURL(urls.AwebURL)
		if err != nil {
			return onboardingServiceURLs{}, err
		}
	}
	if strings.TrimSpace(urls.RegistryURL) != "" {
		urls.RegistryURL, err = cleanBaseURL(urls.RegistryURL)
		if err != nil {
			return onboardingServiceURLs{}, err
		}
	}
	if urls.OnboardingURL == "" {
		urls.OnboardingURL = urls.AwebURL
	}
	if urls.AwebURL == "" {
		urls.AwebURL = urls.OnboardingURL
	}
	return urls, nil
}
