package main

import (
	"context"
	"strings"
	"time"

	"github.com/awebai/aw/awid"
)

type onboardingServiceURLs struct {
	CloudURL string
	AwebURL  string
	AwidURL  string
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
			CloudURL: fallbackURL,
			AwebURL:  fallbackURL,
		}, nil
	}

	if sel, err := resolveSelectionForDir(""); err == nil {
		urls, err := normalizeOnboardingServiceURLs(onboardingServiceURLs{
			CloudURL: sel.CloudURL,
			AwebURL:  sel.AwebURL,
			AwidURL:  sel.AwidURL,
		})
		if err == nil && strings.TrimSpace(urls.AwebURL) != "" {
			return urls, nil
		}
		if strings.TrimSpace(sel.BaseURL) != "" {
			return onboardingServiceURLs{
				CloudURL: strings.TrimSpace(sel.BaseURL),
				AwebURL:  strings.TrimSpace(sel.BaseURL),
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
		CloudURL: fallbackURL,
		AwebURL:  fallbackURL,
	}, nil
}

func discoverOnboardingServiceURLs(raw string) (onboardingServiceURLs, error) {
	cloudURL, err := resolveGuidedOnboardingServerURL(raw)
	if err != nil {
		return onboardingServiceURLs{}, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	resp, err := awid.DiscoverServices(ctx, cloudURL)
	if err != nil {
		return onboardingServiceURLs{}, err
	}
	urls, err := normalizeOnboardingServiceURLs(onboardingServiceURLs{
		CloudURL: resp.CloudURL,
		AwebURL:  resp.AwebURL,
		AwidURL:  resp.AwidURL,
	})
	if err != nil {
		return onboardingServiceURLs{}, err
	}
	if urls.CloudURL == "" {
		urls.CloudURL = cloudURL
	}
	if urls.AwebURL == "" {
		urls.AwebURL = cloudURL
	}
	return urls, nil
}

func normalizeOnboardingServiceURLs(urls onboardingServiceURLs) (onboardingServiceURLs, error) {
	var err error
	if strings.TrimSpace(urls.CloudURL) != "" {
		urls.CloudURL, err = cleanBaseURL(urls.CloudURL)
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
	if strings.TrimSpace(urls.AwidURL) != "" {
		urls.AwidURL, err = cleanBaseURL(urls.AwidURL)
		if err != nil {
			return onboardingServiceURLs{}, err
		}
	}
	if urls.CloudURL == "" {
		urls.CloudURL = urls.AwebURL
	}
	if urls.AwebURL == "" {
		urls.AwebURL = urls.CloudURL
	}
	return urls, nil
}
