package awid

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const discoveryPath = "/api/v1/discovery"

type DiscoveryResponse struct {
	CloudURL string   `json:"cloud_url"`
	AwebURL  string   `json:"aweb_url"`
	AwidURL  string   `json:"awid_url"`
	Version  string   `json:"version,omitempty"`
	Features []string `json:"features,omitempty"`
}

func DiscoverServices(ctx context.Context, baseURL string) (*DiscoveryResponse, error) {
	baseURL, err := cleanDiscoveryBaseURL(baseURL)
	if err != nil {
		return nil, err
	}

	requestPath := discoveryPath
	if strings.HasSuffix(baseURL, "/api") {
		requestPath = strings.TrimPrefix(requestPath, "/api")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+requestPath, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, &RegistryError{StatusCode: resp.StatusCode, Detail: strings.TrimSpace(string(detail))}
	}

	var out DiscoveryResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode discovery response: %w", err)
	}
	return &out, nil
}

func cleanDiscoveryBaseURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("empty base url")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("invalid base url %q", raw)
	}
	u.Path = strings.TrimSuffix(u.Path, "/")
	u.RawPath = ""
	u.RawQuery = ""
	u.Fragment = ""
	return strings.TrimSuffix(u.String(), "/"), nil
}
