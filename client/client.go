package aweb

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

const (
	// DefaultTimeout is the default HTTP timeout used by the client.
	DefaultTimeout = 10 * time.Second

	maxResponseSize = 10 * 1024 * 1024
)

// Client is an aweb HTTP client.
//
// It is designed to be easy to extract into a standalone repo and to be used by:
// - the `aw` CLI
// - the `bdh` CLI for `:mail/:chat/:lock` delegation
type Client struct {
	baseURL    string
	httpClient *http.Client
	sseClient  *http.Client // No response timeout; SSE connections are long-lived.
	apiKey     string
}

// New creates a new client.
func New(baseURL string) (*Client, error) {
	if _, err := url.Parse(baseURL); err != nil {
		return nil, err
	}
	return &Client{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: DefaultTimeout,
		},
		sseClient: &http.Client{},
	}, nil
}

// NewWithAPIKey creates a new client authenticated with a project API key.
func NewWithAPIKey(baseURL, apiKey string) (*Client, error) {
	c, err := New(baseURL)
	if err != nil {
		return nil, err
	}
	c.apiKey = apiKey
	return c, nil
}

type apiError struct {
	StatusCode int
	Body       string
}

func (e *apiError) Error() string {
	if e.Body == "" {
		return fmt.Sprintf("aweb: http %d", e.StatusCode)
	}
	return fmt.Sprintf("aweb: http %d: %s", e.StatusCode, e.Body)
}

func (c *Client) get(ctx context.Context, path string, out any) error {
	return c.do(ctx, http.MethodGet, path, nil, out)
}

func (c *Client) post(ctx context.Context, path string, in any, out any) error {
	return c.do(ctx, http.MethodPost, path, in, out)
}

func (c *Client) do(ctx context.Context, method, path string, in any, out any) error {
	resp, err := c.doRaw(ctx, method, path, "application/json", in)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	limited := io.LimitReader(resp.Body, maxResponseSize)
	data, err := io.ReadAll(limited)
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &apiError{StatusCode: resp.StatusCode, Body: string(data)}
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return err
	}
	return nil
}

func (c *Client) doRaw(ctx context.Context, method, path, accept string, in any) (*http.Response, error) {
	var body io.Reader
	if in != nil {
		data, err := json.Marshal(in)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return nil, err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", accept)
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}
