// Package approval is the aw requester for the shared awsign protocol. It owns
// transport and the original request bytes, never a human decision or an effect.
package approval

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	proof "github.com/awebai/approval-service/verify"
	"github.com/awebai/aw/awid"
)

// Routes are the format-v1 transport paths; signing is owned by the shared
// verifier. Corpus tests check the actual URL and signed packet together.
var routes = map[string]string{"submit": "/v1/requests/submit", "poll": "/v1/requests/poll", "cancel": "/v1/requests/cancel", "enrollment_start": "/v1/enrollments/start", "enrollment_material": "/v1/enrollments/material", "enrollment_confirm": "/v1/enrollments/confirm", "enrollment_activate": "/v1/enrollments/activate"}

type Client struct {
	Origin    string
	Requester map[string]any
	Key       ed25519.PrivateKey
	// Authorize allows a typed custody client to return the header without
	// releasing its key. The shared verifier checks the returned binding.
	Authorize    func(body []byte, purpose string, issuedAt int64) (string, error)
	Admission    map[string]any
	HTTP         *http.Client
	Now          func() time.Time
	PollInterval time.Duration
	Notify       io.Writer
	// Retain stores original request bytes before submission, and the complete
	// receipt before presentation. A failed write prevents the next exchange.
	Retain func(kind string, raw []byte) error
}

func (c *Client) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}
func (c *Client) SignedRequest(ctx context.Context, purpose string, body []byte) (*http.Request, error) {
	origin, e := url.Parse(c.Origin)
	if e != nil || origin.Scheme != "https" || origin.Host == "" || origin.User != nil || origin.Path != "" || origin.RawQuery != "" || origin.Fragment != "" {
		return nil, errors.New("approval_origin_invalid")
	}
	path, ok := routes[purpose]
	if !ok {
		return nil, errors.New("http_binding_mismatch")
	}
	value, e := proof.Parse(body)
	if e != nil {
		return nil, e
	}
	raw, e := proof.Canonical(value)
	if e != nil {
		return nil, e
	}
	now := c.now().Unix()
	var header string
	if c.Authorize != nil {
		header, e = c.Authorize(raw, purpose, now)
	} else {
		header, e = proof.HTTPAuthorization(raw, c.Key, c.Requester, c.Origin, purpose, now)
	}
	if e != nil {
		return nil, e
	}
	if _, e = proof.CheckHTTP(header, raw, proof.HTTPInput{Requester: c.Requester, Origin: c.Origin, Method: http.MethodPost, Path: path, Purpose: purpose, Now: now}); e != nil {
		return nil, e
	}
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, c.Origin+path, bytes.NewReader(raw))
	if e != nil {
		return nil, e
	}
	req.Header.Set("Authorization", header)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	return req, nil
}

type Session struct {
	client       *Client
	RequestBytes []byte
	Request      map[string]any
	Digest       string
	Locator      string
	answer       map[string]any
	status       int
	answerKind   string
}

func (c *Client) From428(raw []byte, status int) (*Session, error) {
	value, e := proof.Parse(raw)
	if e != nil {
		return nil, e
	}
	request, e := proof.ReadNeedsHuman(value, c.Requester, c.Origin, c.now().Unix(), int64(status))
	if e != nil {
		return nil, e
	}
	original, e := base64.RawURLEncoding.Strict().DecodeString(value["request_bytes"].(string))
	if e != nil {
		return nil, e
	}
	return &Session{client: c, RequestBytes: original, Request: request, Digest: value["digest"].(string)}, nil
}
func (s *Session) Submission() map[string]any {
	return map[string]any{"version": 1, "request_bytes": base64.RawURLEncoding.EncodeToString(s.RequestBytes), "admission": s.client.Admission}
}
func (s *Session) Selection() map[string]any {
	return map[string]any{"version": 1, "request_bytes": base64.RawURLEncoding.EncodeToString(s.RequestBytes), "admission": s.client.Admission, "locator": s.Locator, "digest": s.Digest}
}
func (s *Session) ReadAnswer(kind string, raw []byte, status int) (map[string]any, error) {
	answer, e := proof.ReadAnswerJSON(kind, raw, proof.AnswerInput{Status: status, RequestBytes: s.RequestBytes, Locator: s.Locator})
	if e != nil {
		return nil, e
	}
	s.Locator = answer["locator"].(string)
	s.answer = answer
	s.status = status
	s.answerKind = kind
	return answer, nil
}

// NeedsPoll distinguishes a decision summary from the raw approval bundle.
func (s *Session) NeedsPoll() bool { return s.answerKind == "submit" || s.answer["state"] == "pending" }
func (s *Session) Receipt() (map[string]any, error) {
	return proof.AssembleReceipt(s.RequestBytes, s.answer, proof.AnswerInput{Status: s.status, Locator: s.Locator})
}
func (s *Session) Presentation() ([]byte, error) {
	receipt, e := s.Receipt()
	if e != nil {
		return nil, e
	}
	return proof.Canonical(map[string]any{"version": 1, "request_bytes": base64.RawURLEncoding.EncodeToString(s.RequestBytes), "receipt": receipt})
}
func (c *Client) exchange(ctx context.Context, purpose string, body map[string]any) ([]byte, int, error) {
	raw, e := proof.Canonical(body)
	if e != nil {
		return nil, 0, e
	}
	req, e := c.SignedRequest(ctx, purpose, raw)
	if e != nil {
		return nil, 0, e
	}
	client := c.HTTP
	if client == nil {
		client = &http.Client{Timeout: awid.APITimeout(), Transport: awid.NewAPITransport()}
	}
	bounded := *client
	bounded.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, e := bounded.Do(req)
	if e != nil {
		return nil, 0, e
	}
	defer response.Body.Close()
	raw, e = awid.ReadAllBounded(response.Body, 1<<20)
	return raw, response.StatusCode, e
}
func (s *Session) live() error {
	now := s.client.now().Unix()
	n, e := s.Request["not_before"].(interface{ Int64() (int64, error) }).Int64()
	if e != nil {
		return e
	}
	d, e := s.Request["deadline"].(interface{ Int64() (int64, error) }).Int64()
	if e != nil {
		return e
	}
	if now < n || now >= d {
		return errors.New("request_expired")
	}
	original, e := proof.Canonical(s.Request["requester"])
	if e != nil {
		return e
	}
	actual, e := proof.Canonical(s.client.Requester)
	if e != nil {
		return e
	}
	if !bytes.Equal(original, actual) {
		return errors.New("requester_mismatch")
	}
	return nil
}

// Complete428 carries a single frozen request through submission and polling.
// It returns the receipt presentation, not an assertion that an effect occurred.
func (c *Client) Complete428(ctx context.Context, body []byte, status int) ([]byte, error) {
	s, e := c.From428(body, status)
	if e != nil {
		return nil, e
	}
	if c.Retain == nil {
		return nil, errors.New("approval_record_required")
	}
	if e = c.Retain("request", s.RequestBytes); e != nil {
		return nil, e
	}
	deadline, _ := s.Request["deadline"].(interface{ Int64() (int64, error) }).Int64()
	ctx, cancel := context.WithDeadline(ctx, time.Unix(deadline, 0))
	defer cancel()
	purpose, payload := "submit", s.Submission()
	interval := c.PollInterval
	if interval <= 0 {
		interval = time.Second
	}
	wait := func() error {
		timer := time.NewTimer(interval)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return nil
		}
	}
	notified := false
	for {
		if e = s.live(); e != nil {
			return nil, e
		}
		answer, status, e := c.exchange(ctx, purpose, payload)
		if e != nil {
			return nil, e
		}
		if purpose == "poll" && (status == http.StatusTooManyRequests || status >= 500 && status < 600) {
			if e = wait(); e != nil {
				return nil, e
			}
			continue
		}
		if _, e = s.ReadAnswer(purpose, answer, status); e != nil {
			return nil, e
		}
		if !s.NeedsPoll() {
			if e = s.live(); e != nil {
				return nil, e
			}
			receipt, err := s.Receipt()
			if err != nil {
				return nil, err
			}
			saved, err := proof.Canonical(receipt)
			if err != nil {
				return nil, err
			}
			if err = c.Retain("receipt", saved); err != nil {
				return nil, err
			}
			if err = s.live(); err != nil {
				return nil, err
			}
			return s.Presentation()
		}
		if purpose == "submit" {
			purpose, payload = "poll", s.Selection()
			continue
		}
		if !notified && c.Notify != nil {
			fmt.Fprintln(c.Notify, "Waiting for human approval at the person's known approval service.")
			notified = true
		}
		if e = wait(); e != nil {
			return nil, e
		}
		purpose, payload = "poll", s.Selection()
	}
}

// Resume uses the caller's saved R, without asking the enforcer for a new act,
// nonce or deadline. The service's same-requester submission is idempotent.
func (c *Client) Resume(ctx context.Context, original []byte, receipt map[string]any) ([]byte, error) {
	request, err := proof.Parse(original)
	if err != nil {
		return nil, err
	}
	canonical, err := proof.Canonical(request)
	if err != nil || !bytes.Equal(original, canonical) {
		return nil, errors.New("request_mismatch")
	}
	status, needs, err := proof.MakeNeedsHuman(request, c.Origin)
	if err != nil {
		return nil, err
	}
	body, err := proof.Canonical(needs)
	if err != nil {
		return nil, err
	}
	if receipt != nil {
		s, err := c.From428(body, status)
		if err != nil {
			return nil, err
		}
		if err = s.live(); err != nil {
			return nil, err
		}
		if receipt["request_bytes"] != base64.RawURLEncoding.EncodeToString(original) {
			return nil, errors.New("request_mismatch")
		}
		return proof.Canonical(map[string]any{"version": 1, "request_bytes": receipt["request_bytes"], "receipt": receipt})
	}
	return c.Complete428(ctx, body, status)
}
