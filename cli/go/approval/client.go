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
)

// Client carries the shared awsign protocol over HTTPS. The shared verifier
// owns packet/signature/answer rules; this client owns transport and retention.

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
	// ResponseLimit bounds a service answer; zero retains the released 1 MiB default.
	ResponseLimit int64
	Notify        io.Writer
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

// SignedRequest validates and signs an exact shared HTTP-purpose packet.
// The returned request is not evidence of service acceptance or an effect.
func (c *Client) SignedRequest(ctx context.Context, purpose string, body []byte) (*http.Request, error) {
	origin, e := url.Parse(c.Origin)
	if e != nil || origin.Scheme != "https" || origin.Host == "" || origin.User != nil || origin.Path != "" || origin.RawQuery != "" || origin.Fragment != "" {
		return nil, errors.New("approval_origin_invalid")
	}
	kind, err := checkedPurpose(purpose)
	if err != nil {
		return nil, err
	}
	path := routes[kind]
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

// Session retains the original request bytes and the shared verifier's answer.
// Exported Request is a data view; live timing/requester facts are snapshotted
// from the checked original and cannot be extended by mutating that view.
type Session struct {
	client             *Client
	RequestBytes       []byte
	Request            map[string]any
	Digest             string
	Locator            string
	answer             map[string]any
	status             int
	answerKind         RequestPurpose
	answerState        answerState
	notBefore          int64
	deadline           int64
	requesterCanonical []byte
}

// From428 checks the shared needs-human packet and snapshots its original request.
func (c *Client) From428(raw []byte, status int) (*Session, error) {
	value, e := proof.Parse(raw)
	if e != nil {
		return nil, e
	}
	request, e := proof.ReadNeedsHuman(value, c.Requester, c.Origin, c.now().Unix(), int64(status))
	if e != nil {
		return nil, e
	}
	encoded, e := checkedStringField(value, "request_bytes")
	if e != nil {
		return nil, e
	}
	original, e := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if e != nil {
		return nil, e
	}
	digest, e := checkedStringField(value, "digest")
	if e != nil {
		return nil, e
	}
	notBefore, e := checkedIntegerField(request, "not_before")
	if e != nil {
		return nil, e
	}
	deadline, e := checkedIntegerField(request, "deadline")
	if e != nil {
		return nil, e
	}
	requester, e := proof.Canonical(request["requester"])
	if e != nil {
		return nil, e
	}
	return &Session{client: c, RequestBytes: original, Request: request,
		Digest: digest, notBefore: notBefore, deadline: deadline,
		requesterCanonical: requester}, nil
}

// Submission carries the unchanged request and requester admission.
func (s *Session) Submission() map[string]any {
	return map[string]any{"version": 1, "request_bytes": base64.RawURLEncoding.EncodeToString(s.RequestBytes), "admission": s.client.Admission}
}

// Selection identifies the same submitted request for polling or cancellation.
func (s *Session) Selection() map[string]any {
	return map[string]any{"version": 1, "request_bytes": base64.RawURLEncoding.EncodeToString(s.RequestBytes), "admission": s.client.Admission, "locator": s.Locator, "digest": s.Digest}
}

// ReadAnswer uses the shared answer reader before retaining any answer fields.
func (s *Session) ReadAnswer(kind string, raw []byte, status int) (map[string]any, error) {
	answer, e := proof.ReadAnswerJSON(kind, raw, proof.AnswerInput{Status: status, RequestBytes: s.RequestBytes, Locator: s.Locator})
	if e != nil {
		return nil, e
	}
	locator, e := checkedStringField(answer, "locator")
	if e != nil {
		return nil, e
	}
	state, e := checkedStringField(answer, "state")
	if e != nil {
		return nil, e
	}
	purpose, e := checkedPurpose(kind)
	if e != nil {
		return nil, e
	}
	s.Locator = locator
	s.answer = answer
	s.status = status
	s.answerKind = purpose
	s.answerState = answerState(state)
	return answer, nil
}

// NeedsPoll distinguishes a decision summary from the raw approval bundle.
func (s *Session) NeedsPoll() bool {
	return s.answerKind == purposeSubmit || s.answerState == answerPending
}

// Receipt assembles historical evidence, without claiming a live effect.
func (s *Session) Receipt() (map[string]any, error) {
	return proof.AssembleReceipt(s.RequestBytes, s.answer, proof.AnswerInput{Status: s.status, Locator: s.Locator})
}

// Presentation serializes the original request and checked receipt together.
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
	limit := c.ResponseLimit
	if limit <= 0 {
		limit = 1 << 20
	}
	answer, err := sendApprovalRequest(approvalHTTPRequest{Request: req, Client: c.HTTP, ResponseLimit: limit})
	if err != nil {
		return nil, 0, err
	}
	return answer.Body, answer.Status, nil
}

func (s *Session) live() error {
	now := s.client.now().Unix()
	if now < s.notBefore || now >= s.deadline {
		return errors.New("request_expired")
	}
	actual, e := proof.Canonical(s.client.Requester)
	if e != nil {
		return e
	}
	if !bytes.Equal(s.requesterCanonical, actual) {
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
	if e = c.Retain(string(retainRequest), s.RequestBytes); e != nil {
		return nil, e
	}
	ctx, cancel := context.WithDeadline(ctx, time.Unix(s.deadline, 0))
	defer cancel()
	purpose, payload := purposeSubmit, s.Submission()
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
		answer, status, e := c.exchange(ctx, string(purpose), payload)
		if e != nil {
			return nil, e
		}
		if purpose == purposePoll && (status == http.StatusTooManyRequests || status >= 500 && status < 600) {
			if e = wait(); e != nil {
				return nil, e
			}
			continue
		}
		if _, e = s.ReadAnswer(string(purpose), answer, status); e != nil {
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
			if err = c.Retain(string(retainReceipt), saved); err != nil {
				return nil, err
			}
			if err = s.live(); err != nil {
				return nil, err
			}
			return s.Presentation()
		}
		if purpose == purposeSubmit {
			purpose, payload = purposePoll, s.Selection()
			continue
		}
		if !notified && c.Notify != nil {
			if _, err := fmt.Fprintln(c.Notify, "Waiting for human approval at the person's known approval service."); err != nil {
				return nil, fmt.Errorf("Approval is still pending, but its status could not be written. Retry the retained request: %w", err)
			}
			notified = true
		}
		if e = wait(); e != nil {
			return nil, e
		}
		purpose, payload = purposePoll, s.Selection()
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
