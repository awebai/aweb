// Real SDK requests; every response comes from the listening aweb application.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/awebai/aw/awid"
)

type authority struct {
	URL, DID, StableID, Key, Certificate, SessionID, Recipient string
}
type checkedTransport struct {
	mutate bool
	count  int
}

func (t *checkedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Header.Get("Authorization") != "" {
		data, err := base64.RawURLEncoding.DecodeString(r.Header.Get("X-AWEB-Signed-Payload"))
		if err != nil {
			return nil, err
		}
		var payload map[string]any
		if err := json.Unmarshal(data, &payload); err != nil {
			return nil, err
		}
		if payload["v"] != float64(2) {
			return nil, fmt.Errorf("request is not v2")
		}
		t.count++
		if t.mutate {
			r.URL.RawQuery += "&retargeted=1"
		}
	}
	return http.DefaultTransport.RoundTrip(r)
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		return err
	}
	var a authority
	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}
	seed, err := base64.StdEncoding.DecodeString(a.Key)
	if err != nil {
		return err
	}
	key := ed25519.NewKeyFromSeed(seed)
	var client *awid.Client
	if a.Certificate != "" {
		cert, e := awid.DecodeTeamCertificateHeader(a.Certificate)
		if e != nil {
			return e
		}
		client, err = awid.NewWithCertificate(a.URL, key, cert)
	} else {
		client, err = awid.NewWithIdentity(a.URL, key, a.DID)
		if err == nil {
			client.SetStableID(a.StableID)
		}
	}
	if err != nil {
		return err
	}
	transport := &checkedTransport{}
	network := &http.Client{Transport: transport}
	client.SetHTTPClient(network)
	client.SetSSEClient(network)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := client.Get(ctx, "/v1/messages/inbox?limit=1&opaque=a%2Fb", nil); err != nil {
		return err
	}
	var result map[string]any
	if err := client.Post(ctx, "/v1/messages", map[string]string{"to_did": a.Recipient, "subject": "bound", "body": "real SDK"}, &result); err != nil {
		return err
	}
	after := time.Now().Add(-time.Minute)
	stream, err := client.ChatStream(ctx, a.SessionID, time.Now().Add(2*time.Second), &after)
	if err != nil {
		return err
	}
	if _, err := stream.Next(); err != nil {
		stream.Close()
		return fmt.Errorf("chat stream read: %w", err)
	}
	stream.Close()
	events, err := client.EventStream(ctx, time.Now().Add(time.Second))
	if a.Certificate == "" {
		if code, ok := awid.HTTPStatusCode(err); !ok || code != 401 {
			return fmt.Errorf("identity-only must not gain team event authority: %v", err)
		}
	} else {
		if err != nil {
			return err
		}
		if _, err := events.Next(ctx); err != nil {
			events.Close()
			return err
		}
		events.Close()
	}
	transport.mutate = true
	err = client.Get(ctx, "/v1/messages/inbox?limit=1", nil)
	if code, ok := awid.HTTPStatusCode(err); !ok || code != 401 {
		return fmt.Errorf("retargeted request: %v", err)
	}
	if transport.count != 5 {
		return fmt.Errorf("authenticated request count=%d, want5", transport.count)
	}
	fmt.Println(`{"v2_requests":5,"retargeted_status":401}`)
	return nil
}
