package approval

import (
	"bytes"
	"crypto/ed25519"
	proof "github.com/awebai/approval-service/verify"
	"github.com/awebai/aw/awid"
	"io"
	"net/http"
	"testing"
	"time"
)

func TestBindingRefreshUsesTheSharedOwnPersonHTTPProof(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, 32))
	requester := map[string]any{"kind": "identity", "id": awid.ComputeStableID(key.Public().(ed25519.PublicKey)), "key": awid.ComputeDIDKey(key.Public().(ed25519.PublicKey))}
	raw := []byte(`{"binding":{"opaque":"kept"},"id_chain":[],"previous_binding_commitment":"sha256:original","requester":{"id":"carrier"},"version":1}`)
	now := time.Unix(1795040000, 0)
	client := &Client{Origin: "https://awsign.example", Key: key, Requester: requester, Now: func() time.Time { return now }}
	req, err := client.SignedRequest(t.Context(), PurposeBindingRefresh, raw)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(body, raw) {
		t.Fatal("changed packet bytes")
	}
	_, err = proof.CheckHTTP(req.Header.Get("Authorization"), body, proof.HTTPInput{Requester: requester, Origin: client.Origin, Method: http.MethodPost, Path: "/v1/enrollment-bindings/refresh", Purpose: PurposeBindingRefresh, Now: now.Unix()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = proof.CheckHTTP(req.Header.Get("Authorization"), append(body, 'x'), proof.HTTPInput{Requester: requester, Origin: client.Origin, Method: http.MethodPost, Path: req.URL.Path, Purpose: PurposeBindingRefresh, Now: now.Unix()}); err == nil {
		t.Fatal("accepted changed packet")
	}
}
