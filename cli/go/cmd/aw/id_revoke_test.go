package main

import (
	"context"
	"errors"
	"testing"
)

// The registry-backed revocations (self, parent, root and the outsiders'
// view of them) run in scripts/cross-registry-human-journey.py, whose AWID
// checks the namespace's real DNS. These refusals happen before any
// signer is selected or any request is sent: nothing here resolves a name
// or prompts.

func TestIDRevokeRefusesBeforeSigning(t *testing.T) {
	const target = "did:aw:3YDAM5ZLRKg7eHH1Zs6sSMwkga8w"
	prompted := 0
	opts := idChildOptions{
		WorkingDir:  t.TempDir(),
		RegistryURL: "http://127.0.0.1:1",
		Prompt: func(string) ([]byte, error) {
			prompted++
			return nil, errors.New("nothing is signed")
		},
	}
	for name, tc := range map[string]struct {
		issuer         childIssuerSelection
		target, cutoff string
	}{
		"a cutoff from the current identity": {childIssuerSelection{}, target, "2026-10-26T00:00:00Z"},
		"a cutoff from a human":              {childIssuerSelection{Human: target, Domain: "example.com"}, target, "2026-10-26T00:00:00Z"},
		"a cutoff the root cannot parse":     {childIssuerSelection{AsRoot: true, Domain: "example.com"}, target, "yesterday"},
		"a local did:key":                    {childIssuerSelection{AsRoot: true, Domain: "example.com"}, "did:key:z6Mkon3Necd6NkkyfoGoHxid2znGc59LU3K7mubaRcFbLfLX", ""},
		"no target":                          {childIssuerSelection{AsRoot: true, Domain: "example.com"}, " ", ""},
	} {
		t.Run(name, func(t *testing.T) {
			opts.Issuer = tc.issuer
			_, err := executeIDRevoke(context.Background(), opts, tc.target, tc.cutoff)
			if exitCode(err) != 2 || prompted != 0 {
				t.Fatalf("err=%v prompted=%d", err, prompted)
			}
		})
	}
}

// The root's cutoff reaches AWID as its wire time: UTC with microseconds.
func TestIDRevokeCutoffIsTheWireTime(t *testing.T) {
	for in, want := range map[string]string{
		"2026-10-30T10:00:00+02:00":      "2026-10-30T08:00:00.000000Z",
		"2026-10-30T08:00:00.123456789Z": "2026-10-30T08:00:00.123456Z",
		"2026-10-30T08:00:00.5-00:30":    "2026-10-30T08:30:00.500000Z",
	} {
		got, err := idRevokeWireTime(in)
		if err != nil || got != want {
			t.Fatalf("%s: %q %v, want %q", in, got, err, want)
		}
	}
}
