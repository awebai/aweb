package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/awebai/aw/awid"
)

func TestDirectTrustRequestsDoNotFollowRedirects(t *testing.T) {
	memberPublicKey, memberKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	memberDID := awid.ComputeDIDKey(memberPublicKey)
	teamPublicKey, teamKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	cert := &awid.TeamCertificate{
		Version:       1,
		CertificateID: "cert-test",
		Team:          "default:example.com",
		TeamDIDKey:    awid.ComputeDIDKey(teamPublicKey),
		MemberDIDKey:  memberDID,
		Alias:         "alice",
		IdentityScope: awid.IdentityModeGlobal,
		IssuedAt:      "2026-07-25T00:00:00Z",
		Signature:     "test-signature",
	}

	tests := []struct {
		name             string
		expectsAuthority bool
		invoke           func(sourceURL string) error
	}{
		{
			name:             "connect",
			expectsAuthority: true,
			invoke: func(sourceURL string) error {
				_, err := postConnect(context.Background(), sourceURL, memberKey, cert, connectRequest{})
				return err
			},
		},
		{
			name:             "local identity key replacement",
			expectsAuthority: true,
			invoke: func(sourceURL string) error {
				_, err := postLocalIdentityKeyReplacementOnce(context.Background(), sourceURL, "alice", localIdentityKeyReplacementRequest{TeamID: cert.Team}, teamKey)
				return err
			},
		},
		{
			name:             "hosted team member removal",
			expectsAuthority: true,
			invoke: func(sourceURL string) error {
				_, err := postHostedTeamRemoveMember(context.Background(), sourceURL, "secret-api-key", cert.Team, hostedTeamRemoveMemberRequest{CertificateID: cert.CertificateID})
				return err
			},
		},
		{
			name: "team service registration",
			invoke: func(sourceURL string) error {
				return postTeamRegister(context.Background(), sourceURL, map[string]any{"controller_signature": "signed-authority"}, &map[string]any{})
			},
		},
		{
			name: "BYOT cleanup",
			invoke: func(sourceURL string) error {
				return postTeamCleanupCloud(context.Background(), sourceURL, map[string]any{"controller_signature": "signed-authority"}, &map[string]any{})
			},
		},
		{
			name:             "API key workspace init",
			expectsAuthority: true,
			invoke: func(sourceURL string) error {
				_, err := postAPIKeyWorkspaceInit(context.Background(), sourceURL, "secret-api-key", apiKeyBootstrapRequest{})
				return err
			},
		},
		{
			name: "public runnable profile",
			invoke: func(sourceURL string) error {
				_, err := fetchPublicLibraryProfile(context.Background(), libraryProfileSelector{
					LibraryURL:         sourceURL,
					SourceBlueprintRef: "aweb.team",
					ProfileRef:         "developer",
				})
				return err
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var targetHits atomic.Int32
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				targetHits.Add(1)
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{}`))
			}))
			t.Cleanup(target.Close)

			var sourceHits atomic.Int32
			source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				sourceHits.Add(1)
				if test.expectsAuthority && r.Header.Get("Authorization") == "" {
					t.Error("production request did not carry the expected authority header")
				}
				http.Redirect(w, r, target.URL+r.URL.Path, http.StatusTemporaryRedirect)
			}))
			t.Cleanup(source.Close)

			_ = test.invoke(source.URL)
			if sourceHits.Load() != 1 {
				t.Fatalf("redirect source received %d requests, want 1", sourceHits.Load())
			}
			if targetHits.Load() != 0 {
				t.Fatalf("redirect target received %d requests, want 0", targetHits.Load())
			}
		})
	}
}

func TestDirectTrustRequestsEnforcePinnedBoundAndStrictJSON(t *testing.T) {
	const pinnedTrustResponseLimit = 10 * 1024 * 1024
	if awid.MaxResponseSize != pinnedTrustResponseLimit {
		t.Fatalf("MaxResponseSize=%d, security policy requires %d", awid.MaxResponseSize, pinnedTrustResponseLimit)
	}
	tests := []struct {
		name           string
		responsePrefix string
		invoke         func(sourceURL string) error
	}{
		{name: "hosted team member removal", invoke: func(sourceURL string) error {
			_, err := postHostedTeamRemoveMember(context.Background(), sourceURL, "secret-api-key", "default:example.com", hostedTeamRemoveMemberRequest{CertificateID: "cert-test"})
			return err
		}},
		{name: "team service registration", invoke: func(sourceURL string) error {
			return postTeamRegister(context.Background(), sourceURL, map[string]any{"controller_signature": "signed-authority"}, &map[string]any{})
		}},
		{name: "BYOT cleanup", invoke: func(sourceURL string) error {
			return postTeamCleanupCloud(context.Background(), sourceURL, map[string]any{"controller_signature": "signed-authority"}, &map[string]any{})
		}},
		{name: "API key workspace init", invoke: func(sourceURL string) error {
			_, err := postAPIKeyWorkspaceInit(context.Background(), sourceURL, "secret-api-key", apiKeyBootstrapRequest{})
			return err
		}},
		{name: "public runnable profile", responsePrefix: `{"blueprint_ref":"aweb.team","blueprint_version":"1","profile_ref":"developer","version":"1","digest":"digest","files":[{"path":"AGENTS.md","content_utf8":"x"}]}`, invoke: func(sourceURL string) error {
			_, err := fetchPublicLibraryProfile(context.Background(), libraryProfileSelector{LibraryURL: sourceURL, SourceBlueprintRef: "aweb.team", ProfileRef: "developer"})
			return err
		}},
	}
	variants := []struct {
		name      string
		body      func(string) []byte
		wantError bool
	}{
		{name: "exact limit", body: func(prefix string) []byte {
			return append([]byte(prefix), bytes.Repeat([]byte(" "), pinnedTrustResponseLimit-len(prefix))...)
		}},
		{name: "limit plus one valid prefix", body: func(prefix string) []byte {
			return append([]byte(prefix), bytes.Repeat([]byte(" "), pinnedTrustResponseLimit+1-len(prefix))...)
		}, wantError: true},
		{name: "trailing JSON document", body: func(prefix string) []byte {
			return []byte(prefix + ` {}`)
		}, wantError: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			prefix := test.responsePrefix
			if prefix == "" {
				prefix = `{}`
			}
			for _, variant := range variants {
				t.Run(variant.name, func(t *testing.T) {
					server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						w.Header().Set("Content-Type", "application/json")
						_, _ = w.Write(variant.body(prefix))
					}))
					t.Cleanup(server.Close)
					err := test.invoke(server.URL)
					if variant.wantError && err == nil {
						t.Fatal("malicious response was accepted")
					}
					if !variant.wantError && err != nil {
						t.Fatalf("exact-limit response was rejected: %v", err)
					}
				})
			}
		})
	}
}
