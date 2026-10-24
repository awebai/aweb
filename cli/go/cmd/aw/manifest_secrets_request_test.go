package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/awebai/aw/internal/appmanifest"
)

// Exercise the real manifest and generic CLI parser, without a broker stand-in.
// Server admission, approval and resubmission are checked in the service tests.
func TestSecretsRequestManifestEncoding(t *testing.T) {
	resolved, _ := secretsRunManifest(t)
	tool, err := installedAgentTool(resolved, "request")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		flags []string
		body  string
	}{
		{
			name: "named",
			flags: []string{
				"--operation", "create-refund",
				"--params", `{"charge":"ch_example","amount_minor":500}`,
				"--reason", "refund requested by customer",
			},
			body: `{"request_id":"request-1","operation":"create-refund","params":{"charge":"ch_example","amount_minor":500},"reason":"refund requested by customer"}`,
		},
		{
			name: "open",
			flags: []string{
				"--method", "POST", "--url", "https://upstream.example/events?kind=build",
				"--headers", `["Content-Type: application/json","X-Event: build","X-Event: verify"]`,
				"--data", `{"event":"build","sequence":2}`,
			},
			body: `{"request_id":"request-1","method":"POST","url":"https://upstream.example/events?kind=build","headers":["Content-Type: application/json","X-Event: build","X-Event: verify"],"data":"{\"event\":\"build\",\"sequence\":2}"}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			flags := append([]string{"--secret", "example-ref", "--request_id", "request-1"}, tc.flags...)
			var previous []byte
			// An explicit second invocation carries the same logical request.
			// This does not assert that a repeated invocation dispatches again.
			for range 2 {
				args, rawBody, err := parseManifestDispatchArgs(flags)
				if err != nil {
					t.Fatal(err)
				}
				if err := validateManifestDispatchArgs("secrets", tool, args); err != nil {
					t.Fatal(err)
				}
				spec, err := appmanifest.Interpret(appmanifest.InterpretRequest{
					Manifest: resolved.Manifest, Verb: "request", Args: args, RawBody: rawBody,
				})
				if err != nil {
					t.Fatal(err)
				}
				if spec.Method != "POST" || spec.PathQuery != "/v1/secrets/example-ref/requests" || spec.Auth != "team-cert" {
					t.Fatalf("unexpected broker routing/auth: %+v", spec)
				}
				var got, want any
				if err := json.Unmarshal(spec.Body, &got); err != nil {
					t.Fatal(err)
				}
				if err := json.Unmarshal([]byte(tc.body), &want); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("broker body = %#v, want %#v", got, want)
				}
				if previous != nil && !bytes.Equal(previous, spec.Body) {
					t.Fatal("explicit resubmission changed the encoded request")
				}
				previous = spec.Body
			}
		})
	}
}

func TestSecretsStatusManifestIsAnAuthenticatedRead(t *testing.T) {
	resolved, _ := secretsRunManifest(t)
	spec, err := appmanifest.Interpret(appmanifest.InterpretRequest{
		Manifest: resolved.Manifest, Verb: "status", Args: map[string]any{"ref": "request-1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if spec.Method != "GET" || spec.PathQuery != "/v1/status/request-1" || spec.Auth != "team-cert" || spec.Mutation || len(spec.Body) != 0 {
		t.Fatalf("unexpected status request: %+v", spec)
	}
}

// Typed tool arguments and a CLI JSON body file must preserve the same body
// types, including object data and the optional run selector. This exercises
// request construction only; hosted MCP invocation is separate acceptance.
func TestSecretsTypedArgumentsAndCLIFilePreserveTheSameBody(t *testing.T) {
	resolved, _ := secretsRunManifest(t)
	for _, tc := range []struct {
		name, verb, pathFlag, pathValue, path, body string
	}{
		{
			name: "named", verb: "request", pathFlag: "secret", pathValue: "example-ref",
			path: "/v1/secrets/example-ref/requests",
			body: `{"request_id":"request-1","operation":"create-refund","params":{"amount_minor":500},"headers":["X-Request-Label: refund"],"reason":"refund requested"}`,
		},
		{
			name: "open-object", verb: "request", pathFlag: "secret", pathValue: "example-ref",
			path: "/v1/secrets/example-ref/requests",
			body: `{"request_id":"request-2","method":"POST","url":"https://upstream.example/events","headers":["Content-Type: application/json"],"data":{"event":"build","sequence":2}}`,
		},
		{
			name: "run-fixed", verb: "run", pathFlag: "job", pathValue: "nightly-backup",
			path: "/v1/jobs/nightly-backup/runs",
			body: `{"request_id":"run-1","runner":"run_home001","params":{"environment":"staging"},"reason":"nightly backup"}`,
		},
		{
			name: "run-child", verb: "run", pathFlag: "job", pathValue: "nightly-backup",
			path: "/v1/jobs/nightly-backup/runs",
			body: `{"request_id":"run-2","runner":"run_home001","params":{},"secret":"issued-child"}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var typed map[string]any
			if err := json.Unmarshal([]byte(tc.body), &typed); err != nil {
				t.Fatal(err)
			}
			typed[tc.pathFlag] = tc.pathValue
			bodyFile := filepath.Join(t.TempDir(), "request.json")
			if err := os.WriteFile(bodyFile, []byte(tc.body), 0600); err != nil {
				t.Fatal(err)
			}
			cliArgs, rawBody, err := parseManifestDispatchArgs([]string{
				"--" + tc.pathFlag, tc.pathValue, "--body-file", bodyFile,
			})
			if err != nil {
				t.Fatal(err)
			}
			tool, err := installedAgentTool(resolved, tc.verb)
			if err != nil {
				t.Fatal(err)
			}
			if err := validateManifestDispatchArgs("secrets", tool, cliArgs); err != nil {
				t.Fatal(err)
			}
			var first []byte
			for _, input := range []appmanifest.InterpretRequest{
				{Manifest: resolved.Manifest, Verb: tc.verb, Args: typed},
				{Manifest: resolved.Manifest, Verb: tc.verb, Args: cliArgs, RawBody: rawBody},
			} {
				spec, err := appmanifest.Interpret(input)
				if err != nil {
					t.Fatal(err)
				}
				if spec.Method != "POST" || spec.PathQuery != tc.path || spec.Auth != "team-cert" || !spec.Mutation {
					t.Fatalf("unexpected tool request: %+v", spec)
				}
				var got, want any
				if err := json.Unmarshal(spec.Body, &got); err != nil {
					t.Fatal(err)
				}
				if err := json.Unmarshal([]byte(tc.body), &want); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("tool body = %#v, want %#v", got, want)
				}
				if first != nil && !bytes.Equal(first, spec.Body) {
					t.Fatal("typed arguments and CLI file encoded different bodies")
				}
				first = spec.Body
			}
		})
	}
}
