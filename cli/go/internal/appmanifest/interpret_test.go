package appmanifest

import (
	"strings"
	"testing"
)

func TestInterpretFailClosedValidationBeforeRequestConstruction(t *testing.T) {
	manifest := Manifest{
		ManifestVersion: 1,
		App:             App{ID: "safe", Version: "1.0.0", Origin: "https://app.example"},
		Tools: []Tool{{
			Name:        "x",
			Method:      "POST",
			Path:        "/v1/{slug}",
			InputSchema: map[string]any{"type": "object", "properties": map[string]any{"slug": map[string]any{"type": "string"}, "title": map[string]any{"type": "string"}}},
			Params:      []Param{{Name: "slug", In: "query"}},
			Body:        Body{Mode: "json"},
		}},
	}
	_, err := Interpret(InterpretRequest{Manifest: manifest, Verb: "x", Args: map[string]any{"slug": "pitch", "title": "deck"}})
	if err == nil {
		t.Fatal("expected malformed manifest to fail before request construction")
	}
	for _, want := range []string{"missing params placement", "placeholder", "path param"} {
		if strings.Contains(err.Error(), want) {
			return
		}
	}
	t.Fatalf("unexpected validation error: %v", err)
}

func TestValidateRawModeRequiresRawParam(t *testing.T) {
	manifest := Manifest{
		ManifestVersion: 1,
		App:             App{ID: "safe", Version: "1.0.0", Origin: "https://app.example"},
		Tools: []Tool{{
			Name:        "append",
			Method:      "POST",
			Path:        "/v1/documents",
			InputSchema: map[string]any{"type": "object", "properties": map[string]any{"body": map[string]any{"type": "string"}}},
			Params:      []Param{{Name: "body", In: "body"}},
			Body:        Body{Mode: "raw", ContentType: "text/plain"},
		}},
	}
	if err := Validate(manifest, nil); err == nil || !strings.Contains(err.Error(), "raw_param") {
		t.Fatalf("Validate() error = %v, want raw_param", err)
	}
}

func TestValidateRejectsParamWithoutSchemaProperty(t *testing.T) {
	cases := []struct {
		name        string
		inputSchema map[string]any
	}{
		{name: "missing input_schema", inputSchema: nil},
		{name: "empty properties", inputSchema: map[string]any{"type": "object", "properties": map[string]any{}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			manifest := Manifest{
				ManifestVersion: 1,
				App:             App{ID: "safe", Version: "1.0.0", Origin: "https://app.example"},
				Tools: []Tool{{
					Name:        "present",
					Method:      "POST",
					Path:        "/v1/present",
					InputSchema: tc.inputSchema,
					Params:      []Param{{Name: "slug", In: "body"}},
					Body:        Body{Mode: "json"},
				}},
			}
			if err := Validate(manifest, nil); err == nil || !strings.Contains(err.Error(), "not declared in input_schema") {
				t.Fatalf("Validate() error = %v, want undeclared input_schema param", err)
			}
		})
	}
}

func TestValidateRejectsPathQueryAndFragment(t *testing.T) {
	cases := []struct {
		name string
		path string
		want string
	}{
		{name: "query", path: "/v1/x?fixed=1", want: "query"},
		{name: "fragment", path: "/v1/x#frag", want: "fragment"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			manifest := Manifest{
				ManifestVersion: 1,
				App:             App{ID: "safe", Version: "1.0.0", Origin: "https://app.example"},
				Tools: []Tool{{
					Name:        "x",
					Method:      "GET",
					Path:        tc.path,
					InputSchema: map[string]any{"type": "object", "properties": map[string]any{}},
					Params:      []Param{},
					Body:        Body{Mode: "json"},
				}},
			}
			if err := Validate(manifest, nil); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate() error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestValidateAuthNoneIsOptionalAndReadOnly(t *testing.T) {
	manifest := Manifest{
		ManifestVersion: 1,
		App:             App{ID: "library", Version: "1.0.0", Origin: "https://library.example"},
		Tools: []Tool{{
			Name:        "list-blueprints",
			Method:      "GET",
			Path:        "/v1/blueprints",
			InputSchema: map[string]any{"type": "object", "properties": map[string]any{}},
			Params:      []Param{},
			Auth:        "none",
			Mutation:    false,
		}},
	}
	if err := Validate(manifest, nil); err != nil {
		t.Fatalf("Validate(auth:none read) error = %v", err)
	}
	got, err := Interpret(InterpretRequest{Manifest: manifest, Verb: "list-blueprints"})
	if err != nil {
		t.Fatal(err)
	}
	if got.Auth != "none" {
		t.Fatalf("interpreted auth=%q want none", got.Auth)
	}

	manifest.Tools[0].Mutation = true
	if err := Validate(manifest, nil); err == nil || !strings.Contains(err.Error(), "auth:none") {
		t.Fatalf("Validate(auth:none mutation) error = %v, want auth:none rejection", err)
	}

	manifest.Tools[0].Mutation = false
	manifest.Tools[0].Auth = "oauth"
	if err := Validate(manifest, nil); err == nil || !strings.Contains(err.Error(), "unsupported auth") {
		t.Fatalf("Validate(unsupported auth) error = %v, want unsupported auth", err)
	}

	// A present-but-whitespace-only auth is malformed: rejected as unsupported,
	// not trimmed to "" and normalized to team-cert (parity with AC; aabq.12).
	manifest.Tools[0].Auth = "   "
	if err := Validate(manifest, nil); err == nil || !strings.Contains(err.Error(), "unsupported auth") {
		t.Fatalf("Validate(whitespace-only auth) error = %v, want unsupported auth", err)
	}

	manifest.Tools[0].Auth = ""
	got, err = Interpret(InterpretRequest{Manifest: manifest, Verb: "list-blueprints"})
	if err != nil {
		t.Fatal(err)
	}
	if got.Auth != "team-cert" {
		t.Fatalf("default auth=%q want team-cert", got.Auth)
	}
}

func TestValidateRejectsUndeclaredSchemaPlacement(t *testing.T) {
	manifest := Manifest{
		ManifestVersion: 1,
		App:             App{ID: "safe", Version: "1.0.0", Origin: "https://app.example"},
		Tools: []Tool{{
			Name:        "present",
			Method:      "POST",
			Path:        "/v1/present",
			InputSchema: map[string]any{"type": "object", "properties": map[string]any{"slug": map[string]any{"type": "string"}, "ttl": map[string]any{"type": "integer"}}},
			Params:      []Param{{Name: "slug", In: "body"}},
			Body:        Body{Mode: "json"},
		}},
	}
	if err := Validate(manifest, nil); err == nil || !strings.Contains(err.Error(), "ttl") {
		t.Fatalf("Validate() error = %v, want missing ttl placement", err)
	}
}
