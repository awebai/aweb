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
