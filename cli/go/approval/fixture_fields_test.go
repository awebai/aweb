package approval

import (
	"encoding/json"
	"testing"
)

func fixtureObject(t *testing.T, value any) map[string]any {
	t.Helper()
	object, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("frozen fixture needs a JSON object, got %T", value)
	}
	return object
}

func fixtureText(t *testing.T, value any) string {
	t.Helper()
	text, ok := value.(string)
	if !ok {
		t.Fatalf("frozen fixture needs a string, got %T", value)
	}
	return text
}

func fixtureInteger(t *testing.T, value any) int64 {
	t.Helper()
	number, ok := value.(json.Number)
	if !ok {
		t.Fatalf("frozen fixture needs an integer, got %T", value)
	}
	result, err := number.Int64()
	if err != nil {
		t.Fatalf("frozen fixture integer: %v", err)
	}
	return result
}
