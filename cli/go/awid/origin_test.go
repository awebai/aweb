package awid

import "testing"

func TestCanonicalServerOrigin(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"https://Aweb.Example.com/":    "https://aweb.example.com",
		"https://aweb.example.com:443": "https://aweb.example.com",
		"http://localhost:8000":        "http://localhost:8000",
	}
	for raw, want := range cases {
		got, err := CanonicalServerOrigin(raw)
		if err != nil {
			t.Fatalf("CanonicalServerOrigin(%q): %v", raw, err)
		}
		if got != want {
			t.Fatalf("CanonicalServerOrigin(%q)=%q want %q", raw, got, want)
		}
	}
}

func TestCanonicalServerOriginRejectsPath(t *testing.T) {
	t.Parallel()

	if _, err := CanonicalServerOrigin("https://app.aweb.ai/api"); err == nil {
		t.Fatal("expected path rejection")
	}
}
