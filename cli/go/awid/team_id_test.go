package awid

import "testing"

func TestBuildTeamID(t *testing.T) {
	t.Parallel()

	if got := BuildTeamID("Acme.COM.", "Backend"); got != "backend:acme.com" {
		t.Fatalf("BuildTeamID()=%q", got)
	}
}

func TestParseTeamID(t *testing.T) {
	t.Parallel()

	domain, name, err := ParseTeamID("Backend:Acme.COM.")
	if err != nil {
		t.Fatalf("ParseTeamID() error=%v", err)
	}
	if domain != "acme.com" {
		t.Fatalf("domain=%q", domain)
	}
	if name != "backend" {
		t.Fatalf("name=%q", name)
	}
}

func TestParseTeamIDRejectsSlashForm(t *testing.T) {
	t.Parallel()

	if _, _, err := ParseTeamID("acme.com/backend"); err == nil {
		t.Fatal("expected slash-form team identifier to fail")
	}
}
