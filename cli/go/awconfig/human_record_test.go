package awconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHumanRecordLivesInItsOwnDirectoryUnderTheDomain(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	rec := &HumanRecord{StableID: "did:aw:3YDAM5ZLRKg7eHH1Zs6sSMwkga8w", DIDKey: "did:key:z6Mkon3Necd6NkkyfoGoHxid2znGc59LU3K7mubaRcFbLfLX", Domain: "example.com", RegistryURL: "https://registry.example.com", State: HumanPrepared}
	if err := SaveHumanRecord(rec); err != nil {
		t.Fatal(err)
	}
	dir, err := HumanRecordDir("example.com", rec.StableID)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(home, ".awid", "humans", "example.com", "3YDAM5ZLRKg7eHH1Zs6sSMwkga8w"); dir != want {
		t.Fatalf("dir %s want %s", dir, want)
	}
	info, err := os.Stat(dir)
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("record dir mode: %v %v", info, err)
	}
	loaded, err := LoadHumanRecord("example.com", rec.StableID)
	if err != nil || *loaded != *rec {
		t.Fatalf("loaded %+v (%v)", loaded, err)
	}
	all, err := HumanRecords("example.com")
	if err != nil || len(all) != 1 || all[0].StableID != rec.StableID {
		t.Fatalf("records %+v (%v)", all, err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "identity.yaml"))
	if err != nil || !strings.Contains(string(data), rec.StableID) {
		t.Fatalf("identity.yaml: %s (%v)", data, err)
	}
}

func TestHumanRecordsAreSeparatePerID(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	first := &HumanRecord{StableID: "did:aw:3YDAM5ZLRKg7eHH1Zs6sSMwkga8w", DIDKey: "did:key:a", Domain: "example.com", State: HumanRegistered}
	second := &HumanRecord{StableID: "did:aw:2e2SPDJNyxg5Dt6EFJX3Tcn8Tauj", DIDKey: "did:key:b", Domain: "example.com", State: HumanPrepared}
	for _, rec := range []*HumanRecord{first, second} {
		if err := SaveHumanRecord(rec); err != nil {
			t.Fatal(err)
		}
	}
	if loaded, err := LoadHumanRecord("example.com", first.StableID); err != nil || *loaded != *first {
		t.Fatalf("a second human overwrote the first: %+v (%v)", loaded, err)
	}
	if all, err := HumanRecords("example.com"); err != nil || len(all) != 2 {
		t.Fatalf("records %d (%v)", len(all), err)
	}
}

func TestHumanRecordRefusesAMismatchedOrInvalidID(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	for _, id := range []string{"did:key:z6Mkon3Necd6NkkyfoGoHxid2znGc59LU3K7mubaRcFbLfLX", "did:aw:../escape", "did:aw:"} {
		if err := SaveHumanRecord(&HumanRecord{StableID: id, Domain: "example.com"}); err == nil {
			t.Fatalf("saved a record for %q", id)
		}
	}
	if loaded, err := LoadHumanRecord("example.com", "did:aw:3YDAM5ZLRKg7eHH1Zs6sSMwkga8w"); err != nil || loaded != nil {
		t.Fatalf("absent record: %+v (%v)", loaded, err)
	}
}

func TestControllerIssuanceDirIsBesideTheControllerKey(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir, err := ControllerIssuanceDir("Example.COM.")
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(home, ".awid", "controllers", "example.com.id-issuance"); dir != want {
		t.Fatalf("dir %s want %s", dir, want)
	}
}
