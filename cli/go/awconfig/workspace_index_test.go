package awconfig

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestMachineWorkspaceIndexConcurrentProcessesPreserveBothEntries(t *testing.T) {
	// Uses process environment (HOME) and helper processes; do not mark parallel.
	home := t.TempDir()
	workspaceA := filepath.Join(t.TempDir(), "workspace-a")
	workspaceB := filepath.Join(t.TempDir(), "workspace-b")
	if err := os.MkdirAll(workspaceA, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(workspaceB, 0o700); err != nil {
		t.Fatal(err)
	}
	startFile := filepath.Join(t.TempDir(), "start")

	cmdA := machineWorkspaceIndexHelperCommand(t, home, startFile, workspaceA, "backend:acme.com", "alice", "https://a.example")
	cmdB := machineWorkspaceIndexHelperCommand(t, home, startFile, workspaceB, "frontend:acme.com", "bob", "https://b.example")
	var outA, outB bytes.Buffer
	cmdA.Stdout = &outA
	cmdA.Stderr = &outA
	cmdB.Stdout = &outB
	cmdB.Stderr = &outB
	if err := cmdA.Start(); err != nil {
		t.Fatalf("start helper A: %v", err)
	}
	if err := cmdB.Start(); err != nil {
		t.Fatalf("start helper B: %v", err)
	}
	if err := os.WriteFile(startFile, []byte("go\n"), 0o600); err != nil {
		t.Fatalf("release helpers: %v", err)
	}
	if err := cmdA.Wait(); err != nil {
		t.Fatalf("helper A failed: %v\n%s", err, outA.String())
	}
	if err := cmdB.Wait(); err != nil {
		t.Fatalf("helper B failed: %v\n%s", err, outB.String())
	}

	indexPath := filepath.Join(home, ".config", "aw", "workspaces.yaml")
	entries, err := LoadMachineWorkspaceIndexAt(indexPath)
	if err != nil {
		t.Fatalf("load index: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("entries=%d want 2: %#v", len(entries), entries)
	}
	byPath := map[string]MachineWorkspaceIndexEntry{}
	for _, entry := range entries {
		byPath[entry.Path] = entry
	}
	assertMachineWorkspaceIndexEntry(t, byPath[workspaceA], workspaceA, "backend:acme.com", "alice", "https://a.example", MachineWorkspaceAvailable)
	assertMachineWorkspaceIndexEntry(t, byPath[workspaceB], workspaceB, "frontend:acme.com", "bob", "https://b.example", MachineWorkspaceAvailable)
}

func TestMachineWorkspaceIndexRetainsUnavailableEntries(t *testing.T) {
	// Uses process environment (HOME); do not mark parallel.
	home := t.TempDir()
	t.Setenv("HOME", home)
	available := filepath.Join(t.TempDir(), "available")
	if err := os.MkdirAll(available, 0o700); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(t.TempDir(), "missing-workspace")

	if err := RecordMachineWorkspace(MachineWorkspaceIndexEntry{Path: missing, TeamID: "missing:acme.com", Alias: "missing", ServerURL: "https://missing.example"}); err != nil {
		t.Fatalf("record missing: %v", err)
	}
	if err := RecordMachineWorkspace(MachineWorkspaceIndexEntry{Path: available, TeamID: "available:acme.com", Alias: "alice", ServerURL: "https://available.example"}); err != nil {
		t.Fatalf("record available: %v", err)
	}

	entries, err := LoadMachineWorkspaceIndex()
	if err != nil {
		t.Fatalf("load index: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("entries=%d want 2: %#v", len(entries), entries)
	}
	byPath := map[string]MachineWorkspaceIndexEntry{}
	for _, entry := range entries {
		byPath[entry.Path] = entry
	}
	assertMachineWorkspaceIndexEntry(t, byPath[missing], missing, "missing:acme.com", "missing", "https://missing.example", MachineWorkspaceUnavailable)
	if got := byPath[missing].AvailabilityError; got == "" {
		t.Fatal("missing entry did not report availability error")
	}
	assertMachineWorkspaceIndexEntry(t, byPath[available], available, "available:acme.com", "alice", "https://available.example", MachineWorkspaceAvailable)

	data, err := os.ReadFile(filepath.Join(home, ".config", "aw", "workspaces.yaml"))
	if err != nil {
		t.Fatalf("read raw index: %v", err)
	}
	text := string(data)
	for _, want := range []string{"path: " + missing, "team_id: missing:acme.com", "server_url: https://missing.example"} {
		if !strings.Contains(text, want) {
			t.Fatalf("raw index lost unavailable entry field %q:\n%s", want, text)
		}
	}
}

func TestMachineWorkspaceIndexRetainsMultipleTeamsForOneRoot(t *testing.T) {
	// Uses process environment (HOME); do not mark parallel.
	home := t.TempDir()
	t.Setenv("HOME", home)
	root := filepath.Join(t.TempDir(), "workspace")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, entry := range []MachineWorkspaceIndexEntry{
		{Path: root, TeamID: "backend:acme.com", Alias: "alice", ServerURL: "https://backend.example"},
		{Path: root, TeamID: "frontend:acme.com", Alias: "alice-ui", ServerURL: "https://frontend.example"},
	} {
		if err := RecordMachineWorkspace(entry); err != nil {
			t.Fatalf("record %+v: %v", entry, err)
		}
	}
	entries, err := LoadMachineWorkspaceIndex()
	if err != nil {
		t.Fatalf("load index: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("entries=%d want 2: %#v", len(entries), entries)
	}
	teams := map[string]MachineWorkspaceIndexEntry{}
	for _, entry := range entries {
		teams[entry.TeamID] = entry
	}
	assertMachineWorkspaceIndexEntry(t, teams["backend:acme.com"], root, "backend:acme.com", "alice", "https://backend.example", MachineWorkspaceAvailable)
	assertMachineWorkspaceIndexEntry(t, teams["frontend:acme.com"], root, "frontend:acme.com", "alice-ui", "https://frontend.example", MachineWorkspaceAvailable)
}

func TestMachineWorkspaceIndexReportsUnreadableRootsUnavailable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chmod unreadable directory semantics are platform-specific")
	}
	// Uses process environment (HOME); do not mark parallel.
	home := t.TempDir()
	t.Setenv("HOME", home)
	root := filepath.Join(t.TempDir(), "unreadable")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := RecordMachineWorkspace(MachineWorkspaceIndexEntry{Path: root, TeamID: "team:acme.com", Alias: "alice", ServerURL: "https://example"}); err != nil {
		t.Fatalf("record root: %v", err)
	}
	if err := os.Chmod(root, 0); err != nil {
		t.Fatalf("chmod root unreadable: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(root, 0o700) })
	entries, err := LoadMachineWorkspaceIndex()
	if err != nil {
		t.Fatalf("load index: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries=%d want 1: %#v", len(entries), entries)
	}
	if entries[0].Availability != MachineWorkspaceUnavailable || entries[0].AvailabilityError == "" {
		t.Fatalf("unreadable root availability=%q error=%q", entries[0].Availability, entries[0].AvailabilityError)
	}
}

func TestMachineWorkspaceIndexHelperProcess(t *testing.T) {
	if os.Getenv("AWCONFIG_WORKSPACE_INDEX_HELPER") != "1" {
		return
	}
	deadline := time.Now().Add(10 * time.Second)
	start := os.Getenv("AWCONFIG_WORKSPACE_INDEX_START")
	for {
		if _, err := os.Stat(start); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", start)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := RecordMachineWorkspace(MachineWorkspaceIndexEntry{
		Path:      os.Getenv("AWCONFIG_WORKSPACE_INDEX_PATH"),
		TeamID:    os.Getenv("AWCONFIG_WORKSPACE_INDEX_TEAM"),
		Alias:     os.Getenv("AWCONFIG_WORKSPACE_INDEX_ALIAS"),
		ServerURL: os.Getenv("AWCONFIG_WORKSPACE_INDEX_SERVER"),
	}); err != nil {
		t.Fatalf("record workspace: %v", err)
	}
}

func machineWorkspaceIndexHelperCommand(t *testing.T, home, start, path, team, alias, server string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestMachineWorkspaceIndexHelperProcess$", "-test.v=false")
	cmd.Env = append(os.Environ(),
		"HOME="+home,
		"AWCONFIG_WORKSPACE_INDEX_HELPER=1",
		"AWCONFIG_WORKSPACE_INDEX_START="+start,
		"AWCONFIG_WORKSPACE_INDEX_PATH="+path,
		"AWCONFIG_WORKSPACE_INDEX_TEAM="+team,
		"AWCONFIG_WORKSPACE_INDEX_ALIAS="+alias,
		"AWCONFIG_WORKSPACE_INDEX_SERVER="+server,
	)
	return cmd
}

func assertMachineWorkspaceIndexEntry(t *testing.T, got MachineWorkspaceIndexEntry, path, team, alias, server string, availability MachineWorkspaceAvailability) {
	t.Helper()
	abs, err := filepath.Abs(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Path != filepath.Clean(abs) || got.TeamID != team || got.Alias != alias || got.ServerURL != server || got.Availability != availability {
		t.Fatalf("entry mismatch:\n got=%#v\nwant path=%q team=%q alias=%q server=%q availability=%q", got, filepath.Clean(abs), team, alias, server, availability)
	}
}

func TestMachineWorkspaceIndexOrderingIsDeterministic(t *testing.T) {
	// Uses process environment (HOME); do not mark parallel.
	home := t.TempDir()
	t.Setenv("HOME", home)
	paths := []string{filepath.Join(t.TempDir(), "c"), filepath.Join(t.TempDir(), "a"), filepath.Join(t.TempDir(), "b")}
	for i, path := range paths {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := RecordMachineWorkspace(MachineWorkspaceIndexEntry{Path: path, TeamID: "team", Alias: string(rune('a' + i)), ServerURL: "https://example"}); err != nil {
			t.Fatalf("record %s: %v", path, err)
		}
	}
	entries, err := LoadMachineWorkspaceIndex()
	if err != nil {
		t.Fatalf("load index: %v", err)
	}
	got := make([]string, 0, len(entries))
	for _, entry := range entries {
		got = append(got, entry.Path)
	}
	want := append([]string(nil), got...)
	sort.Strings(want)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("entries not sorted:\n got=%v\nwant=%v", got, want)
	}
}
