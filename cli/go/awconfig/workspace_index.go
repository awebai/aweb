package awconfig

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

const machineWorkspaceIndexVersion = 1

// MachineWorkspaceAvailability reports whether a discovery-index entry's root is
// currently reachable on this machine. It is derived when listing and is never
// used as authority for membership or credential decisions.
type MachineWorkspaceAvailability string

const (
	MachineWorkspaceAvailable   MachineWorkspaceAvailability = "available"
	MachineWorkspaceUnavailable MachineWorkspaceAvailability = "unavailable"
)

// MachineWorkspaceIndexEntry is one non-secret workspace discovery record in
// ~/.config/aw/workspaces.yaml. The index is discovery only: callers must still
// load and verify workspace/team/certificate state from the referenced path.
type MachineWorkspaceIndexEntry struct {
	Path      string `yaml:"path"`
	TeamID    string `yaml:"team_id"`
	Alias     string `yaml:"alias"`
	ServerURL string `yaml:"server_url"`

	Availability      MachineWorkspaceAvailability `yaml:"-"`
	AvailabilityError string                       `yaml:"-"`
}

type machineWorkspaceIndexYAML struct {
	Version    int                          `yaml:"version"`
	Workspaces []MachineWorkspaceIndexEntry `yaml:"workspaces,omitempty"`
}

// DefaultMachineWorkspaceIndexPath returns the required per-user discovery index
// path, ~/.config/aw/workspaces.yaml.
func DefaultMachineWorkspaceIndexPath() (string, error) {
	return PathInUserState("workspaces.yaml")
}

// RecordMachineWorkspace records or replaces one workspace root in the default
// non-secret machine workspace index. It holds the index lock across read,
// merge, and atomic write so concurrent processes preserve each other's entries.
func RecordMachineWorkspace(entry MachineWorkspaceIndexEntry) error {
	path, err := DefaultMachineWorkspaceIndexPath()
	if err != nil {
		return err
	}
	return RecordMachineWorkspaceAt(path, entry)
}

// RecordMachineWorkspaceAt is the path-injected form of RecordMachineWorkspace,
// intended for tests and for callers with an already-resolved config path.
func RecordMachineWorkspaceAt(indexPath string, entry MachineWorkspaceIndexEntry) error {
	entry, err := normalizeMachineWorkspaceEntry(entry)
	if err != nil {
		return err
	}
	lock, err := LockExclusive(indexPath + ".lock")
	if err != nil {
		return fmt.Errorf("lock machine workspace index: %w", err)
	}
	defer func() { _ = lock.Close() }()

	index, err := loadMachineWorkspaceIndexStored(indexPath)
	if err != nil {
		return err
	}
	index = upsertMachineWorkspaceEntry(index, entry)
	return saveMachineWorkspaceIndexStored(indexPath, index)
}

// LoadMachineWorkspaceIndex loads the default discovery index and annotates each
// entry with current path availability. Missing index files return an empty list.
func LoadMachineWorkspaceIndex() ([]MachineWorkspaceIndexEntry, error) {
	path, err := DefaultMachineWorkspaceIndexPath()
	if err != nil {
		return nil, err
	}
	return LoadMachineWorkspaceIndexAt(path)
}

// LoadMachineWorkspaceIndexAt is the path-injected form of
// LoadMachineWorkspaceIndex.
func LoadMachineWorkspaceIndexAt(indexPath string) ([]MachineWorkspaceIndexEntry, error) {
	index, err := loadMachineWorkspaceIndexStored(indexPath)
	if err != nil {
		return nil, err
	}
	entries := make([]MachineWorkspaceIndexEntry, 0, len(index.Workspaces))
	for _, entry := range index.Workspaces {
		entry, err = normalizeMachineWorkspaceEntry(entry)
		if err != nil {
			return nil, err
		}
		annotateMachineWorkspaceAvailability(&entry)
		entries = append(entries, entry)
	}
	sortMachineWorkspaceEntries(entries)
	return entries, nil
}

func loadMachineWorkspaceIndexStored(indexPath string) (machineWorkspaceIndexYAML, error) {
	data, err := os.ReadFile(indexPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return machineWorkspaceIndexYAML{Version: machineWorkspaceIndexVersion}, nil
		}
		return machineWorkspaceIndexYAML{}, fmt.Errorf("read machine workspace index: %w", err)
	}
	var index machineWorkspaceIndexYAML
	if err := yaml.Unmarshal(data, &index); err != nil {
		return machineWorkspaceIndexYAML{}, fmt.Errorf("parse machine workspace index: %w", err)
	}
	if index.Version == 0 {
		index.Version = machineWorkspaceIndexVersion
	}
	if index.Version != machineWorkspaceIndexVersion {
		return machineWorkspaceIndexYAML{}, fmt.Errorf("machine workspace index version %d is not supported", index.Version)
	}
	return index, nil
}

func saveMachineWorkspaceIndexStored(indexPath string, index machineWorkspaceIndexYAML) error {
	index.Version = machineWorkspaceIndexVersion
	entries := make([]MachineWorkspaceIndexEntry, 0, len(index.Workspaces))
	for _, entry := range index.Workspaces {
		normalized, err := normalizeMachineWorkspaceEntry(entry)
		if err != nil {
			return err
		}
		entries = append(entries, normalized)
	}
	sortMachineWorkspaceEntries(entries)
	index.Workspaces = entries
	data, err := yaml.Marshal(index)
	if err != nil {
		return fmt.Errorf("encode machine workspace index: %w", err)
	}
	return atomicWriteFileMode(indexPath, append(bytesTrimRightNewlines(data), '\n'), 0o644)
}

func upsertMachineWorkspaceEntry(index machineWorkspaceIndexYAML, entry MachineWorkspaceIndexEntry) machineWorkspaceIndexYAML {
	for i := range index.Workspaces {
		existing, err := normalizeMachineWorkspaceEntry(index.Workspaces[i])
		if err != nil {
			continue
		}
		if existing.Path == entry.Path && existing.TeamID == entry.TeamID {
			index.Workspaces[i] = entry
			return index
		}
	}
	index.Workspaces = append(index.Workspaces, entry)
	return index
}

func normalizeMachineWorkspaceEntry(entry MachineWorkspaceIndexEntry) (MachineWorkspaceIndexEntry, error) {
	entry.Path = strings.TrimSpace(entry.Path)
	if entry.Path == "" {
		return MachineWorkspaceIndexEntry{}, fmt.Errorf("machine workspace index entry requires path")
	}
	abs, err := filepath.Abs(entry.Path)
	if err != nil {
		return MachineWorkspaceIndexEntry{}, fmt.Errorf("resolve machine workspace index path %q: %w", entry.Path, err)
	}
	entry.Path = filepath.Clean(abs)
	entry.TeamID = strings.TrimSpace(entry.TeamID)
	entry.Alias = strings.TrimSpace(entry.Alias)
	entry.ServerURL = strings.TrimSpace(entry.ServerURL)
	entry.Availability = ""
	entry.AvailabilityError = ""
	return entry, nil
}

func annotateMachineWorkspaceAvailability(entry *MachineWorkspaceIndexEntry) {
	if entry == nil {
		return
	}
	info, err := os.Stat(entry.Path)
	if err != nil {
		entry.Availability = MachineWorkspaceUnavailable
		entry.AvailabilityError = err.Error()
		return
	}
	if !info.IsDir() {
		entry.Availability = MachineWorkspaceUnavailable
		entry.AvailabilityError = "path is not a directory"
		return
	}
	dir, err := os.Open(entry.Path)
	if err != nil {
		entry.Availability = MachineWorkspaceUnavailable
		entry.AvailabilityError = err.Error()
		return
	}
	defer func() { _ = dir.Close() }()
	if _, err := dir.Readdirnames(1); err != nil && !errors.Is(err, io.EOF) {
		entry.Availability = MachineWorkspaceUnavailable
		entry.AvailabilityError = err.Error()
		return
	}
	entry.Availability = MachineWorkspaceAvailable
}

func sortMachineWorkspaceEntries(entries []MachineWorkspaceIndexEntry) {
	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].Path != entries[j].Path {
			return entries[i].Path < entries[j].Path
		}
		if entries[i].TeamID != entries[j].TeamID {
			return entries[i].TeamID < entries[j].TeamID
		}
		if entries[i].Alias != entries[j].Alias {
			return entries[i].Alias < entries[j].Alias
		}
		return entries[i].ServerURL < entries[j].ServerURL
	})
}
