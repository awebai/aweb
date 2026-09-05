package wake

import "time"

// Status is what `aw wake status` reports and what the daemon mirrors into
// status.json so the CLI can answer while the daemon is down.
//
// It holds counts, ids, states and timestamps. It never holds message content
// (§6), and it holds no presented marks (§4).
type Status struct {
	UpdatedAt     time.Time        `json:"updated_at"`
	StateDir      string           `json:"state_dir"`
	DaemonRunning bool             `json:"daemon_running"`
	DaemonPID     int              `json:"daemon_pid,omitempty"`
	MaxStreams    int              `json:"max_streams"`
	Streams       []StreamStatus   `json:"streams"`
	Instances     []InstanceStatus `json:"instances"`
}

// StreamStatus is one identity's event stream.
type StreamStatus struct {
	IdentityHome string    `json:"identity_home"`
	Phase        string    `json:"phase"`
	LastError    string    `json:"last_error,omitempty"`
	UnreadCount  int       `json:"unread_count,omitempty"`
	ConnectedAt  time.Time `json:"connected_at,omitempty"`
	// Admitted is false for a registration past the configured stream bound.
	// Such a registration is reported here, never silently dropped (§4).
	Admitted bool `json:"admitted"`
}

// InstancePhase is a registration's lifecycle position.
const (
	// PhasePending means no confirmed live inspect yet. Every pending state
	// and every error is tolerated here, and nothing is submitted.
	PhasePending = "pending"
	// PhaseActive means at least one confirmed live inspect has happened.
	PhaseActive = "active"
	// PhaseInactive means `stopped` was seen after a confirmed live
	// observation. Removal stays with the retire hook.
	PhaseInactive = "inactive"
)

// InstanceStatus is one registered instance.
type InstanceStatus struct {
	Home           string    `json:"home"`
	IdentityHome   string    `json:"identity_home"`
	Backend        string    `json:"backend,omitempty"`
	Delivery       string    `json:"delivery"`
	RegisteredAt   time.Time `json:"registered_at"`
	Phase          string    `json:"phase"`
	Paused         bool      `json:"paused"`
	PendingHints   int       `json:"pending_hints"`
	Evicted        int       `json:"evicted_hints"`
	LastInspectAt  time.Time `json:"last_inspect_at,omitempty"`
	LastAttemptAt  time.Time `json:"last_attempt_at,omitempty"`
	LastSubmitAt   time.Time `json:"last_submit_at,omitempty"`
	LastState      string    `json:"last_state,omitempty"`
	LastError      string    `json:"last_error,omitempty"`
	UnreadCount    int       `json:"unread_count,omitempty"`
	StreamAdmitted bool      `json:"stream_admitted"`
}
