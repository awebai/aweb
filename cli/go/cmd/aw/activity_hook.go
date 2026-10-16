package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

// The Codex activity emitter (docs/agent-activity.md, "Emitters"). Codex runs
// one hook process per event, so what a resident emitter keeps in memory (the
// open turn, its seq, the coalescing window and the rate-limit pause) lives in
// a state file in the identity root, read and written under an exclusive lock.
// The hook never writes to stdout and never fails the Codex event.

const (
	activityPath             = "/v1/agents/me/activity"
	activityHookStateFile    = ".activity-hook-state.json"
	activityHookLockFile     = ".activity-hook.lock"
	activityValidity         = 60 * time.Second
	activityCoalesceWindow   = 500 * time.Millisecond
	activityDefaultPause     = 5 * time.Second
	activityRouteAbsentPause = time.Hour
	activityEndedTurnsKept   = 256
	activityHookInputLimit   = 16 << 20
	activityRequestTimeout   = 3 * time.Second
)

var activityIdentifier = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,64}$`)

var activityHookCmd = &cobra.Command{
	Use:   "hook",
	Short: "Publish live activity from a Codex hook event on stdin",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		runCodexActivityHook(cmd.InOrStdin(), cmd.ErrOrStderr())
		return nil
	},
}

type codexHookInput struct {
	HookEventName string          `json:"hook_event_name"`
	TurnID        string          `json:"turn_id"`
	AgentID       string          `json:"agent_id"`
	ToolName      string          `json:"tool_name"`
	ToolInput     json.RawMessage `json:"tool_input"`
	Cwd           string          `json:"cwd"`
}

type activityItem struct {
	Token   string `json:"token,omitempty"`
	Turn    string `json:"turn"`
	Seq     int64  `json:"seq,omitempty"`
	Phase   string `json:"phase"`
	Tool    string `json:"tool,omitempty"`
	Summary string `json:"summary,omitempty"`
}

type activityHookState struct {
	OpenTurn         string        `json:"open_turn,omitempty"`
	Seq              int64         `json:"seq,omitempty"`
	Ended            []string      `json:"ended,omitempty"`
	LastSentMs       int64         `json:"last_sent_ms,omitempty"`
	PauseUntilMs     int64         `json:"pause_until_ms,omitempty"`
	RouteAbsentUntil int64         `json:"route_absent_until_ms,omitempty"`
	Pending          *activityItem `json:"pending,omitempty"`
}

// activityPublisher signs events with the key that signs the runtime's
// requests: the agent's own, or the grant session key for a grant seat.
type activityPublisher struct {
	client interface {
		DoRaw(context.Context, string, string, string, any) (*http.Response, error)
	}
	key      ed25519.PrivateKey
	did      string
	stableID string
	teamID   string
}

type activityOutcome int

const (
	activityAccepted activityOutcome = iota
	activityRateLimited
	activityRouteAbsent
	activityDropped
)

func runCodexActivityHook(stdin io.Reader, stderr io.Writer) {
	// Read the whole event first, whatever happens next, so that Codex never
	// writes into a closed pipe.
	raw, err := io.ReadAll(io.LimitReader(stdin, activityHookInputLimit+1))
	_, _ = io.Copy(io.Discard, stdin)
	if err != nil || len(raw) > activityHookInputLimit {
		return
	}
	root, err := activityIdentityRoot()
	if err != nil || readActivitySetting(root) != "status" {
		return
	}
	var in codexHookInput
	if json.Unmarshal(raw, &in) != nil {
		return
	}
	publisher, err := newActivityPublisher()
	if err != nil {
		return
	}
	lock, err := awconfig.LockExclusive(filepath.Join(root, activityHookLockFile))
	if err != nil {
		return
	}
	hook := &codexActivityHook{root: root, publisher: publisher, stderr: stderr, lock: lock}
	defer func() { hook.lock.Close() }()
	hook.state = loadActivityHookState(root)
	if time.Now().UnixMilli() < hook.state.RouteAbsentUntil {
		return
	}
	boundaries, state := hook.plan(in)
	for _, item := range boundaries {
		if !hook.sendBoundary(item) {
			hook.save()
			return
		}
	}
	if state != nil {
		hook.sendState(*state)
	}
	hook.save()
}

type codexActivityHook struct {
	root      string
	publisher *activityPublisher
	stderr    io.Writer
	lock      interface{ Close() error }
	unlocked  bool
	state     activityHookState
}

// plan applies the event to the turn state and returns the boundaries to send
// in order and the intermediate state, if any.
func (h *codexActivityHook) plan(in codexHookInput) ([]activityItem, *activityItem) {
	s := &h.state
	var boundaries []activityItem
	closeTurn := func(turn string) {
		s.Seq++
		boundaries = append(boundaries, activityItem{Turn: turn, Seq: s.Seq, Phase: "turn_ended"})
		h.markEnded(turn)
		s.OpenTurn, s.Seq = "", 0
		if s.Pending != nil && s.Pending.Turn == turn {
			s.Pending = nil
		}
	}
	openTurn := func(turn string) {
		if s.OpenTurn != "" {
			closeTurn(s.OpenTurn)
		}
		s.OpenTurn, s.Seq = turn, 1
		boundaries = append(boundaries, activityItem{Turn: turn, Seq: 1, Phase: "turn_started"})
	}
	item := codexActivityState(in)
	if in.HookEventName == "SessionEnd" {
		if s.OpenTurn != "" {
			closeTurn(s.OpenTurn)
		}
		return boundaries, nil
	}
	// A subagent's tool events belong to the open turn of its parent.
	if strings.TrimSpace(in.AgentID) != "" {
		if item == nil || s.OpenTurn == "" {
			return nil, nil
		}
		item.Turn = s.OpenTurn
		return nil, item
	}
	turn := in.TurnID
	if !activityIdentifier.MatchString(turn) || slices.Contains(s.Ended, turn) {
		return nil, nil
	}
	switch in.HookEventName {
	case "UserPromptSubmit":
		if s.OpenTurn != turn {
			openTurn(turn)
		}
		return boundaries, nil
	case "Stop", "Interrupt":
		if s.OpenTurn == turn {
			closeTurn(turn)
		} else {
			h.markEnded(turn)
		}
		return boundaries, nil
	}
	if item == nil {
		return nil, nil
	}
	if s.OpenTurn != turn {
		openTurn(turn)
	}
	item.Turn = turn
	return boundaries, item
}

// codexActivityState maps a Codex tool event to its intermediate phase.
func codexActivityState(in codexHookInput) *activityItem {
	tool := in.ToolName
	if !activityIdentifier.MatchString(tool) {
		tool = "unknown"
	}
	switch in.HookEventName {
	case "PreToolUse":
		return &activityItem{Phase: "tool", Tool: tool, Summary: codexToolSummary(in.ToolName, in.ToolInput, in.Cwd)}
	case "PostToolUse":
		return &activityItem{Phase: "thinking"}
	case "PermissionRequest":
		if !activityIdentifier.MatchString(in.ToolName) {
			return &activityItem{Phase: "waiting_permission"}
		}
		return &activityItem{Phase: "waiting_permission", Tool: in.ToolName}
	}
	return nil
}

func (h *codexActivityHook) markEnded(turn string) {
	h.state.Ended = append(h.state.Ended, turn)
	if len(h.state.Ended) > activityEndedTurnsKept {
		h.state.Ended = h.state.Ended[len(h.state.Ended)-activityEndedTurnsKept:]
	}
}

// sendBoundary sends a turn boundary, waiting out a rate-limit pause first
// with the lock held so that nothing overtakes it. A boundary that draws a 429
// is sent once more after the pause. It reports whether publishing goes on.
func (h *codexActivityHook) sendBoundary(item activityItem) bool {
	for attempt := 0; attempt < 2; attempt++ {
		h.sleepUntil(h.state.PauseUntilMs)
		switch h.send(item) {
		case activityRouteAbsent:
			return false
		case activityRateLimited:
			continue
		default:
			return true
		}
	}
	return true
}

// sendState sends an intermediate state, or leaves it pending until the
// coalescing window and any pause have passed. A later state replaces a
// pending one, and the turn's end discards it.
func (h *codexActivityHook) sendState(item activityItem) {
	token := make([]byte, 8)
	_, _ = rand.Read(token)
	item.Token = hex.EncodeToString(token)
	for {
		ready := max(h.state.LastSentMs+activityCoalesceWindow.Milliseconds(), h.state.PauseUntilMs)
		if time.Now().UnixMilli() >= ready {
			h.state.Pending = nil
			if item.Turn == h.state.OpenTurn {
				h.state.Seq++
				item.Seq = h.state.Seq
				h.send(item)
			}
			return
		}
		h.state.Pending = &item
		h.save()
		h.lock.Close()
		time.Sleep(time.Until(time.UnixMilli(ready)))
		lock, err := awconfig.LockExclusive(filepath.Join(h.root, activityHookLockFile))
		if err != nil {
			h.lock, h.unlocked = nopCloser{}, true
			return
		}
		h.lock = lock
		h.state = loadActivityHookState(h.root)
		if h.state.Pending == nil || h.state.Pending.Token != item.Token {
			return
		}
	}
}

type nopCloser struct{}

func (nopCloser) Close() error { return nil }

func (h *codexActivityHook) sleepUntil(ms int64) {
	if wait := time.Until(time.UnixMilli(ms)); wait > 0 {
		time.Sleep(wait)
	}
}

func (h *codexActivityHook) send(item activityItem) activityOutcome {
	outcome, retryAfter := h.publisher.publish(item)
	now := time.Now()
	h.state.LastSentMs = now.UnixMilli()
	switch outcome {
	case activityRateLimited:
		h.state.PauseUntilMs = now.Add(retryAfter).UnixMilli()
	case activityRouteAbsent:
		h.state.RouteAbsentUntil = now.Add(activityRouteAbsentPause).UnixMilli()
		fmt.Fprintln(h.stderr, "aw activity: the server has no activity route; publishing stops for an hour")
	}
	return outcome
}

func newActivityPublisher() (*activityPublisher, error) {
	client, sel, err := resolveClientSelection()
	if err != nil {
		return nil, err
	}
	key, err := awid.LoadSigningKey(sel.SigningKey)
	if err != nil {
		return nil, err
	}
	stableID := strings.TrimSpace(sel.StableID)
	if !strings.HasPrefix(stableID, "did:aw:") {
		stableID = ""
	}
	return &activityPublisher{client: client, key: key, did: awid.ComputeDIDKey(key.Public().(ed25519.PublicKey)),
		stableID: stableID, teamID: strings.TrimSpace(sel.TeamID)}, nil
}

func (p *activityPublisher) publish(item activityItem) (activityOutcome, time.Duration) {
	now := time.Now().UTC().Truncate(time.Second)
	event := map[string]any{
		"v": 1, "type": "agent_activity", "from_did": p.did, "team_id": p.teamID, "session_id": nil,
		"turn_id": item.Turn, "seq": item.Seq, "phase": item.Phase,
		"timestamp": now.Format(time.RFC3339), "expires_at": now.Add(activityValidity).Format(time.RFC3339),
	}
	if p.stableID != "" {
		event["from_stable_id"] = p.stableID
	}
	if item.Tool != "" {
		event["tool"] = item.Tool
	}
	if item.Summary != "" {
		event["summary"] = item.Summary
	}
	signed, err := signActivityEvent(event, p.key)
	if err != nil {
		return activityDropped, 0
	}
	ctx, cancel := context.WithTimeout(context.Background(), activityRequestTimeout)
	defer cancel()
	response, err := p.client.DoRaw(ctx, http.MethodPost, activityPath, "application/json", signed)
	if err != nil {
		return activityDropped, 0
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
	switch {
	case response.StatusCode >= 200 && response.StatusCode < 300:
		return activityAccepted, 0
	case response.StatusCode == http.StatusTooManyRequests:
		if seconds, err := strconv.Atoi(response.Header.Get("Retry-After")); err == nil && seconds >= 0 {
			return activityRateLimited, time.Duration(seconds) * time.Second
		}
		return activityRateLimited, activityDefaultPause
	case response.StatusCode == http.StatusNotFound && !isSharedResource404(body):
		return activityRouteAbsent, 0
	}
	return activityDropped, 0
}

// isSharedResource404 recognises the route's own 404 for a session the caller
// cannot see; any other 404 body means the server has no activity route.
func isSharedResource404(body []byte) bool {
	var parsed map[string]any
	return json.Unmarshal(body, &parsed) == nil && len(parsed) == 1 && parsed["detail"] == "Not found"
}

// signActivityEvent returns the request body for POST /v1/agents/me/activity.
func signActivityEvent(event map[string]any, key ed25519.PrivateKey) (map[string]string, error) {
	payload, err := canonicalUTF8JSON(event)
	if err != nil {
		return nil, err
	}
	return map[string]string{
		"signed_payload": base64.RawURLEncoding.EncodeToString(payload),
		"signature":      base64.RawStdEncoding.EncodeToString(ed25519.Sign(key, payload)),
	}, nil
}

func loadActivityHookState(root string) activityHookState {
	var state activityHookState
	if data, err := os.ReadFile(filepath.Join(root, activityHookStateFile)); err == nil {
		if json.Unmarshal(data, &state) != nil {
			return activityHookState{}
		}
	}
	return state
}

// save writes the state; a hook that lost its lock writes nothing.
func (h *codexActivityHook) save() {
	if h.unlocked {
		return
	}
	if data, err := json.Marshal(h.state); err == nil {
		_ = writeFileAtomic(h.root, activityHookStateFile, data, 0o600)
	}
}
