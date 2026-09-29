package wake

import (
	"bytes"
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	awid "github.com/awebai/aw/awid"
	"github.com/awebai/aw/wake/session"
)

//go:embed channel_core_runner_bundle.mjs
var channelCoreRunnerFS embed.FS

type ChannelCoreStatus struct {
	NodePath      string    `json:"node_path,omitempty"`
	BundlePath    string    `json:"bundle_path,omitempty"`
	LastError     string    `json:"last_error,omitempty"`
	LastRunAt     time.Time `json:"last_run_at,omitempty"`
	LastSuccessAt time.Time `json:"last_success_at,omitempty"`
}

type ChannelCoreRunner struct {
	store *Store
	bin   string
	mu    sync.Mutex
	st    ChannelCoreStatus
}

type channelCoreRequest struct {
	Event             map[string]any `json:"event"`
	Home              string         `json:"home"`
	IdentityHome      string         `json:"identityHome"`
	TeamID            string         `json:"teamID,omitempty"`
	StatePath         string         `json:"statePath,omitempty"`
	OatsBin           string         `json:"oatsBin,omitempty"`
	AWCommand         string         `json:"awCommand,omitempty"`
	DeliveryStorePath string         `json:"deliveryStorePath,omitempty"`
	CoalesceMs        int            `json:"coalesceMs,omitempty"`
	RateLimitMs       int            `json:"rateLimitMs,omitempty"`
	InspectDelayMs    int            `json:"inspectDelayMs,omitempty"`
}

type channelCoreResponse struct {
	OK       bool           `json:"ok"`
	Inactive string         `json:"inactive,omitempty"`
	Terminal map[string]any `json:"terminal,omitempty"`
	Error    string         `json:"error,omitempty"`
}

func NewChannelCoreRunner(store *Store) *ChannelCoreRunner { return &ChannelCoreRunner{store: store} }

func (r *ChannelCoreRunner) Status() ChannelCoreStatus {
	if r == nil {
		return ChannelCoreStatus{}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.st
}

func (r *ChannelCoreRunner) Deliver(ctx context.Context, reg Registration, binding ReceiveIdentity, ev awid.AgentEvent, coalesce, rate, inspect time.Duration, awCommand string) (string, error) {
	if r == nil {
		return "", errors.New("channel-core runner is not configured")
	}
	node, err := exec.LookPath("node")
	if err != nil {
		r.note("", "", "system Node executable not found in PATH")
		return "", errors.New("system Node executable not found in PATH")
	}
	bundle, err := r.bundlePath()
	if err != nil {
		r.note(node, "", err.Error())
		return "", err
	}
	req := channelCoreRequest{
		Event:             agentEventForChannelCore(ev),
		Home:              reg.Home,
		IdentityHome:      binding.IdentityHome,
		TeamID:            binding.TeamID,
		StatePath:         r.store.instancePath(HomeKey(reg.Home)),
		OatsBin:           session.DefaultOatsBin,
		AWCommand:         awCommand,
		DeliveryStorePath: filepath.Join(binding.IdentityHome, "channel-delivered-ids.json"),
		CoalesceMs:        millis(coalesce),
		RateLimitMs:       millis(rate),
		InspectDelayMs:    millis(inspect),
	}
	raw, _ := json.Marshal(req)
	cmd := exec.CommandContext(ctx, node, bundle)
	cmd.Stdin = bytes.NewReader(raw)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	r.note(node, bundle, "")
	if err := cmd.Run(); err != nil {
		detail := strings.TrimSpace(stderr.String())
		if detail == "" {
			detail = strings.TrimSpace(stdout.String())
		}
		if detail == "" {
			detail = err.Error()
		}
		r.note(node, bundle, detail)
		return "", fmt.Errorf("channel-core delivery failed: %s", detail)
	}
	var resp channelCoreResponse
	if err := json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &resp); err != nil {
		detail := strings.TrimSpace(stderr.String())
		if detail != "" {
			detail += ": "
		}
		detail += err.Error()
		r.note(node, bundle, detail)
		return "", fmt.Errorf("channel-core delivery returned invalid JSON: %s", detail)
	}
	if !resp.OK {
		detail := strings.TrimSpace(resp.Error)
		if detail == "" {
			detail = strings.TrimSpace(stderr.String())
		}
		if detail == "" {
			detail = "channel-core delivery failed"
		}
		r.note(node, bundle, detail)
		return resp.Inactive, errors.New(detail)
	}
	r.mu.Lock()
	r.st.LastError = ""
	r.st.LastSuccessAt = time.Now().UTC()
	r.mu.Unlock()
	return resp.Inactive, nil
}

func (r *ChannelCoreRunner) note(node, bundle, lastErr string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.st.NodePath = node
	r.st.BundlePath = bundle
	r.st.LastError = lastErr
	r.st.LastRunAt = time.Now().UTC()
}

func (r *ChannelCoreRunner) bundlePath() (string, error) {
	root := filepath.Join(r.store.Dir(), "channel-core")
	if err := os.MkdirAll(root, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(root, "runner.mjs")
	content, err := channelCoreRunnerFS.ReadFile("channel_core_runner_bundle.mjs")
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(content)
	stamp := filepath.Join(root, "runner.sha256")
	want := hex.EncodeToString(sum[:])
	if got, err := os.ReadFile(stamp); err == nil && strings.TrimSpace(string(got)) == want {
		return path, nil
	}
	if err := os.WriteFile(path, content, 0o600); err != nil {
		return "", err
	}
	if err := os.WriteFile(stamp, []byte(want+"\n"), 0o600); err != nil {
		return "", err
	}
	return path, nil
}

func millis(d time.Duration) int {
	if d <= 0 {
		return 0
	}
	return int(d / time.Millisecond)
}

func agentEventForChannelCore(ev awid.AgentEvent) map[string]any {
	typ := string(ev.Type)
	if ev.Type == awid.AgentEventActionableMail {
		typ = "mail_message"
	}
	if ev.Type == awid.AgentEventActionableChat {
		typ = "chat_message"
	}
	out := map[string]any{"type": typ}
	put := func(k, v string) {
		if strings.TrimSpace(v) != "" {
			out[k] = v
		}
	}
	put("agent_id", ev.AgentID)
	put("team_id", ev.TeamID)
	put("wake_mode", ev.WakeMode)
	put("channel", ev.Channel)
	put("message_id", ev.MessageID)
	put("conversation_id", ev.ConversationID)
	put("from_alias", ev.FromAlias)
	put("from_stable_id", ev.FromStableID)
	put("from_did", ev.FromDID)
	put("from_address", ev.FromAddress)
	put("session_id", ev.SessionID)
	put("subject", ev.Subject)
	put("content_mode", ev.ContentMode)
	put("task_id", ev.TaskID)
	put("title", ev.Title)
	put("status", ev.Status)
	put("signal_id", ev.SignalID)
	put("event_id", ev.EventID)
	put("app_id", ev.AppID)
	put("app_event_type", ev.AppEventType)
	put("resource_ref", ev.ResourceRef)
	put("delivery_intent", ev.DeliveryIntent)
	put("producer_delivery_intent", ev.ProducerIntent)
	put("text", ev.Text)
	if ev.MessageVersion != 0 {
		out["message_version"] = ev.MessageVersion
	}
	if ev.Encrypted {
		out["encrypted"] = ev.Encrypted
	}
	if ev.UnreadCount != 0 {
		out["unread_count"] = ev.UnreadCount
	}
	if ev.SenderWaiting {
		out["sender_waiting"] = ev.SenderWaiting
	}
	if ev.Payload != nil {
		out["payload"] = ev.Payload
	}
	return out
}
