package wake

import (
	"bufio"
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	awid "github.com/awebai/aw/awid"
)

//go:embed channel_core_runner_bundle.mjs
var channelCoreRunnerFS embed.FS

type ChannelCoreStatus struct {
	NodePath       string            `json:"node_path,omitempty"`
	BundlePath     string            `json:"bundle_path,omitempty"`
	LastError      string            `json:"last_error,omitempty"`
	LastRunAt      time.Time         `json:"last_run_at,omitempty"`
	LastSuccessAt  time.Time         `json:"last_success_at,omitempty"`
	LastInputAt    time.Time         `json:"last_input_at,omitempty"`
	AmbientQueued  int               `json:"ambient_queued"`
	AmbientDropped int               `json:"ambient_dropped"`
	Evicted        int               `json:"evicted_events"`
	BindingErrors  map[string]string `json:"binding_errors,omitempty"`
	TraceStage     string            `json:"trace_stage,omitempty"`
	TraceBindingID string            `json:"trace_binding_id,omitempty"`
	TraceMessageID string            `json:"trace_message_id,omitempty"`
	TraceSessionID string            `json:"trace_session_id,omitempty"`
	Running        bool              `json:"running"`
}

type ChannelCoreRunner struct{ store *Store }

type ChannelCoreChild struct {
	runner *ChannelCoreRunner
	reg    Registration
	cfg    channelCoreChildConfig

	mu     sync.Mutex
	st     ChannelCoreStatus
	paused bool
	in     chan childLine
	ctl    chan childLine
	cancel context.CancelFunc
	done   chan struct{}
}

type channelCoreChildConfig struct {
	Coalesce      time.Duration
	RateLimit     time.Duration
	InspectDelay  time.Duration
	OatsBin       string
	AWCommand     string
	AdmissionSize int
	Paused        bool
	Log           func(string, ...any)
	OnInactive    func(string)
}

type childBinding struct {
	BindingID         string `json:"binding_id"`
	IdentityHome      string `json:"identity_home"`
	TeamID            string `json:"team_id"`
	DeliveryStorePath string `json:"delivery_store_path"`
}

type initLine struct {
	Type           string         `json:"type"`
	Home           string         `json:"home"`
	OatsBin        string         `json:"oatsBin,omitempty"`
	AWCommand      string         `json:"awCommand,omitempty"`
	CoalesceMs     int            `json:"coalesceMs,omitempty"`
	RateLimitMs    int            `json:"rateLimitMs,omitempty"`
	InspectDelayMs int            `json:"inspectDelayMs,omitempty"`
	Paused         bool           `json:"paused,omitempty"`
	Bindings       []childBinding `json:"bindings"`
}

type childLine struct {
	Type      string         `json:"type"`
	BindingID string         `json:"binding_id,omitempty"`
	Event     map[string]any `json:"event,omitempty"`
}

type childStatusLine struct {
	Type           string `json:"type"`
	Inactive       string `json:"inactive,omitempty"`
	LastInputAt    string `json:"last_input_at,omitempty"`
	LastError      string `json:"last_error,omitempty"`
	AmbientQueued  *int   `json:"ambient_queued,omitempty"`
	AmbientDropped *int   `json:"ambient_dropped,omitempty"`
	Ready          bool   `json:"ready,omitempty"`
	Stopped        bool   `json:"stopped,omitempty"`
	Fatal          bool   `json:"fatal,omitempty"`
	Delivered      bool   `json:"delivered,omitempty"`
	BindingID      string `json:"binding_id,omitempty"`
	Error          string `json:"error,omitempty"`
	TraceStage     string `json:"trace_stage,omitempty"`
	TraceMessageID string `json:"trace_message_id,omitempty"`
	TraceSessionID string `json:"trace_session_id,omitempty"`
	Log            string `json:"log,omitempty"`
}

func NewChannelCoreRunner(store *Store) *ChannelCoreRunner { return &ChannelCoreRunner{store: store} }

func (r *ChannelCoreRunner) Status() ChannelCoreStatus { return ChannelCoreStatus{} }

func (r *ChannelCoreRunner) StartChild(ctx context.Context, reg Registration, cfg channelCoreChildConfig) *ChannelCoreChild {
	if cfg.AdmissionSize <= 0 {
		cfg.AdmissionSize = 256
	}
	ctx, cancel := context.WithCancel(ctx)
	c := &ChannelCoreChild{runner: r, reg: reg.clone(), cfg: cfg, paused: cfg.Paused, in: make(chan childLine, cfg.AdmissionSize), ctl: make(chan childLine, 16), cancel: cancel, done: make(chan struct{})}
	go c.run(ctx)
	return c
}

func (c *ChannelCoreChild) Stop() {
	if c == nil {
		return
	}
	c.cancel()
	<-c.done
}

func (c *ChannelCoreChild) Pause(paused bool) {
	line := childLine{Type: "resume"}
	if paused {
		line.Type = "pause"
	}
	c.mu.Lock()
	c.paused = paused
	c.mu.Unlock()
	c.control(line)
}

func (c *ChannelCoreChild) Offer(binding ReceiveIdentity, ev awid.AgentEvent) {
	if teamID, err := effectiveTeamID(binding.IdentityHome, binding.TeamID); err == nil {
		binding.TeamID = teamID
	}
	c.offer(childLine{Type: "event", BindingID: bindingID(binding), Event: agentEventForChannelCore(ev)})
}

func (c *ChannelCoreChild) control(line childLine) {
	select {
	case c.ctl <- line:
		return
	default:
	}
	go func() { c.ctl <- line }()
}

func (c *ChannelCoreChild) offer(line childLine) {
	select {
	case c.in <- line:
		return
	default:
	}
	c.mu.Lock()
	c.st.Evicted++
	c.mu.Unlock()
	select {
	case <-c.in:
	default:
	}
	select {
	case c.in <- line:
	default:
	}
}

func (c *ChannelCoreChild) Status() ChannelCoreStatus {
	if c == nil {
		return ChannelCoreStatus{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	st := c.st
	if c.st.BindingErrors != nil {
		st.BindingErrors = make(map[string]string, len(c.st.BindingErrors))
		for key, value := range c.st.BindingErrors {
			st.BindingErrors[key] = value
		}
	}
	return st
}

func (c *ChannelCoreChild) run(ctx context.Context) {
	defer close(c.done)
	backoff := 100 * time.Millisecond
	for ctx.Err() == nil {
		err := c.runOnce(ctx)
		if ctx.Err() != nil {
			return
		}
		c.setError(err)
		if c.cfg.Log != nil {
			c.cfg.Log("channel-core child exited home=%s err=%v", c.reg.Home, err)
		}
		t := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
		if backoff < 2*time.Second {
			backoff *= 2
		}
	}
}

func (c *ChannelCoreChild) runOnce(ctx context.Context) error {
	node, err := exec.LookPath("node")
	if err != nil {
		c.setNode("", "", "system Node executable not found in PATH", false)
		return errors.New("system Node executable not found in PATH")
	}
	bundle, err := c.runner.bundlePath()
	if err != nil {
		c.setNode(node, "", err.Error(), false)
		return err
	}
	cmd := exec.CommandContext(ctx, node, bundle)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		c.setNode(node, bundle, err.Error(), false)
		return err
	}
	c.setNode(node, bundle, "", false)
	doneRead := make(chan struct{})
	go c.readStatus(stdout, doneRead)
	go c.readStderr(stderr)
	waitCh := make(chan error, 1)
	go func() { waitCh <- cmd.Wait() }()
	enc := json.NewEncoder(stdin)
	if err := enc.Encode(c.initLine()); err != nil {
		_ = cmd.Process.Kill()
		return err
	}
	for {
		select {
		case line := <-c.ctl:
			if err := enc.Encode(line); err != nil {
				_ = cmd.Process.Kill()
				<-waitCh
				<-doneRead
				c.setRunning(false)
				return err
			}
			continue
		default:
		}
		select {
		case <-ctx.Done():
			_ = enc.Encode(childLine{Type: "shutdown"})
			_ = stdin.Close()
			<-waitCh
			<-doneRead
			c.setRunning(false)
			return ctx.Err()
		case err := <-waitCh:
			<-doneRead
			c.setRunning(false)
			if err == nil {
				err = errors.New("channel-core child exited")
			}
			return err
		case line := <-c.ctl:
			if err := enc.Encode(line); err != nil {
				_ = cmd.Process.Kill()
				<-waitCh
				<-doneRead
				c.setRunning(false)
				return err
			}
		case line := <-c.in:
			if err := enc.Encode(line); err != nil {
				_ = cmd.Process.Kill()
				<-waitCh
				<-doneRead
				c.setRunning(false)
				return err
			}
		}
	}
}

func (c *ChannelCoreChild) initLine() initLine {
	bindings := []childBinding{}
	for _, b := range c.reg.ReceiveBindings() {
		teamID, err := effectiveTeamID(b.IdentityHome, b.TeamID)
		if err != nil {
			teamID = b.TeamID
		}
		b.TeamID = teamID
		bindings = append(bindings, childBinding{BindingID: bindingID(b), IdentityHome: b.IdentityHome, TeamID: teamID, DeliveryStorePath: filepath.Join(b.IdentityHome, "channel-delivered-ids-"+safeTeamID(teamID)+".json")})
	}
	c.mu.Lock()
	paused := c.paused
	c.mu.Unlock()
	return initLine{Type: "init", Home: c.reg.Home, OatsBin: c.cfg.OatsBin, AWCommand: c.cfg.AWCommand, CoalesceMs: millis(c.cfg.Coalesce), RateLimitMs: millis(c.cfg.RateLimit), InspectDelayMs: millis(c.cfg.InspectDelay), Paused: paused, Bindings: bindings}
}

func (c *ChannelCoreChild) readStatus(r io.Reader, done chan<- struct{}) {
	defer close(done)
	s := bufio.NewScanner(r)
	for s.Scan() {
		var line childStatusLine
		if err := json.Unmarshal(s.Bytes(), &line); err != nil {
			continue
		}
		c.mu.Lock()
		if line.LastError != "" {
			c.st.LastError = line.LastError
		}
		if line.LastInputAt != "" {
			if t, err := time.Parse(time.RFC3339Nano, line.LastInputAt); err == nil {
				c.st.LastInputAt = t
				c.st.LastSuccessAt = t
			}
		}
		if line.Ready {
			c.st.Running = true
		}
		if line.AmbientQueued != nil {
			c.st.AmbientQueued = *line.AmbientQueued
		}
		if line.AmbientDropped != nil {
			c.st.AmbientDropped = *line.AmbientDropped
		}
		if line.TraceStage != "" {
			c.st.TraceStage = line.TraceStage
			c.st.TraceBindingID = line.BindingID
			c.st.TraceMessageID = line.TraceMessageID
			c.st.TraceSessionID = line.TraceSessionID
			if line.BindingID != "" && (line.TraceStage == "lane_job_completed" || line.TraceStage == "lane_job_started") && c.st.BindingErrors != nil {
				delete(c.st.BindingErrors, line.BindingID)
			}
		}
		if line.BindingID != "" && line.Error != "" {
			if c.st.BindingErrors == nil {
				c.st.BindingErrors = map[string]string{}
			}
			c.st.BindingErrors[line.BindingID] = line.Error
		}
		c.mu.Unlock()
		if line.Inactive != "" && c.cfg.OnInactive != nil {
			c.cfg.OnInactive(line.Inactive)
		}
	}
}

func (c *ChannelCoreChild) readStderr(r io.Reader) {
	if c.cfg.Log == nil {
		_, _ = io.Copy(io.Discard, r)
		return
	}
	s := bufio.NewScanner(r)
	for s.Scan() {
		c.cfg.Log("channel-core child stderr home=%s: %s", c.reg.Home, s.Text())
	}
}

func (c *ChannelCoreChild) setNode(node, bundle, err string, running bool) {
	c.mu.Lock()
	c.st.NodePath = node
	c.st.BundlePath = bundle
	c.st.LastError = err
	c.st.LastRunAt = time.Now().UTC()
	c.st.Running = running
	c.mu.Unlock()
}
func (c *ChannelCoreChild) setRunning(running bool) {
	c.mu.Lock()
	c.st.Running = running
	c.mu.Unlock()
}
func (c *ChannelCoreChild) setError(err error) {
	if err == nil {
		return
	}
	c.mu.Lock()
	c.st.LastError = err.Error()
	c.st.Running = false
	c.mu.Unlock()
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
func bindingID(b ReceiveIdentity) string { return b.IdentityHome + "|" + b.TeamID }
func safeTeamID(team string) string {
	s := strings.NewReplacer("/", "_", ":", "_", "\\", "_").Replace(team)
	if s == "" {
		return "default"
	}
	return s
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
