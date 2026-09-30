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
	"math/rand"
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
var wakePipe = os.Pipe

type ChannelCoreStatus struct {
	NodePath         string            `json:"node_path,omitempty"`
	BundlePath       string            `json:"bundle_path,omitempty"`
	LastError        string            `json:"last_error,omitempty"`
	LastRunAt        time.Time         `json:"last_run_at,omitempty"`
	LastSuccessAt    time.Time         `json:"last_success_at,omitempty"`
	LastInputAt      time.Time         `json:"last_input_at,omitempty"`
	AmbientQueued    int               `json:"ambient_queued"`
	AmbientDropped   int               `json:"ambient_dropped"`
	Evicted          int               `json:"evicted_events"`
	BindingErrors    map[string]string `json:"binding_errors,omitempty"`
	Generation       int               `json:"generation,omitempty"`
	Paused           bool              `json:"paused,omitempty"`
	ReadinessState   string            `json:"readiness_state,omitempty"`
	ReadinessError   string            `json:"readiness_error,omitempty"`
	ReadinessPaused  bool              `json:"readiness_paused,omitempty"`
	ReadinessWaiting string            `json:"readiness_waiting,omitempty"`
	RestartCount     int               `json:"restart_count,omitempty"`
	LastExit         string            `json:"last_exit,omitempty"`
	NextRetryAt      time.Time         `json:"next_retry_at,omitempty"`
	TraceStage       string            `json:"trace_stage,omitempty"`
	TraceBindingID   string            `json:"trace_binding_id,omitempty"`
	TraceMessageID   string            `json:"trace_message_id,omitempty"`
	TraceSessionID   string            `json:"trace_session_id,omitempty"`
	Running          bool              `json:"running"`
}

type ChannelCoreRunner struct{ store *Store }

type childPipes struct {
	stdinWriter  *os.File
	stdinReader  *os.File
	stdoutReader *os.File
	stdoutWriter *os.File
	stderrReader *os.File
	stderrWriter *os.File
}

func openChildPipes() (_ childPipes, err error) {
	var p childPipes
	defer func() {
		if err != nil {
			p.closeAll()
		}
	}()
	if p.stdinReader, p.stdinWriter, err = wakePipe(); err != nil {
		return p, err
	}
	if p.stdoutReader, p.stdoutWriter, err = wakePipe(); err != nil {
		return p, err
	}
	if p.stderrReader, p.stderrWriter, err = wakePipe(); err != nil {
		return p, err
	}
	return p, nil
}

func (p childPipes) closeChildEnds() {
	if p.stdinReader != nil {
		_ = p.stdinReader.Close()
	}
	if p.stdoutWriter != nil {
		_ = p.stdoutWriter.Close()
	}
	if p.stderrWriter != nil {
		_ = p.stderrWriter.Close()
	}
}

func (p childPipes) closeParentEnds() {
	if p.stdinWriter != nil {
		_ = p.stdinWriter.Close()
	}
	if p.stdoutReader != nil {
		_ = p.stdoutReader.Close()
	}
	if p.stderrReader != nil {
		_ = p.stderrReader.Close()
	}
}

func (p childPipes) closeAll() {
	p.closeChildEnds()
	p.closeParentEnds()
}

type ChannelCoreChild struct {
	runner *ChannelCoreRunner
	reg    Registration
	cfg    channelCoreChildConfig

	mu         sync.Mutex
	st         ChannelCoreStatus
	paused     bool
	lastStderr string
	readyAt    time.Time
	in         chan childLine
	ctl        chan childLine
	cancel     context.CancelFunc
	done       chan struct{}
}

type channelCoreChildConfig struct {
	Coalesce          time.Duration
	RateLimit         time.Duration
	InspectDelay      time.Duration
	OatsBin           string
	AWCommand         string
	AdmissionSize     int
	Paused            bool
	Generation        int
	Log               func(string, ...any)
	OnInactive        func(string)
	OnLiveness        func(time.Time, string, string)
	RestartBackoffMin time.Duration
	RestartBackoffMax time.Duration
	RestartReadyReset time.Duration
	ShutdownTimeout   time.Duration
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
	Type             string  `json:"type"`
	Inactive         string  `json:"inactive,omitempty"`
	LastInputAt      string  `json:"last_input_at,omitempty"`
	LastError        string  `json:"last_error,omitempty"`
	AmbientQueued    *int    `json:"ambient_queued,omitempty"`
	AmbientDropped   *int    `json:"ambient_dropped,omitempty"`
	Ready            bool    `json:"ready,omitempty"`
	Stopped          bool    `json:"stopped,omitempty"`
	Fatal            bool    `json:"fatal,omitempty"`
	Delivered        bool    `json:"delivered,omitempty"`
	Paused           *bool   `json:"paused,omitempty"`
	BindingID        string  `json:"binding_id,omitempty"`
	Error            string  `json:"error,omitempty"`
	ReadinessState   string  `json:"readiness_state,omitempty"`
	ReadinessError   *string `json:"readiness_error,omitempty"`
	ReadinessPaused  *bool   `json:"readiness_paused,omitempty"`
	ReadinessWaiting string  `json:"readiness_waiting,omitempty"`
	TraceStage       string  `json:"trace_stage,omitempty"`
	TraceMessageID   string  `json:"trace_message_id,omitempty"`
	TraceSessionID   string  `json:"trace_session_id,omitempty"`
	Log              string  `json:"log,omitempty"`
}

const (
	defaultChildBackoffMin = 100 * time.Millisecond
	defaultChildBackoffMax = 60 * time.Second
	defaultChildReadyReset = 60 * time.Second
)

func NewChannelCoreRunner(store *Store) *ChannelCoreRunner { return &ChannelCoreRunner{store: store} }

func (r *ChannelCoreRunner) Status() ChannelCoreStatus { return ChannelCoreStatus{} }

func (r *ChannelCoreRunner) StartChild(ctx context.Context, reg Registration, cfg channelCoreChildConfig) *ChannelCoreChild {
	if cfg.AdmissionSize <= 0 {
		cfg.AdmissionSize = 256
	}
	ctx, cancel := context.WithCancel(ctx)
	c := &ChannelCoreChild{runner: r, reg: reg.clone(), cfg: cfg, paused: cfg.Paused, in: make(chan childLine, cfg.AdmissionSize), ctl: make(chan childLine, 16), cancel: cancel, done: make(chan struct{})}
	c.st.Generation = cfg.Generation
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
	// Keep only the latest pending control when the bounded queue fills.
	// The authoritative pause value is also carried by every new init line.
	select {
	case <-c.ctl:
	default:
	}
	select {
	case c.ctl <- line:
	default:
	}
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
	minBackoff := c.cfg.RestartBackoffMin
	if minBackoff <= 0 {
		minBackoff = defaultChildBackoffMin
	}
	maxBackoff := c.cfg.RestartBackoffMax
	if maxBackoff <= 0 {
		maxBackoff = defaultChildBackoffMax
	}
	if maxBackoff < minBackoff {
		maxBackoff = minBackoff
	}
	readyReset := c.cfg.RestartReadyReset
	if readyReset <= 0 {
		readyReset = defaultChildReadyReset
	}
	backoff := minBackoff
	for ctx.Err() == nil {
		err := c.runOnce(ctx)
		if ctx.Err() != nil {
			return
		}
		readyFor := c.readyDuration()
		c.recordExit(err)
		c.setError(err)
		if c.cfg.Log != nil {
			c.cfg.Log("channel-core child exited home=%s err=%v", c.reg.Home, err)
		}
		if readyFor >= readyReset {
			backoff = minBackoff
		}
		delay := jitteredBackoff(backoff)
		c.setNextRetry(delay)
		t := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
		c.clearNextRetry()
		if backoff < maxBackoff {
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
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
	childCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd := exec.CommandContext(childCtx, node, bundle)
	configureChildProcess(cmd)
	pipes, err := openChildPipes()
	if err != nil {
		return err
	}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = pipes.stdinReader, pipes.stdoutWriter, pipes.stderrWriter
	grace := c.cfg.ShutdownTimeout
	if grace <= 0 {
		grace = 5 * time.Second
	}
	cmd.WaitDelay = grace
	writerCtx, stopWriter := context.WithCancel(context.Background())
	defer stopWriter()
	writerDone := make(chan struct{})
	writerErrors := make(chan error, 1)
	// Cancel never waits on an unbounded pipe write. Interrupt any current write,
	// allow the sole encoder a bounded shutdown attempt, then request termination.
	cmd.Cancel = func() error {
		_ = pipes.stdinWriter.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
		stopWriter()
		<-writerDone
		return terminateChildProcess(cmd)
	}
	if err := cmd.Start(); err != nil {
		pipes.closeAll()
		c.setNode(node, bundle, err.Error(), false)
		return err
	}
	pipes.closeChildEnds()
	c.setNode(node, bundle, "", false)
	go func() {
		defer close(writerDone)
		enc := json.NewEncoder(pipes.stdinWriter)
		err := enc.Encode(c.initLine())
		for err == nil && writerCtx.Err() == nil {
			var line childLine
			select {
			case <-writerCtx.Done():
				continue
			case line = <-c.ctl:
			default:
				select {
				case <-writerCtx.Done():
					continue
				case line = <-c.ctl:
				case line = <-c.in:
				}
			}
			err = enc.Encode(line)
		}
		if writerCtx.Err() != nil {
			_ = pipes.stdinWriter.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
			_ = enc.Encode(childLine{Type: "shutdown"})
		} else if err != nil {
			writerErrors <- err
		}
	}()
	doneRead := make(chan struct{})
	fatal := make(chan error, 1)
	go c.readStatus(pipes.stdoutReader, doneRead, fatal)
	doneStderr := make(chan struct{})
	go func() { defer close(doneStderr); c.readStderr(pipes.stderrReader) }()
	waitCh := make(chan error, 1)
	go func() { waitCh <- cmd.Wait() }()
	// Command's WaitDelay kills the direct child. Independently kill its group
	// at the same deadline so descendants cannot survive or retain output pipes.
	groupDone := make(chan struct{})
	stopGroupWatch := make(chan struct{})
	go func() {
		defer close(groupDone)
		select {
		case <-childCtx.Done():
		case <-stopGroupWatch:
			return
		}
		timer := time.NewTimer(grace)
		defer timer.Stop()
		select {
		case <-timer.C:
			killChildProcessGroup(cmd)
		case <-stopGroupWatch:
		}
	}()
	finish := func(err error) error {
		close(stopGroupWatch)
		<-groupDone
		killChildProcessGroup(cmd)
		stopWriter()
		_ = pipes.stdinWriter.Close()
		<-writerDone
		waitForReaderEOF(doneRead, 2*time.Second)
		waitForReaderEOF(doneStderr, 2*time.Second)
		pipes.closeParentEnds()
		<-doneRead
		<-doneStderr
		c.setRunning(false)
		return err
	}
	select {
	case <-ctx.Done():
		cancel()
		<-waitCh
		return finish(ctx.Err())
	case err := <-fatal:
		cancel()
		<-waitCh
		return finish(err)
	case err := <-writerErrors:
		cancel()
		<-waitCh
		return finish(err)
	case err := <-waitCh:
		if err == nil {
			err = errors.New("channel-core child exited")
		}
		return finish(err)
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

func (c *ChannelCoreChild) readStatus(r io.Reader, done chan<- struct{}, fatalChannels ...chan<- error) {
	defer close(done)
	c.readChildLines(r, func(data []byte) {
		var line childStatusLine
		if err := json.Unmarshal(data, &line); err != nil {
			return
		}
		if line.Fatal && len(fatalChannels) > 0 {
			detail := line.LastError
			if detail == "" {
				detail = "channel-core child reported fatal"
			}
			select {
			case fatalChannels[0] <- errors.New(detail):
			default:
			}
		}
		now := time.Now().UTC()
		var livenessState string
		var livenessError string
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
			if !c.st.Running || c.readyAt.IsZero() {
				c.readyAt = time.Now().UTC()
			}
			c.st.Running = true
			c.st.NextRetryAt = time.Time{}
		}
		if line.AmbientQueued != nil {
			c.st.AmbientQueued = *line.AmbientQueued
		}
		if line.AmbientDropped != nil {
			c.st.AmbientDropped = *line.AmbientDropped
		}
		if line.Paused != nil {
			c.st.Paused = *line.Paused
		}
		if line.ReadinessState != "" {
			c.st.ReadinessState = line.ReadinessState
			livenessState = line.ReadinessState
		}
		if line.ReadinessError != nil {
			c.st.ReadinessError = *line.ReadinessError
			livenessError = *line.ReadinessError
		}
		if line.ReadinessPaused != nil {
			c.st.ReadinessPaused = *line.ReadinessPaused
		}
		if line.ReadinessWaiting != "" {
			c.st.ReadinessWaiting = line.ReadinessWaiting
		}
		if line.TraceStage != "" {
			c.st.TraceStage = line.TraceStage
			c.st.TraceBindingID = line.BindingID
			c.st.TraceMessageID = line.TraceMessageID
			c.st.TraceSessionID = line.TraceSessionID
			if line.BindingID != "" && line.TraceStage == "lane_job_completed" && c.st.BindingErrors != nil {
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
		if c.cfg.OnLiveness != nil && (livenessState != "" || livenessError != "") {
			c.cfg.OnLiveness(now, livenessState, livenessError)
		}
		if line.Inactive != "" && c.cfg.OnInactive != nil {
			c.cfg.OnInactive(line.Inactive)
		}
	})
}

func waitForReaderEOF(done <-chan struct{}, timeout time.Duration) {
	if timeout <= 0 {
		<-done
		return
	}
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case <-done:
	case <-t.C:
	}
}

func (c *ChannelCoreChild) readStderr(r io.Reader) {
	c.readChildLines(r, func(data []byte) {
		line := string(data)
		c.mu.Lock()
		c.lastStderr = line
		c.mu.Unlock()
		if c.cfg.Log != nil {
			c.cfg.Log("channel-core child stderr home=%s: %s", c.reg.Home, line)
		}
	})
}

// readChildLines bounds memory per record while continuing to drain an
// oversized record. A scanner stops on overflow and can wedge the child writer.
func (c *ChannelCoreChild) readChildLines(r io.Reader, consume func([]byte)) {
	const maxLine = 1024 * 1024
	reader := bufio.NewReaderSize(r, 32*1024)
	var line []byte
	dropping := false
	for {
		part, err := reader.ReadSlice('\n')
		if !dropping {
			if len(line)+len(part) > maxLine {
				dropping = true
				line = nil
				c.mu.Lock()
				c.st.LastError = "channel-core child output line exceeds 1 MiB; discarded"
				c.mu.Unlock()
				if c.cfg.Log != nil {
					c.cfg.Log("channel-core child output line exceeds 1 MiB home=%s; discarded", c.reg.Home)
				}
			} else {
				line = append(line, part...)
			}
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		if !dropping && len(line) > 0 {
			consume([]byte(strings.TrimSuffix(strings.TrimSuffix(string(line), "\n"), "\r")))
		}
		line = line[:0]
		dropping = false
		if err != nil {
			if err != io.EOF {
				c.mu.Lock()
				c.st.LastError = "channel-core child output read: " + err.Error()
				c.mu.Unlock()
			}
			return
		}
	}
}

func (c *ChannelCoreChild) setNode(node, bundle, err string, running bool) {
	c.mu.Lock()
	c.st.NodePath = node
	c.st.BundlePath = bundle
	c.st.LastError = err
	c.st.LastRunAt = time.Now().UTC()
	c.st.Running = running
	c.st.NextRetryAt = time.Time{}
	if err == "" {
		c.resetPerRunLocked()
	}
	c.mu.Unlock()
}

func (c *ChannelCoreChild) resetPerRunLocked() {
	c.st.AmbientQueued = 0
	c.st.AmbientDropped = 0
	c.st.ReadinessState = ""
	c.st.ReadinessError = ""
	c.st.ReadinessPaused = false
	c.st.ReadinessWaiting = ""
	c.st.TraceStage = ""
	c.st.TraceBindingID = ""
	c.st.TraceMessageID = ""
	c.st.TraceSessionID = ""
	c.readyAt = time.Time{}
	c.lastStderr = ""
}

func jitteredBackoff(base time.Duration) time.Duration {
	if base <= 0 {
		return 0
	}
	// Add up to 20% jitter. This avoids synchronized fleet retries without
	// shortening the configured recovery bound.
	maxJitter := int64(base / 5)
	if maxJitter <= 0 {
		return base
	}
	return base + time.Duration(rand.Int63n(maxJitter+1))
}

func (c *ChannelCoreChild) readyDuration() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.readyAt.IsZero() {
		return 0
	}
	return time.Since(c.readyAt)
}

func (c *ChannelCoreChild) recordExit(err error) {
	if err == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.st.RestartCount++
	text := err.Error()
	if c.lastStderr != "" {
		text += "; stderr: " + c.lastStderr
	}
	c.st.LastExit = text
}
func (c *ChannelCoreChild) setNextRetry(delay time.Duration) {
	c.mu.Lock()
	c.st.NextRetryAt = time.Now().Add(delay).UTC()
	c.mu.Unlock()
}
func (c *ChannelCoreChild) clearNextRetry() {
	c.mu.Lock()
	c.st.NextRetryAt = time.Time{}
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
