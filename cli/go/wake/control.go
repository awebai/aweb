package wake

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

// The control surface is a local unix socket under the state directory.
//
// register, deregister, pause, resume and status talk to the running daemon
// over it, and fall back to writing the state files directly when the daemon
// is down, so an OATS hook never fails because the broker is restarting. The
// daemon reconciles the files on start and on a timer, so a fallback write is
// picked up either way.

// ControlOp names a control request.
type ControlOp string

const (
	OpRegister   ControlOp = "register"
	OpDeregister ControlOp = "deregister"
	OpPause      ControlOp = "pause"
	OpResume     ControlOp = "resume"
	OpStatus     ControlOp = "status"
)

// ControlRequest is one line of JSON sent to the daemon.
type ControlRequest struct {
	Op           ControlOp     `json:"op"`
	Registration *Registration `json:"registration,omitempty"`
	Home         string        `json:"home,omitempty"`
}

// ControlResponse is the daemon's single-line answer.
type ControlResponse struct {
	OK      bool    `json:"ok"`
	Error   string  `json:"error,omitempty"`
	Existed bool    `json:"existed,omitempty"`
	Status  *Status `json:"status,omitempty"`
}

// ErrDaemonDown reports that no broker is listening on the control socket.
var ErrDaemonDown = errors.New("wake: broker daemon is not running")

// controlDeadline bounds one control exchange so a wedged daemon cannot hang a
// spawn hook.
const controlDeadline = 5 * time.Second

// maxSocketPath is the practical sun_path bound on the platforms this runs on
// (104 on macOS/BSD, 108 on Linux). A path over it fails inside the kernel with
// nothing but "invalid argument", so the bound is checked here where the fix
// can be named.
const maxSocketPath = 100

// ServeControl listens on the store's control socket until ctx is done.
func ServeControl(ctx context.Context, b *Broker) error {
	path := b.cfg.Store.SocketPath()
	if len(path) > maxSocketPath {
		return fmt.Errorf("wake: control socket path is %d bytes, over the %d-byte unix socket limit: %s. Use a shorter --state-dir (or AW_WAKE_STATE_DIR)", len(path), maxSocketPath, path)
	}
	// A socket left by a crashed daemon is stale by the time the lock has been
	// taken, so removing it is safe and is what makes restart unconditional.
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = listener.Close()
		return err
	}

	go func() {
		<-ctx.Done()
		_ = listener.Close()
		_ = os.Remove(path)
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			b.cfg.Log("control accept failed err=%v", err)
			continue
		}
		go handleControlConn(ctx, b, conn)
	}
}

func handleControlConn(ctx context.Context, b *Broker, conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(controlDeadline))

	reader := bufio.NewReader(conn)
	line, err := reader.ReadBytes('\n')
	if err != nil && len(strings.TrimSpace(string(line))) == 0 {
		return
	}
	var req ControlRequest
	if err := json.Unmarshal(line, &req); err != nil {
		writeControlResponse(conn, ControlResponse{Error: "malformed control request"})
		return
	}
	writeControlResponse(conn, b.Handle(ctx, req))
}

// Handle applies one control request. It is exported so a test can drive the
// daemon's control semantics without a socket.
func (b *Broker) Handle(_ context.Context, req ControlRequest) ControlResponse {
	switch req.Op {
	case OpRegister:
		if req.Registration == nil {
			return ControlResponse{Error: "register requires a registration"}
		}
		if err := b.Register(*req.Registration); err != nil {
			return ControlResponse{Error: err.Error()}
		}
		return ControlResponse{OK: true}
	case OpDeregister:
		existed, err := b.Deregister(req.Home)
		if err != nil {
			return ControlResponse{Error: err.Error()}
		}
		return ControlResponse{OK: true, Existed: existed}
	case OpPause, OpResume:
		if err := b.SetPaused(req.Home, req.Op == OpPause); err != nil {
			return ControlResponse{Error: err.Error()}
		}
		return ControlResponse{OK: true}
	case OpStatus:
		status := b.Status()
		return ControlResponse{OK: true, Status: &status}
	default:
		return ControlResponse{Error: fmt.Sprintf("unknown control op %q", req.Op)}
	}
}

func writeControlResponse(conn net.Conn, resp ControlResponse) {
	data, err := json.Marshal(resp)
	if err != nil {
		return
	}
	_, _ = conn.Write(append(data, '\n'))
}

// Call sends one control request to the daemon. It returns ErrDaemonDown when
// nothing is listening, which is the caller's signal to use the file fallback.
func Call(socketPath string, req ControlRequest) (ControlResponse, error) {
	conn, err := net.DialTimeout("unix", socketPath, controlDeadline)
	if err != nil {
		return ControlResponse{}, fmt.Errorf("%w: %v", ErrDaemonDown, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(controlDeadline))

	data, err := json.Marshal(req)
	if err != nil {
		return ControlResponse{}, err
	}
	if _, err := conn.Write(append(data, '\n')); err != nil {
		return ControlResponse{}, fmt.Errorf("%w: %v", ErrDaemonDown, err)
	}
	line, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil && len(strings.TrimSpace(string(line))) == 0 {
		return ControlResponse{}, fmt.Errorf("%w: %v", ErrDaemonDown, err)
	}
	var resp ControlResponse
	if err := json.Unmarshal(line, &resp); err != nil {
		return ControlResponse{}, fmt.Errorf("wake: malformed daemon response: %w", err)
	}
	if !resp.OK && strings.TrimSpace(resp.Error) != "" {
		return resp, errors.New(resp.Error)
	}
	return resp, nil
}

// StatusFromStore builds a status answer with the daemon down: the
// registrations and the per-instance state files, plus whatever the daemon
// last mirrored into status.json.
func StatusFromStore(store *Store, maxStreams int) (Status, error) {
	registrations, err := store.ListRegistrations()
	if err != nil {
		return Status{}, err
	}
	status := Status{
		UpdatedAt:  time.Now().UTC(),
		StateDir:   store.Dir(),
		MaxStreams: maxStreams,
		Streams:    []StreamStatus{},
		Instances:  []InstanceStatus{},
	}
	if pid, alive := LockOwner(store.LockDir()); alive {
		status.DaemonRunning = true
		status.DaemonPID = pid
	}
	for _, reg := range registrations {
		state, err := store.LoadInstance(reg.Home)
		if err != nil {
			continue
		}
		phase := PhasePending
		switch {
		case state.Inactive:
			phase = PhaseInactive
		case state.ConfirmedLive():
			phase = PhaseActive
		}
		status.Instances = append(status.Instances, InstanceStatus{
			Home:          reg.Home,
			IdentityHome:  reg.IdentityHome,
			Backend:       reg.Backend,
			Delivery:      reg.Delivery,
			RegisteredAt:  reg.RegisteredAt,
			Phase:         phase,
			Paused:        state.Paused,
			PendingHints:  len(state.Pending),
			Evicted:       state.Evicted,
			LastInspectAt: state.LastInspectAt,
			LastAttemptAt: state.LastAttemptAt,
			LastSubmitAt:  state.LastSubmitAt,
			LastState:     state.LastState,
			LastError:     state.LastError,
			UnreadCount:   state.UnreadCount,
		})
	}
	return status, nil
}
