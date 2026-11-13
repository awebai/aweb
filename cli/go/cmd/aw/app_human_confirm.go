package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"time"

	"github.com/awebai/aw/internal/appmanifest"
	"github.com/awebai/aw/internal/handoff"
)

// confirmPollInterval is the most often a confirm's state is read.
const confirmPollInterval = 2 * time.Second

// confirmSteps are what completing a confirm action needs: the completion
// read and the confirm, each in the current session, a renewal that opens a
// fresh session for both, and the pause between reads.
type confirmSteps struct {
	Completion appmanifest.Completion
	Read       func(context.Context) (*handoff.Response, error)
	Confirm    func(context.Context) (*handoff.Response, error)
	Renew      func(context.Context) error
	Sleep      func(time.Duration)
}

// confirmOutcome is a completed confirm: "applied" with the confirm's
// response, or "confirm_already_applied".
type confirmOutcome struct {
	Code     string
	Response *handoff.Response
}

// runConfirm completes a confirm action as human-confirmation-from-aw.md
// ("Completion of a confirm") defines it. It sends the confirm at most once,
// renews the session at most once, and never renews on a refused renewal or
// a lost holding.
func runConfirm(ctx context.Context, s confirmSteps) (confirmOutcome, error) {
	sent, renewed := false, false
	renew := func() error {
		if renewed {
			return withErrorCode("console_session_required", errors.New("the app refused the renewed session too"))
		}
		renewed = true
		return s.Renew(ctx)
	}
	for {
		resp, err := s.Read(ctx)
		if err != nil {
			return confirmOutcome{}, err
		}
		switch refusal := sessionRefusal(resp); refusal {
		case "console_session_required":
			if err := renew(); err != nil {
				return confirmOutcome{}, err
			}
			continue
		case "role_not_held":
			return confirmOutcome{}, roleNotHeld(sent)
		case "":
		default:
			return confirmOutcome{}, appRefusal(resp)
		}
		state, err := decodeState(resp)
		if err != nil {
			return confirmOutcome{}, err
		}
		done, stopped, ready := holds(state, s.Completion.Done), stopping(state, s.Completion.Stop), holds(state, s.Completion.Ready)
		if sent {
			switch {
			case done:
				return confirmOutcome{}, withErrorCode("confirm_result_lost", errors.New("the change was applied, but its reply was lost; a one-time output in it is not recovered"))
			case stopped != "":
				return confirmOutcome{}, withErrorCode("confirm_stopped", fmt.Errorf("after the confirm, the change reads %s", stopped))
			default:
				return confirmOutcome{}, withErrorCode("confirm_not_applied", fmt.Errorf("the confirm's reply was lost and the change was not applied when read (%s); a confirm still committing may yet land, and aw does not send it again", describeState(state, s.Completion)))
			}
		}
		switch {
		case done:
			return confirmOutcome{Code: "confirm_already_applied"}, nil
		case stopped != "":
			return confirmOutcome{}, withErrorCode("confirm_stopped", fmt.Errorf("the change reads %s", stopped))
		case !ready:
			s.Sleep(confirmPollInterval)
			continue
		}
		sent = true
		reply, err := s.Confirm(ctx)
		if err != nil || lostReply(reply) {
			continue
		}
		switch refusal := sessionRefusal(reply); refusal {
		case "console_session_required":
			if err := renew(); err != nil {
				return confirmOutcome{}, err
			}
			continue
		case "role_not_held":
			return confirmOutcome{}, roleNotHeld(true)
		case "":
			return confirmOutcome{Code: "applied", Response: reply}, nil
		default:
			return confirmOutcome{}, appRefusal(reply)
		}
	}
}

// sessionRefusal is "" for a 2xx answer, the session codes aw acts on, or
// "refused" for any other answer.
func sessionRefusal(resp *handoff.Response) string {
	if resp.Status >= 200 && resp.Status < 300 {
		return ""
	}
	code := handoff.RefusalCode(resp.Body)
	if (resp.Status == http.StatusUnauthorized && code == "console_session_required") || (resp.Status == http.StatusForbidden && code == "role_not_held") {
		return code
	}
	return "refused"
}

// lostReply is a confirm answer that says nothing about the change: a 5xx
// with no JSON body.
func lostReply(resp *handoff.Response) bool {
	return resp.Status >= 500 && !json.Valid(bytes.TrimSpace(resp.Body))
}

func roleNotHeld(sent bool) error {
	if sent {
		return withErrorCode("role_not_held", errors.New("the holding was revoked; the confirm was sent and its outcome was not read"))
	}
	return withErrorCode("role_not_held", errors.New("the holding was revoked"))
}

// appRefusal passes an app's refusal through with its status and detail.
func appRefusal(resp *handoff.Response) error {
	code := handoff.RefusalCode(resp.Body)
	if code == "" {
		code = fmt.Sprintf("app_http_%d", resp.Status)
	}
	return withErrorCode(code, fmt.Errorf("the app refused (%d %s)", resp.Status, code))
}

func decodeState(resp *handoff.Response) (map[string]any, error) {
	decoder := json.NewDecoder(bytes.NewReader(resp.Body))
	decoder.UseNumber()
	var state map[string]any
	if err := decoder.Decode(&state); err != nil || state == nil {
		return nil, fmt.Errorf("the completion read did not answer a JSON object")
	}
	return state, nil
}

// holds reports whether state's member is one of p's values, compared by
// JSON type and value.
func holds(state map[string]any, p appmanifest.Predicate) bool {
	value, ok := state[p.Member]
	if !ok {
		return false
	}
	for _, raw := range p.In {
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		var want any
		if decoder.Decode(&want) == nil && reflect.DeepEqual(value, want) {
			return true
		}
	}
	return false
}

// stopping names the first stop predicate state meets, as "member=value".
func stopping(state map[string]any, stops []appmanifest.Predicate) string {
	for _, p := range stops {
		if holds(state, p) {
			value, _ := json.Marshal(state[p.Member])
			return p.Member + "=" + string(value)
		}
	}
	return ""
}

func describeState(state map[string]any, c appmanifest.Completion) string {
	var parts []string
	for _, member := range []string{c.Ready.Member, c.Done.Member} {
		value, _ := json.Marshal(state[member])
		parts = append(parts, member+"="+string(value))
	}
	return strings.Join(parts, ", ")
}
