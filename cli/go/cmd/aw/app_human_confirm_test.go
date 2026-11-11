package main

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/awebai/aw/internal/appmanifest"
	"github.com/awebai/aw/internal/handoff"
)

func secretsCompletion() appmanifest.Completion {
	raw := func(s string) json.RawMessage { return json.RawMessage(s) }
	return appmanifest.Completion{
		Read:  "change-set",
		Ready: appmanifest.Predicate{Member: "can_confirm", In: []json.RawMessage{raw("true")}},
		Done:  appmanifest.Predicate{Member: "state", In: []json.RawMessage{raw(`"applied"`)}},
		Stop: []appmanifest.Predicate{
			{Member: "state", In: []json.RawMessage{raw(`"cancelled"`), raw(`"expired"`)}},
			{Member: "approval_state", In: []json.RawMessage{raw(`"rejected"`)}},
		},
	}
}

// answer is one scripted reply: a response, or a transport failure.
type answer struct {
	status int
	body   string
	lost   bool
}

func (a answer) response() (*handoff.Response, error) {
	if a.lost {
		return nil, errors.New("connection reset")
	}
	return &handoff.Response{Status: a.status, Body: []byte(a.body)}, nil
}

type confirmScript struct {
	reads, confirms []answer
	renewals        []error
	readCalls       int
	confirmCalls    int
	renewCalls      int
}

func (s *confirmScript) steps() confirmSteps {
	return confirmSteps{
		Completion: secretsCompletion(),
		Read: func(context.Context) (*handoff.Response, error) {
			a := s.reads[min(s.readCalls, len(s.reads)-1)]
			s.readCalls++
			return a.response()
		},
		Confirm: func(context.Context) (*handoff.Response, error) {
			a := s.confirms[min(s.confirmCalls, len(s.confirms)-1)]
			s.confirmCalls++
			return a.response()
		},
		Renew: func(context.Context) error {
			s.renewCalls++
			if len(s.renewals) >= s.renewCalls {
				return s.renewals[s.renewCalls-1]
			}
			return nil
		},
		Sleep: func(time.Duration) {},
	}
}

var (
	pending      = answer{status: 200, body: `{"state":"pending","can_confirm":false,"approval_state":"pending"}`}
	ready        = answer{status: 200, body: `{"state":"approved","can_confirm":true,"approval_state":"approved"}`}
	readyAsOne   = answer{status: 200, body: `{"state":"approved","can_confirm":1,"approval_state":"approved"}`}
	applied      = answer{status: 200, body: `{"state":"applied","can_confirm":false}`}
	cancelled    = answer{status: 200, body: `{"state":"cancelled","can_confirm":false}`}
	sessionGone  = answer{status: 401, body: `{"detail":"console_session_required"}`}
	roleGone     = answer{status: 403, body: `{"detail":"role_not_held"}`}
	confirmed    = answer{status: 200, body: `{"state":"applied","runner_registrations":[]}`}
	droppedReply = answer{lost: true}
	gatewayError = answer{status: 502, body: `<html>bad gateway</html>`}
	notApproved  = answer{status: 409, body: `{"detail":"change_not_approved"}`}
)

func TestAConfirmIsSentOnceWhenTheChangeIsReady(t *testing.T) {
	s := &confirmScript{reads: []answer{pending, pending, ready}, confirms: []answer{confirmed}}
	outcome, err := runConfirm(context.Background(), s.steps())
	if err != nil || outcome.Code != "applied" || s.confirmCalls != 1 || s.readCalls != 3 {
		t.Fatalf("outcome %+v err %v reads %d confirms %d", outcome, err, s.readCalls, s.confirmCalls)
	}
}

func TestAnAppliedChangeIsNotConfirmedAgain(t *testing.T) {
	s := &confirmScript{reads: []answer{applied}, confirms: []answer{confirmed}}
	outcome, err := runConfirm(context.Background(), s.steps())
	if err != nil || outcome.Code != "confirm_already_applied" || s.confirmCalls != 0 {
		t.Fatalf("outcome %+v err %v confirms %d", outcome, err, s.confirmCalls)
	}
}

func TestAStoppedChangeRefusesWithItsState(t *testing.T) {
	s := &confirmScript{reads: []answer{cancelled}, confirms: []answer{confirmed}}
	if _, err := runConfirm(context.Background(), s.steps()); errorCodeOf(err) != "confirm_stopped" || s.confirmCalls != 0 {
		t.Fatalf("err %v confirms %d", err, s.confirmCalls)
	}
}

func TestPredicatesCompareByJSONType(t *testing.T) {
	s := &confirmScript{reads: []answer{readyAsOne, readyAsOne, ready}, confirms: []answer{confirmed}}
	if _, err := runConfirm(context.Background(), s.steps()); err != nil || s.readCalls != 3 {
		t.Fatalf("1 satisfied true: err %v reads %d", err, s.readCalls)
	}
}

func TestALostReplyIsReadAndNeverConfirmedAgain(t *testing.T) {
	for name, tc := range map[string]struct {
		lost  answer
		after answer
		code  string
	}{
		"applied after a lost reply":   {droppedReply, applied, "confirm_result_lost"},
		"ready after a lost reply":     {droppedReply, ready, "confirm_not_applied"},
		"applied after a bad gateway":  {gatewayError, applied, "confirm_result_lost"},
		"cancelled after a lost reply": {droppedReply, cancelled, "confirm_stopped"},
	} {
		s := &confirmScript{reads: []answer{ready, tc.after}, confirms: []answer{tc.lost, confirmed}}
		_, err := runConfirm(context.Background(), s.steps())
		if errorCodeOf(err) != tc.code || s.confirmCalls != 1 {
			t.Errorf("%s: err %v confirms %d", name, err, s.confirmCalls)
		}
	}
}

// The contract's sequence: confirm sent, reply lost, 401 on the next read,
// fresh handoff, read still ready while the first confirm commits.
func TestALostConfirmThenARenewalStillNeverConfirmsTwice(t *testing.T) {
	s := &confirmScript{reads: []answer{ready, sessionGone, ready}, confirms: []answer{droppedReply, confirmed}}
	_, err := runConfirm(context.Background(), s.steps())
	if errorCodeOf(err) != "confirm_not_applied" || s.confirmCalls != 1 || s.renewCalls != 1 {
		t.Fatalf("err %v confirms %d renewals %d", err, s.confirmCalls, s.renewCalls)
	}
}

func TestASessionIsRenewedAtMostOnce(t *testing.T) {
	s := &confirmScript{reads: []answer{sessionGone, sessionGone}, confirms: []answer{confirmed}}
	_, err := runConfirm(context.Background(), s.steps())
	if errorCodeOf(err) != "console_session_required" || s.renewCalls != 1 || s.confirmCalls != 0 {
		t.Fatalf("err %v renewals %d confirms %d", err, s.renewCalls, s.confirmCalls)
	}
}

func TestARefusedRenewalEndsTheCommand(t *testing.T) {
	refused := &codedError{code: "console_session_required", err: errors.New("start refused")}
	s := &confirmScript{reads: []answer{sessionGone, ready}, confirms: []answer{confirmed}, renewals: []error{refused}}
	_, err := runConfirm(context.Background(), s.steps())
	if errorCodeOf(err) != "console_session_required" || s.renewCalls != 1 || s.readCalls != 1 {
		t.Fatalf("err %v renewals %d reads %d", err, s.renewCalls, s.readCalls)
	}
}

func TestALostHoldingIsFinal(t *testing.T) {
	s := &confirmScript{reads: []answer{roleGone}, confirms: []answer{confirmed}}
	_, err := runConfirm(context.Background(), s.steps())
	if errorCodeOf(err) != "role_not_held" || s.renewCalls != 0 {
		t.Fatalf("err %v renewals %d", err, s.renewCalls)
	}
}

func TestTheAppsOwnRefusalPassesThrough(t *testing.T) {
	s := &confirmScript{reads: []answer{ready}, confirms: []answer{notApproved}}
	_, err := runConfirm(context.Background(), s.steps())
	if errorCodeOf(err) != "change_not_approved" || s.confirmCalls != 1 {
		t.Fatalf("err %v confirms %d", err, s.confirmCalls)
	}
}
