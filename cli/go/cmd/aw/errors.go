package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/awebai/aw/internal/termtext"
)

type cliError struct {
	code int
	msg  string
}

func (e *cliError) Error() string {
	return e.msg
}

func (e *cliError) ExitCode() int {
	if e.code <= 0 {
		return 1
	}
	return e.code
}

func usageError(format string, args ...any) error {
	return &cliError{
		code: 2,
		msg:  fmt.Sprintf(format, args...),
	}
}

func exitCode(err error) int {
	var coder interface{ ExitCode() int }
	if errors.As(err, &coder) {
		return coder.ExitCode()
	}
	return 1
}

// codedError names a refusal class for the --json error envelope. The code is
// the stable contract; the message and the exit code are those of err.
type codedError struct {
	code string
	err  error
}

func (e *codedError) Error() string { return e.err.Error() }

func (e *codedError) Unwrap() error { return e.err }

func withErrorCode(code string, err error) error {
	return &codedError{code: code, err: err}
}

// errorCodeOf is err's refusal code, or "" when it has none.
func errorCodeOf(err error) string {
	var pending *hostedInviteSignaturePendingError
	if errors.As(err, &pending) {
		return codeNativeAgentSignaturePending
	}
	var coded *codedError
	if errors.As(err, &coded) {
		return coded.code
	}
	// Any command that reads a team key refuses one set aside as unconfirmed.
	if errors.Is(err, awconfig.ErrTeamKeyUnconfirmed) {
		return codeTeamNameUnconfirmed
	}
	var certificate *awid.CurrentTeamCertificateError
	if errors.As(err, &certificate) {
		return string(certificate.Code)
	}
	return ""
}

// plainRefusal is a refusal by an aweb server or AWID registry told in a
// sentence for people. It wraps the refusal, so --json keeps its code, status
// and detail.
type plainRefusal struct {
	text string
	err  error
	// Preserve the server's sentence in JSON when terminal text names a target.
	jsonMessage string
}

func (e *plainRefusal) Error() string { return e.text }

func (e *plainRefusal) Unwrap() error { return e.err }

// isAliasConflict reports a refusal because another active member of the team
// holds the name.
func isAliasConflict(err error) bool {
	return awid.DescribeError(err).Code == "alias_conflict"
}

// recipientHumanMailOnly is the server's refusal of chat to a person: aweb
// reaches people by mail.
const recipientHumanMailOnly = "recipient_human_mail_only"

// humanMailOnlyRefusal says, for the server's refusal of chat that reaches a
// person, that people are reached by mail, under that refusal's code. It
// names only the people the server names in recipients: a refusal of a group
// does not say which member is a person, so aw never infers it. Any other
// error is returned as it is.
func humanMailOnlyRefusal(err error) error {
	if status, ok := awid.HTTPStatusCode(err); !ok || status != http.StatusUnprocessableEntity || httpErrorReason(err) != recipientHumanMailOnly {
		return err
	}
	var refusal struct {
		Recipients []string `json:"recipients"`
	}
	if body, ok := awid.HTTPErrorBody(err); ok {
		_ = json.Unmarshal([]byte(strings.TrimSpace(body)), &refusal)
	}
	people := make([]string, 0, len(refusal.Recipients))
	for _, recipient := range refusal.Recipients {
		if recipient = termtext.Line(strings.TrimSpace(recipient)); recipient != "" {
			people = append(people, recipient)
		}
	}
	text := "This chat includes a person; aweb reaches people by mail: aw mail send --to <their alias>"
	switch len(people) {
	case 0:
	case 1:
		text = fmt.Sprintf("%s is a person; aweb reaches people by mail: aw mail send --to %s", people[0], people[0])
	default:
		names := strings.Join(people[:len(people)-1], ", ") + " and " + people[len(people)-1]
		text = fmt.Sprintf("%s are people; aweb reaches people by mail: aw mail send --to %s", names, people[0])
	}
	return withErrorCode(recipientHumanMailOnly, &plainRefusal{text: text, err: err})
}

// nameTakenText says that another active member of teamID holds alias, and
// which flag of the command picks another name.
func nameTakenText(alias, teamID, flag string) string {
	return fmt.Sprintf("The name %s is already taken in %s. Pick another with %s.", alias, teamID, flag)
}

// cliErrorEnvelope is what --json prints for a failed command: the error's
// awid.ErrorDetail, with the code of a tagged refusal, and its message.
type cliErrorEnvelope struct {
	Error  cliErrorBody      `json:"error"`
	Invite *inviteInspection `json:"invite,omitempty"`
}

type cliErrorBody struct {
	Code       string `json:"code"`
	Message    string `json:"message"`
	HTTPStatus int    `json:"http_status,omitempty"`
	Detail     string `json:"detail,omitempty"`
	Reason     string `json:"reason,omitempty"`
}

func errorEnvelope(err error, message string) cliErrorEnvelope {
	var inspect *inviteInspectError
	if errors.As(err, &inspect) {
		envelope := cliErrorEnvelope{Error: cliErrorBody{Code: inspect.Code, Message: inspect.Message}}
		var failure *inviteInspectionFailure
		if errors.As(err, &failure) {
			envelope.Invite = failure.invite
		}
		return envelope
	}
	detail := awid.DescribeError(err)
	var plain *plainRefusal
	if errors.As(err, &plain) && plain.jsonMessage != "" {
		message = plain.jsonMessage
	}
	if code := errorCodeOf(err); code != "" {
		detail.Code = code
	}
	return cliErrorEnvelope{Error: cliErrorBody{Code: detail.Code, Message: message, HTTPStatus: detail.HTTPStatus, Detail: detail.Detail, Reason: detail.Reason}}
}

type cliErrorResult struct {
	Refusal error
	Message string
	JSON    bool
}

// writeCLIErrorResult owns the JSON error envelope and any retained text
// result from a failed command. The caller still owns stderr and exit status.
func writeCLIErrorResult(w io.Writer, result cliErrorResult) error {
	envelope := errorEnvelope(result.Refusal, result.Message)
	var err error
	if result.JSON {
		err = json.NewEncoder(w).Encode(envelope)
	} else if envelope.Invite != nil {
		err = formatInviteInspection(w, envelope.Invite)
	}
	if err != nil {
		return fmt.Errorf("write command output: %w; check the output destination and retry", err)
	}
	return nil
}
