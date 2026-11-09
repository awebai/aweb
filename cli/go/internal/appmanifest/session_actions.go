package appmanifest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// Session-action kinds. A read changes nothing; stage, draft and confirm
// write on the app's human origin in a role holder's session.
const (
	SessionActionRead    = "read"
	SessionActionStage   = "stage"
	SessionActionDraft   = "draft"
	SessionActionConfirm = "confirm"
)

const (
	maxSessionActions      = 64
	maxTerminalOutputs     = 16
	maxTerminalOutputDepth = 8
	maxCompletionStops     = 8
	maxPredicateValues     = 16
	maxSafeInteger         = 1<<53 - 1
	terminalOutputWildcard = "*"
)

// sessionActionMemberPattern is the manifest field-name grammar, which both a
// terminal_output member and a predicate member follow.
var sessionActionMemberPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// SessionAction is a human-origin action aw drives in a role holder's
// session (docs/design/human-confirmation-from-aw.md, "Session actions").
// It is a version 2 tool without scopes, mutation, invocation_contexts or
// auth, whose path is relative to owner_acts.origin.
type SessionAction struct {
	Name           string               `json:"name"`
	Description    string               `json:"description,omitempty"`
	Kind           string               `json:"kind"`
	Role           string               `json:"role"`
	Method         string               `json:"method"`
	Path           string               `json:"path"`
	InputSchema    map[string]any       `json:"input_schema,omitempty"`
	Params         []SessionActionParam `json:"params"`
	Body           *Body                `json:"body,omitempty"`
	TerminalOutput []string             `json:"terminal_output,omitempty"`
	Completion     *Completion          `json:"completion,omitempty"`
}

// SessionActionParam is a tool param that a stage action may mark
// protected: its value comes only from the controlling terminal.
type SessionActionParam struct {
	Name      string `json:"name"`
	In        string `json:"in"`
	Protected *bool  `json:"protected,omitempty"`
}

// Completion is how a confirm action completes: the read action that
// reports the change's state, and the predicates over that state.
type Completion struct {
	Read  string      `json:"read"`
	Ready Predicate   `json:"ready"`
	Done  Predicate   `json:"done"`
	Stop  []Predicate `json:"stop"`
}

// Predicate holds when the read's top-level Member is one of In.
type Predicate struct {
	Member string            `json:"member"`
	In     []json.RawMessage `json:"in"`
}

// parseSessionActions decodes and checks owner_acts.session_actions against
// the declared roles. Absent declares none; every fault is
// owner_acts_invalid.
func parseSessionActions(raw json.RawMessage, roles []OwnerActRole) ([]SessionAction, error) {
	if raw == nil {
		return nil, nil
	}
	var items []json.RawMessage
	if err := decodeStrictArray(raw, &items, "owner_acts.session_actions"); err != nil {
		return nil, codedf(CodeOwnerActsInvalid, "%v", err)
	}
	if len(items) == 0 || len(items) > maxSessionActions {
		return nil, codedf(CodeOwnerActsInvalid, "owner_acts.session_actions must declare 1 to %d actions", maxSessionActions)
	}
	declaredRoles := map[string]bool{}
	for _, role := range roles {
		declaredRoles[role.Name] = true
	}
	actions := make([]SessionAction, 0, len(items))
	byName := map[string]SessionAction{}
	for _, item := range items {
		action, err := decodeSessionAction(item)
		if err != nil {
			return nil, codedf(CodeOwnerActsInvalid, "%v", err)
		}
		if _, ok := byName[action.Name]; ok {
			return nil, codedf(CodeOwnerActsInvalid, "duplicate session action %q", action.Name)
		}
		if err := validateSessionAction(action, declaredRoles); err != nil {
			return nil, codedf(CodeOwnerActsInvalid, "session action %q: %v", action.Name, err)
		}
		byName[action.Name] = action
		actions = append(actions, action)
	}
	for _, action := range actions {
		if action.Completion == nil {
			continue
		}
		if err := validateCompletionRead(action, byName); err != nil {
			return nil, codedf(CodeOwnerActsInvalid, "session action %q: %v", action.Name, err)
		}
	}
	return actions, nil
}

// decodeSessionAction decodes one action, checking keys exactly at every
// level, because the strict decoder matches them exactly only at the level
// it is given.
func decodeSessionAction(raw json.RawMessage) (SessionAction, error) {
	var decoded struct {
		Name           string            `json:"name"`
		Description    string            `json:"description,omitempty"`
		Kind           string            `json:"kind"`
		Role           string            `json:"role"`
		Method         string            `json:"method"`
		Path           string            `json:"path"`
		InputSchema    map[string]any    `json:"input_schema,omitempty"`
		Params         []json.RawMessage `json:"params"`
		Body           json.RawMessage   `json:"body,omitempty"`
		TerminalOutput []string          `json:"terminal_output,omitempty"`
		Completion     json.RawMessage   `json:"completion,omitempty"`
	}
	if err := decodeStrictObject(raw, &decoded, "session_actions[]"); err != nil {
		return SessionAction{}, err
	}
	action := SessionAction{
		Name: decoded.Name, Description: decoded.Description, Kind: decoded.Kind, Role: decoded.Role,
		Method: decoded.Method, Path: decoded.Path, InputSchema: decoded.InputSchema,
		TerminalOutput: decoded.TerminalOutput,
	}
	if decoded.Params != nil {
		action.Params = []SessionActionParam{}
	}
	for _, item := range decoded.Params {
		var param SessionActionParam
		if err := decodeStrictObject(item, &param, "session_actions[].params[]"); err != nil {
			return SessionAction{}, err
		}
		action.Params = append(action.Params, param)
	}
	if decoded.Body != nil {
		var body Body
		if err := decodeStrictObject(decoded.Body, &body, "session_actions[].body"); err != nil {
			return SessionAction{}, err
		}
		action.Body = &body
	}
	if decoded.Completion != nil {
		completion, err := decodeCompletion(decoded.Completion)
		if err != nil {
			return SessionAction{}, err
		}
		action.Completion = completion
	}
	return action, nil
}

func decodeCompletion(raw json.RawMessage) (*Completion, error) {
	var document struct {
		Read  string            `json:"read"`
		Ready json.RawMessage   `json:"ready"`
		Done  json.RawMessage   `json:"done"`
		Stop  []json.RawMessage `json:"stop"`
	}
	if err := decodeStrictObject(raw, &document, "completion"); err != nil {
		return nil, err
	}
	if document.Ready == nil || document.Done == nil || document.Stop == nil {
		return nil, fmt.Errorf("completion needs read, ready, done and stop")
	}
	completion := &Completion{Read: document.Read}
	var err error
	if completion.Ready, err = decodePredicate(document.Ready); err != nil {
		return nil, err
	}
	if completion.Done, err = decodePredicate(document.Done); err != nil {
		return nil, err
	}
	completion.Stop = []Predicate{}
	for _, item := range document.Stop {
		predicate, err := decodePredicate(item)
		if err != nil {
			return nil, err
		}
		completion.Stop = append(completion.Stop, predicate)
	}
	return completion, nil
}

func decodePredicate(raw json.RawMessage) (Predicate, error) {
	var predicate Predicate
	if err := decodeStrictObject(raw, &predicate, "completion predicate"); err != nil {
		return Predicate{}, err
	}
	return predicate, nil
}

func validateSessionAction(action SessionAction, declaredRoles map[string]bool) error {
	if err := validateTool(action.tool()); err != nil {
		return err
	}
	if strings.Contains(action.Path, "%") {
		return fmt.Errorf("path must not carry percent-encoding")
	}
	if len(routeSegments(action.Path)) > maxV2PathSegments {
		return fmt.Errorf("path has more than %d segments", maxV2PathSegments)
	}
	if !declaredRoles[action.Role] {
		return fmt.Errorf("role %q is not declared in owner_acts.roles", action.Role)
	}
	// The rules apply to the values version 2 validation works with: the
	// method trimmed and uppercased, a param's placement trimmed.
	method := strings.ToUpper(strings.TrimSpace(action.Method))
	switch action.Kind {
	case SessionActionRead:
		if method != "GET" {
			return fmt.Errorf("a read action uses method GET")
		}
		if action.Body != nil {
			return fmt.Errorf("a read action has no body")
		}
		for _, param := range action.Params {
			if in := strings.TrimSpace(param.In); in != "path" && in != "query" {
				return fmt.Errorf("a read action has only path and query params")
			}
		}
	case SessionActionStage, SessionActionDraft, SessionActionConfirm:
		if method != "POST" {
			return fmt.Errorf("a %s action uses method POST", action.Kind)
		}
		if action.Body == nil || action.Body.Mode != "json" {
			return fmt.Errorf("a %s action declares body.mode json", action.Kind)
		}
	default:
		return fmt.Errorf("unknown kind %q", action.Kind)
	}
	for _, param := range action.Params {
		if param.Protected == nil {
			continue
		}
		if !*param.Protected {
			return fmt.Errorf("param %q: protected is true or absent", param.Name)
		}
		if action.Kind != SessionActionStage || strings.TrimSpace(param.In) != "body" {
			return fmt.Errorf("param %q: only an in:body param of a stage action is protected", param.Name)
		}
	}
	if action.TerminalOutput != nil {
		if action.Kind != SessionActionConfirm {
			return fmt.Errorf("only a confirm action declares terminal_output")
		}
		if err := validateTerminalOutput(action.TerminalOutput); err != nil {
			return err
		}
	}
	if (action.Completion != nil) != (action.Kind == SessionActionConfirm) {
		return fmt.Errorf("completion is required on a confirm action and refused on any other")
	}
	if action.Completion != nil {
		return validateCompletionPredicates(*action.Completion)
	}
	return nil
}

// tool is the action as a version 2 tool, for the route, schema and param
// rules every tool follows.
func (action SessionAction) tool() Tool {
	tool := Tool{
		Name: action.Name, Description: action.Description, Method: action.Method,
		Path: action.Path, InputSchema: action.InputSchema,
	}
	for _, param := range action.Params {
		tool.Params = append(tool.Params, Param{Name: param.Name, In: param.In})
	}
	if action.Body != nil {
		tool.Body = *action.Body
	}
	return tool
}

func validateTerminalOutput(pointers []string) error {
	if len(pointers) == 0 || len(pointers) > maxTerminalOutputs {
		return fmt.Errorf("terminal_output lists 1 to %d pointers", maxTerminalOutputs)
	}
	seen := map[string]bool{}
	for _, pointer := range pointers {
		if seen[pointer] {
			return fmt.Errorf("terminal_output repeats %q", pointer)
		}
		seen[pointer] = true
		if !strings.HasPrefix(pointer, "/") {
			return fmt.Errorf("terminal_output pointer %q must begin with /", pointer)
		}
		segments := strings.Split(pointer[1:], "/")
		if len(segments) > maxTerminalOutputDepth {
			return fmt.Errorf("terminal_output pointer %q has more than %d segments", pointer, maxTerminalOutputDepth)
		}
		for i, segment := range segments {
			last := i == len(segments)-1
			if segment == terminalOutputWildcard && !last {
				continue
			}
			if !sessionActionMemberPattern.MatchString(segment) {
				return fmt.Errorf("terminal_output pointer %q: each segment is a member name or *, and the last a member name", pointer)
			}
		}
	}
	return nil
}

func validateCompletionPredicates(completion Completion) error {
	if len(completion.Stop) == 0 || len(completion.Stop) > maxCompletionStops {
		return fmt.Errorf("completion.stop lists 1 to %d predicates", maxCompletionStops)
	}
	for _, predicate := range append([]Predicate{completion.Ready, completion.Done}, completion.Stop...) {
		if err := validatePredicate(predicate); err != nil {
			return err
		}
	}
	return nil
}

func validatePredicate(predicate Predicate) error {
	if !sessionActionMemberPattern.MatchString(predicate.Member) {
		return fmt.Errorf("predicate member %q is not a member name", predicate.Member)
	}
	if len(predicate.In) == 0 || len(predicate.In) > maxPredicateValues {
		return fmt.Errorf("predicate %q lists 1 to %d values", predicate.Member, maxPredicateValues)
	}
	seen := map[string]bool{}
	for _, value := range predicate.In {
		canonical, err := predicateValue(value)
		if err != nil {
			return fmt.Errorf("predicate %q: %v", predicate.Member, err)
		}
		if seen[canonical] {
			return fmt.Errorf("predicate %q repeats a value", predicate.Member)
		}
		seen[canonical] = true
	}
	return nil
}

// predicateValue returns a canonical spelling of a predicate value: a JSON
// string, a boolean or a safe integer. Anything else is refused.
func predicateValue(raw json.RawMessage) (string, error) {
	trimmed := bytes.TrimSpace(raw)
	decoder := json.NewDecoder(bytes.NewReader(trimmed))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return "", err
	}
	switch v := value.(type) {
	case string:
		canonical, err := json.Marshal(v)
		return string(canonical), err
	case bool:
		return fmt.Sprint(v), nil
	case json.Number:
		n, err := v.Int64()
		if err != nil || n > maxSafeInteger || n < -maxSafeInteger {
			return "", fmt.Errorf("%s is not an integer in the safe range", v)
		}
		return fmt.Sprint(n), nil
	default:
		return "", fmt.Errorf("a value is a string, a boolean or an integer")
	}
}

// validateCompletionRead checks that a confirm's completion reads a read
// action of the same role whose every param is an input of the confirm, so
// aw builds the read from the confirm's own invocation.
func validateCompletionRead(confirm SessionAction, byName map[string]SessionAction) error {
	read, ok := byName[confirm.Completion.Read]
	if !ok || read.Kind != SessionActionRead {
		return fmt.Errorf("completion.read %q is not a declared read action", confirm.Completion.Read)
	}
	if read.Role != confirm.Role {
		return fmt.Errorf("completion.read %q belongs to another role", read.Name)
	}
	confirmInputs := map[string]bool{}
	for _, param := range confirm.Params {
		confirmInputs[strings.TrimSpace(param.Name)] = true
	}
	for _, param := range read.Params {
		if !confirmInputs[strings.TrimSpace(param.Name)] {
			return fmt.Errorf("completion.read %q has param %q that the confirm does not declare", read.Name, param.Name)
		}
	}
	return nil
}
