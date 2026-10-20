package appmanifest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/awebai/aw/awid"
)

// Stable error codes shared with every manifest consumer through
// test-vectors/app-manifests/app-manifest-v2-v1.json and
// app-manifest-discovery-v1.json. Messages are for people; codes are the
// contract.
const (
	CodeManifestInvalid            = "manifest_invalid"
	CodeManifestVersionUnsupported = "manifest_version_unsupported"
	CodeToolContextsInvalid        = "tool_contexts_invalid"
	CodeSurfaceInvalid             = "surface_invalid"
	CodeSurfaceToolInvalid         = "surface_tool_invalid"
	CodeAnswerToolContextsInvalid  = "answer_tool_contexts_invalid"
	CodeAnswerInputForbidden       = "answer_input_forbidden"
	CodeAnswerRouteAgentVisible    = "answer_route_agent_visible"
	CodeUsageInvalid               = "usage_invalid"
	CodeLifecycleInvalid           = "lifecycle_invalid"
	CodeHooksInvalid               = "hooks_invalid"
	CodeHookToolInvalid            = "hook_tool_invalid"
	CodeAppKeysInvalid             = "app_keys_invalid"
	CodeToolContextDenied          = "tool_context_denied"
	CodeChannelInvalid             = "channel_invalid"
	CodeAttestationInvalid         = "attestation_invalid"
	CodeToolNotFound               = "tool_not_found"
	CodeAnswerPayloadRefused       = "answer_payload_refused"
)

// Error is a manifest error with a stable code.
type Error struct {
	Code string
	err  error
}

func (e *Error) Error() string { return e.err.Error() }
func (e *Error) Unwrap() error { return e.err }

// ErrorCode returns the stable code of a manifest error, or "" when err
// carries none.
func ErrorCode(err error) string {
	var coded *Error
	if errors.As(err, &coded) {
		return coded.Code
	}
	return ""
}

func codedError(code string, err error) error {
	var coded *Error
	if errors.As(err, &coded) {
		return err
	}
	return &Error{Code: code, err: err}
}

func codedf(code, format string, args ...any) error {
	return &Error{Code: code, err: fmt.Errorf(format, args...)}
}

// Invocation contexts a v2 tool may declare. Absent means agent and surface;
// hook is never implied.
const (
	ContextAgent   = "agent"
	ContextSurface = "surface"
	ContextHook    = "hook"
)

// Bounds and name rules of the version 2 additions.
const (
	maxSurfaces          = 16
	maxSurfaceEvents     = 16
	maxAppKeys           = 16
	maxKeyPurposes       = 8
	maxHookRegistrations = 64
	maxHookProductions   = 64
	maxHookScopes        = 32
	maxHookReads         = 64
	maxSurfaceLabelRunes = 128
	maxV2Tools           = 256
	maxV2PathSegments    = 32
	// MaxJSONDepth bounds the nesting of any manifest or catalog document, so
	// every reader handles it within its own recursion limits.
	MaxJSONDepth = 512
)

var (
	surfaceIDPattern  = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
	formatPattern     = regexp.MustCompile(`^[a-z][a-z0-9.-]{0,63}/[1-9][0-9]{0,8}$`)
	fieldNamePattern  = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	purposePattern    = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)
	keyIDPattern      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	hookNamePattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	scopeNamePattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9:._/-]{0,127}$`)
	v2TopLevelMembers = []string{"app_keys", "surfaces", "usage", "lifecycle", "hooks"}
)

// UnmarshalJSON decodes a manifest strictly: unknown fields are refused at
// every modeled level, and a version 2 member may not be null.
func (m *Manifest) UnmarshalJSON(data []byte) error {
	type plainManifest Manifest
	var plain plainManifest
	if err := decodeSingleJSON(data, &plain, true); err != nil {
		return err
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(data, &members); err != nil {
		return err
	}
	if err := checkManifestKeys(members); err != nil {
		return err
	}
	for _, name := range v2TopLevelMembers {
		if value, ok := members[name]; ok && isJSONNull(value) {
			return fmt.Errorf("%s must not be null", name)
		}
	}
	*m = Manifest(plain)
	m.members = map[string]bool{}
	for name := range members {
		m.members[name] = true
	}
	return nil
}

// Go's decoder matches object keys case-insensitively. The contract matches
// them exactly, so every modeled object's keys are checked against the field
// names of the type it decodes into.

func jsonFieldNames(t reflect.Type) map[string]bool {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	names := map[string]bool{}
	for i := 0; i < t.NumField(); i++ {
		name, _, _ := strings.Cut(t.Field(i).Tag.Get("json"), ",")
		if name != "" && name != "-" {
			names[name] = true
		}
	}
	return names
}

func checkExactKeys(members map[string]json.RawMessage, t reflect.Type, what string) error {
	allowed := jsonFieldNames(t)
	for name := range members {
		if !allowed[name] {
			return fmt.Errorf("%s has unknown field %q", what, name)
		}
	}
	return nil
}

// checkObjectKeys checks one raw value's keys when it is an object; other
// values are left to the decoder's type checks.
func checkObjectKeys(raw json.RawMessage, t reflect.Type, what string) error {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &members); err != nil {
		return err
	}
	return checkExactKeys(members, t, what)
}

func checkArrayKeys(raw json.RawMessage, t reflect.Type, what string, each func(json.RawMessage) error) error {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '[' {
		return nil
	}
	var items []json.RawMessage
	if err := json.Unmarshal(trimmed, &items); err != nil {
		return err
	}
	for _, item := range items {
		if err := checkObjectKeys(item, t, what); err != nil {
			return err
		}
		if each != nil {
			if err := each(item); err != nil {
				return err
			}
		}
	}
	return nil
}

// checkManifestKeys checks the manifest's own keys and those of its v1
// levels; the v2 levels check theirs as they decode.
func checkManifestKeys(members map[string]json.RawMessage) error {
	if err := checkExactKeys(members, reflect.TypeOf(Manifest{}), "manifest"); err != nil {
		return err
	}
	if err := checkObjectKeys(members["app"], reflect.TypeOf(App{}), "app"); err != nil {
		return err
	}
	if err := checkArrayKeys(members["event_emitters"], reflect.TypeOf(EventEmitter{}), "event_emitters[]", nil); err != nil {
		return err
	}
	if err := checkArrayKeys(members["events"], reflect.TypeOf(Event{}), "events[]", nil); err != nil {
		return err
	}
	return checkArrayKeys(members["tools"], reflect.TypeOf(Tool{}), "tools[]", func(raw json.RawMessage) error {
		var tool map[string]json.RawMessage
		if err := json.Unmarshal(bytes.TrimSpace(raw), &tool); err != nil {
			return nil
		}
		if err := checkObjectKeys(tool["body"], reflect.TypeOf(Body{}), "tools[].body"); err != nil {
			return err
		}
		return checkArrayKeys(tool["params"], reflect.TypeOf(Param{}), "tools[].params[]", nil)
	})
}

// checkNestingDepth refuses JSON nested deeper than max levels of objects
// and arrays, counting only brackets outside strings.
func checkNestingDepth(data []byte, max int) error {
	depth, inString, escaped := 0, false, false
	for _, c := range data {
		switch {
		case inString && escaped:
			escaped = false
		case inString && c == '\\':
			escaped = true
		case inString && c == '"':
			inString = false
		case inString:
		case c == '"':
			inString = true
		case c == '{' || c == '[':
			depth++
			if depth > max {
				return fmt.Errorf("JSON is nested deeper than %d levels", max)
			}
		case c == '}' || c == ']':
			depth--
		}
	}
	return nil
}

func isJSONNull(raw json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}

// decodeStrictObject decodes one JSON object with no unknown and no null
// members.
func decodeStrictObject(data []byte, v any, what string) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return fmt.Errorf("%s must be an object", what)
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &members); err != nil {
		return err
	}
	for name, value := range members {
		if isJSONNull(value) {
			return fmt.Errorf("%s.%s must not be null", what, name)
		}
	}
	if err := checkExactKeys(members, reflect.TypeOf(v), what); err != nil {
		return err
	}
	if err := DecodeSingleJSONStrict(trimmed, v); err != nil {
		return fmt.Errorf("%s: %w", what, err)
	}
	return nil
}

// decodeStrictArray decodes a JSON array, refusing null.
func decodeStrictArray(data []byte, v any, what string) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || trimmed[0] != '[' {
		return fmt.Errorf("%s must be an array", what)
	}
	if err := DecodeSingleJSONStrict(trimmed, v); err != nil {
		return fmt.Errorf("%s: %w", what, err)
	}
	return nil
}

// Names is a JSON array of strings with no null elements.
type Names []string

func (n *Names) UnmarshalJSON(data []byte) error {
	var raw []json.RawMessage
	if err := decodeStrictArray(data, &raw, "name list"); err != nil {
		return err
	}
	out := make(Names, 0, len(raw))
	for _, item := range raw {
		trimmed := bytes.TrimSpace(item)
		if len(trimmed) == 0 || trimmed[0] != '"' {
			return fmt.Errorf("name list items must be strings")
		}
		var value string
		if err := json.Unmarshal(trimmed, &value); err != nil {
			return err
		}
		out = append(out, value)
	}
	*n = out
	return nil
}

// Contexts is a tool's declared invocation_contexts.
type Contexts = Names

type AppKeys []AppKey

type AppKey struct {
	KID      string `json:"kid"`
	DIDKey   string `json:"did_key"`
	Purposes Names  `json:"purposes"`
}

func (keys *AppKeys) UnmarshalJSON(data []byte) error {
	type plain []AppKey
	var out plain
	if err := decodeStrictArray(data, &out, "app_keys"); err != nil {
		return err
	}
	*keys = AppKeys(out)
	return nil
}

func (k *AppKey) UnmarshalJSON(data []byte) error {
	type plain AppKey
	var out plain
	if err := decodeStrictObject(data, &out, "app_keys[]"); err != nil {
		return err
	}
	*k = AppKey(out)
	return nil
}

type Surfaces []Surface

type Surface struct {
	ID         string        `json:"id"`
	Label      string        `json:"label"`
	Format     string        `json:"format"`
	ListTool   string        `json:"list_tool"`
	ReadTool   string        `json:"read_tool"`
	InvokeTool string        `json:"invoke_tool,omitempty"`
	AnswerTool string        `json:"answer_tool,omitempty"`
	Inputs     SurfaceInputs `json:"inputs"`
	Events     SurfaceEvents `json:"events,omitempty"`
}

type SurfaceInputs struct {
	Resource   string `json:"resource"`
	Invocation string `json:"invocation,omitempty"`
}

type SurfaceEvents []SurfaceEvent

type SurfaceEvent struct {
	Type          string `json:"type"`
	ResourceField string `json:"resource_field"`
	RevisionField string `json:"revision_field"`
}

func (s *Surfaces) UnmarshalJSON(data []byte) error {
	type plain []Surface
	var out plain
	if err := decodeStrictArray(data, &out, "surfaces"); err != nil {
		return err
	}
	*s = Surfaces(out)
	return nil
}

func (s *Surface) UnmarshalJSON(data []byte) error {
	type plain Surface
	var out plain
	if err := decodeStrictObject(data, &out, "surfaces[]"); err != nil {
		return err
	}
	*s = Surface(out)
	return nil
}

func (in *SurfaceInputs) UnmarshalJSON(data []byte) error {
	type plain SurfaceInputs
	var out plain
	if err := decodeStrictObject(data, &out, "surfaces[].inputs"); err != nil {
		return err
	}
	*in = SurfaceInputs(out)
	return nil
}

func (e *SurfaceEvents) UnmarshalJSON(data []byte) error {
	type plain []SurfaceEvent
	var out plain
	if err := decodeStrictArray(data, &out, "surfaces[].events"); err != nil {
		return err
	}
	*e = SurfaceEvents(out)
	return nil
}

func (e *SurfaceEvent) UnmarshalJSON(data []byte) error {
	type plain SurfaceEvent
	var out plain
	if err := decodeStrictObject(data, &out, "surfaces[].events[]"); err != nil {
		return err
	}
	*e = SurfaceEvent(out)
	return nil
}

// Usage names the app's usage snapshot tool.
type Usage struct {
	Format       string `json:"format"`
	SnapshotTool string `json:"snapshot_tool"`
}

func (u *Usage) UnmarshalJSON(data []byte) error {
	type plain Usage
	var out plain
	if err := decodeStrictObject(data, &out, "usage"); err != nil {
		return err
	}
	*u = Usage(out)
	return nil
}

// Lifecycle names the app's export, delete and status tools.
type Lifecycle struct {
	ExportTool string `json:"export_tool,omitempty"`
	DeleteTool string `json:"delete_tool,omitempty"`
	StatusTool string `json:"status_tool,omitempty"`
}

func (l *Lifecycle) UnmarshalJSON(data []byte) error {
	type plain Lifecycle
	var out plain
	if err := decodeStrictObject(data, &out, "lifecycle"); err != nil {
		return err
	}
	*l = Lifecycle(out)
	return nil
}

// Hooks is the versioned hooks slot. It declares where the app receives a
// hook and which hooks it may fire; neither is active until the team owner
// activates it for one installation generation.
type Hooks struct {
	RegistrationVersion int               `json:"registration_version"`
	Registrations       HookRegistrations `json:"registrations,omitempty"`
	Productions         HookProductions   `json:"productions,omitempty"`
}

type HookCatalog struct {
	ID      string `json:"id"`
	Version int    `json:"version"`
}

type HookRegistrations []HookRegistration

type HookRegistration struct {
	Catalog HookCatalog `json:"catalog"`
	Hook    string      `json:"hook"`
	Tool    string      `json:"tool"`
	Scopes  Names       `json:"scopes,omitempty"`
}

type HookProductions []HookProduction

type HookProduction struct {
	Catalog HookCatalog `json:"catalog"`
	Hook    string      `json:"hook"`
	Reads   Names       `json:"reads,omitempty"`
}

func (h *Hooks) UnmarshalJSON(data []byte) error {
	type plain Hooks
	var out plain
	if err := decodeStrictObject(data, &out, "hooks"); err != nil {
		return err
	}
	*h = Hooks(out)
	return nil
}

func (c *HookCatalog) UnmarshalJSON(data []byte) error {
	type plain HookCatalog
	var out plain
	if err := decodeStrictObject(data, &out, "hooks catalog"); err != nil {
		return err
	}
	*c = HookCatalog(out)
	return nil
}

func (r *HookRegistrations) UnmarshalJSON(data []byte) error {
	type plain []HookRegistration
	var out plain
	if err := decodeStrictArray(data, &out, "hooks.registrations"); err != nil {
		return err
	}
	*r = HookRegistrations(out)
	return nil
}

func (r *HookRegistration) UnmarshalJSON(data []byte) error {
	type plain HookRegistration
	var out plain
	if err := decodeStrictObject(data, &out, "hooks.registrations[]"); err != nil {
		return err
	}
	*r = HookRegistration(out)
	return nil
}

func (p *HookProductions) UnmarshalJSON(data []byte) error {
	type plain []HookProduction
	var out plain
	if err := decodeStrictArray(data, &out, "hooks.productions"); err != nil {
		return err
	}
	*p = HookProductions(out)
	return nil
}

func (p *HookProduction) UnmarshalJSON(data []byte) error {
	type plain HookProduction
	var out plain
	if err := decodeStrictObject(data, &out, "hooks.productions[]"); err != nil {
		return err
	}
	*p = HookProduction(out)
	return nil
}

// hasMember reports whether a decoded manifest carried a top-level member,
// falling back to the field's value for a manifest built in memory.
func (m Manifest) hasMember(name string, set bool) bool {
	if m.members != nil {
		return m.members[name]
	}
	return set
}

func validateV1Only(m Manifest) error {
	for _, tool := range m.Tools {
		if tool.InvocationContexts != nil {
			return codedf(CodeManifestInvalid, "tool %q invocation_contexts requires manifest_version 2", tool.Name)
		}
	}
	v2Members := map[string]bool{
		"app_keys":  m.AppKeys != nil,
		"surfaces":  m.Surfaces != nil,
		"usage":     m.Usage != nil,
		"lifecycle": m.Lifecycle != nil,
		"hooks":     m.Hooks != nil,
	}
	for _, name := range v2TopLevelMembers {
		if m.hasMember(name, v2Members[name]) {
			return codedf(CodeManifestInvalid, "%s requires manifest_version 2", name)
		}
	}
	return nil
}

// validateV2 checks the version 2 additions. The order is part of the
// contract: when one defect could be reported under two codes, the earlier
// check names it.
func validateV2(m Manifest) error {
	if m.hasMember("event_emitters", m.EventEmitters != nil) {
		return codedf(CodeManifestInvalid, "event_emitters is replaced by app_keys in manifest_version 2")
	}
	if len(m.Tools) > maxV2Tools {
		return codedf(CodeManifestInvalid, "a manifest_version 2 manifest declares at most %d tools", maxV2Tools)
	}
	names := map[string]bool{}
	for _, tool := range m.Tools {
		name := strings.TrimSpace(tool.Name)
		if names[name] {
			return codedf(CodeManifestInvalid, "duplicate tool name %q", name)
		}
		names[name] = true
		if strings.Contains(tool.Path, "%") {
			return codedf(CodeManifestInvalid, "tool %q path must not carry percent-encoding", name)
		}
		if len(routeSegments(tool.Path)) > maxV2PathSegments {
			return codedf(CodeManifestInvalid, "tool %q path has more than %d segments", name, maxV2PathSegments)
		}
	}
	tools := toolIndex(m.Tools)
	for _, tool := range m.Tools {
		if err := validateContexts(tool); err != nil {
			return err
		}
	}
	if err := validateAppKeys(m.AppKeys); err != nil {
		return err
	}
	if err := validateSurfaces(m, tools); err != nil {
		return err
	}
	if err := validateAnswerRoutes(m, tools); err != nil {
		return err
	}
	if err := validateAnswerInputs(m); err != nil {
		return err
	}
	if err := validateUsage(m.Usage, tools); err != nil {
		return err
	}
	if err := validateLifecycle(m.Lifecycle, tools); err != nil {
		return err
	}
	return validateHooks(m.Hooks, tools)
}

func toolIndex(tools []Tool) map[string]*Tool {
	out := make(map[string]*Tool, len(tools))
	for i := range tools {
		out[strings.TrimSpace(tools[i].Name)] = &tools[i]
	}
	return out
}

func validateContexts(tool Tool) error {
	if tool.InvocationContexts == nil {
		return nil
	}
	if len(tool.InvocationContexts) == 0 {
		return codedf(CodeToolContextsInvalid, "tool %q invocation_contexts must not be empty", tool.Name)
	}
	seen := map[string]bool{}
	for _, context := range tool.InvocationContexts {
		switch context {
		case ContextAgent, ContextSurface, ContextHook:
		default:
			return codedf(CodeToolContextsInvalid, "tool %q has unknown invocation context %q", tool.Name, context)
		}
		if seen[context] {
			return codedf(CodeToolContextsInvalid, "tool %q repeats invocation context %q", tool.Name, context)
		}
		seen[context] = true
	}
	return nil
}

// toolContexts is the effective context set of a tool.
func toolContexts(tool *Tool) map[string]bool {
	if tool.InvocationContexts == nil {
		return map[string]bool{ContextAgent: true, ContextSurface: true}
	}
	out := map[string]bool{}
	for _, context := range tool.InvocationContexts {
		out[context] = true
	}
	return out
}

func onlyContext(tool *Tool, context string) bool {
	contexts := toolContexts(tool)
	return len(contexts) == 1 && contexts[context]
}

func isPublicTool(tool *Tool) bool {
	auth, err := normalizeToolAuth(*tool)
	return err == nil && auth == "none"
}

func validateAppKeys(keys AppKeys) error {
	if len(keys) > maxAppKeys {
		return codedf(CodeAppKeysInvalid, "app_keys exceeds %d keys", maxAppKeys)
	}
	kids := map[string]bool{}
	for _, key := range keys {
		if !keyIDPattern.MatchString(key.KID) {
			return codedf(CodeAppKeysInvalid, "app key kid %q is invalid", key.KID)
		}
		if kids[key.KID] {
			return codedf(CodeAppKeysInvalid, "duplicate app key kid %q", key.KID)
		}
		kids[key.KID] = true
		if _, err := awid.ExtractPublicKey(key.DIDKey); err != nil {
			return codedf(CodeAppKeysInvalid, "app key %q did_key: %v", key.KID, err)
		}
		if len(key.Purposes) == 0 || len(key.Purposes) > maxKeyPurposes {
			return codedf(CodeAppKeysInvalid, "app key %q must declare 1 to %d purposes", key.KID, maxKeyPurposes)
		}
		purposes := map[string]bool{}
		for _, purpose := range key.Purposes {
			if !purposePattern.MatchString(purpose) {
				return codedf(CodeAppKeysInvalid, "app key %q purpose %q is invalid", key.KID, purpose)
			}
			if purposes[purpose] {
				return codedf(CodeAppKeysInvalid, "app key %q repeats purpose %q", key.KID, purpose)
			}
			purposes[purpose] = true
		}
	}
	return nil
}

func validateSurfaces(m Manifest, tools map[string]*Tool) error {
	if len(m.Surfaces) > maxSurfaces {
		return codedf(CodeSurfaceInvalid, "surfaces exceeds %d", maxSurfaces)
	}
	ids := map[string]bool{}
	for _, surface := range m.Surfaces {
		if err := validateSurfaceShape(surface); err != nil {
			return err
		}
		if ids[surface.ID] {
			return codedf(CodeSurfaceInvalid, "duplicate surface id %q", surface.ID)
		}
		ids[surface.ID] = true
	}
	declaredEvents := map[string]bool{}
	appID := strings.TrimSpace(m.App.ID)
	for _, event := range m.Events {
		declaredEvents[strings.TrimPrefix(strings.TrimSpace(event.Type), appID+"/")] = true
	}
	for _, surface := range m.Surfaces {
		if err := validateSurfaceTools(surface, tools); err != nil {
			return err
		}
		if err := validateSurfaceInputs(surface, tools); err != nil {
			return err
		}
		for _, event := range surface.Events {
			if _, err := resolveSurfaceEventType(event.Type, appID, declaredEvents); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateSurfaceShape(surface Surface) error {
	if !surfaceIDPattern.MatchString(surface.ID) {
		return codedf(CodeSurfaceInvalid, "surface id %q is invalid", surface.ID)
	}
	label := strings.TrimSpace(surface.Label)
	if label == "" || utf8.RuneCountInString(label) > maxSurfaceLabelRunes {
		return codedf(CodeSurfaceInvalid, "surface %q label must be 1 to %d characters", surface.ID, maxSurfaceLabelRunes)
	}
	if !formatPattern.MatchString(surface.Format) {
		return codedf(CodeSurfaceInvalid, "surface %q format %q is invalid", surface.ID, surface.Format)
	}
	if surface.ListTool == "" || surface.ReadTool == "" {
		return codedf(CodeSurfaceInvalid, "surface %q requires list_tool and read_tool", surface.ID)
	}
	if surface.Inputs.Resource == "" {
		return codedf(CodeSurfaceInvalid, "surface %q requires inputs.resource", surface.ID)
	}
	if (surface.InvokeTool != "" || surface.AnswerTool != "") && surface.Inputs.Invocation == "" {
		return codedf(CodeSurfaceInvalid, "surface %q requires inputs.invocation with an invoke or answer tool", surface.ID)
	}
	if len(surface.Events) > maxSurfaceEvents {
		return codedf(CodeSurfaceInvalid, "surface %q events exceeds %d", surface.ID, maxSurfaceEvents)
	}
	for _, event := range surface.Events {
		if event.Type == "" || !fieldNamePattern.MatchString(event.ResourceField) || !fieldNamePattern.MatchString(event.RevisionField) {
			return codedf(CodeSurfaceInvalid, "surface %q event binding is invalid", surface.ID)
		}
	}
	return nil
}

func validateSurfaceTools(surface Surface, tools map[string]*Tool) error {
	if surface.AnswerTool != "" {
		answer, ok := tools[surface.AnswerTool]
		if !ok {
			return codedf(CodeSurfaceToolInvalid, "surface %q answer_tool %q is not a declared tool", surface.ID, surface.AnswerTool)
		}
		if !onlyContext(answer, ContextSurface) {
			return codedf(CodeAnswerToolContextsInvalid, "surface %q answer_tool %q must declare invocation_contexts exactly [\"surface\"]", surface.ID, surface.AnswerTool)
		}
	}
	refs := []struct {
		role, name string
		get        bool
	}{
		{"list_tool", surface.ListTool, true},
		{"read_tool", surface.ReadTool, true},
		{"invoke_tool", surface.InvokeTool, false},
		{"answer_tool", surface.AnswerTool, false},
	}
	for _, ref := range refs {
		if ref.name == "" {
			continue
		}
		tool, ok := tools[ref.name]
		if !ok {
			return codedf(CodeSurfaceToolInvalid, "surface %q %s %q is not a declared tool", surface.ID, ref.role, ref.name)
		}
		if !toolContexts(tool)[ContextSurface] {
			return codedf(CodeSurfaceToolInvalid, "surface %q %s %q lacks the surface invocation context", surface.ID, ref.role, ref.name)
		}
		if isPublicTool(tool) {
			return codedf(CodeSurfaceToolInvalid, "surface %q %s %q must be member-authenticated", surface.ID, ref.role, ref.name)
		}
		if ref.get && (strings.ToUpper(strings.TrimSpace(tool.Method)) != "GET" || tool.Mutation) {
			return codedf(CodeSurfaceToolInvalid, "surface %q %s %q must be a non-mutating GET", surface.ID, ref.role, ref.name)
		}
		if !ref.get && !tool.Mutation {
			return codedf(CodeSurfaceToolInvalid, "surface %q %s %q must be a mutation", surface.ID, ref.role, ref.name)
		}
	}
	if surface.InvokeTool == "" {
		return nil
	}
	if surface.InvokeTool == surface.AnswerTool {
		return codedf(CodeAnswerInputForbidden, "surface %q invoke_tool cannot be its answer_tool", surface.ID)
	}
	return nil
}

func answerTools(surfaces Surfaces) map[string]bool {
	out := map[string]bool{}
	for _, surface := range surfaces {
		if surface.AnswerTool != "" {
			out[surface.AnswerTool] = true
		}
	}
	return out
}

// validateAnswerRoutes refuses an agent-visible tool that can reach a surface
// answer_tool's route as a server routes it, on the decoded path. It is
// deliberately conservative, and defence in depth: the guarantee is the
// naapp refusing answer-kind actions.
func validateAnswerRoutes(m Manifest, tools map[string]*Tool) error {
	for name := range answerTools(m.Surfaces) {
		answer := tools[name]
		for i := range m.Tools {
			tool := &m.Tools[i]
			if strings.TrimSpace(tool.Name) == name || !toolContexts(tool)[ContextAgent] {
				continue
			}
			if canReachRoute(tool, answer) {
				return codedf(CodeAnswerRouteAgentVisible, "agent-visible tool %q can reach answer_tool %q's route", tool.Name, name)
			}
		}
	}
	return nil
}

// canReachRoute reports whether some request the caller tool sends can be
// routed to the target tool: the same method, and decoded paths that can
// match.
func canReachRoute(caller, target *Tool) bool {
	if strings.ToUpper(strings.TrimSpace(caller.Method)) != strings.ToUpper(strings.TrimSpace(target.Method)) {
		return false
	}
	callerPath, errCaller := validateRelativePath(caller.Path)
	targetPath, errTarget := validateRelativePath(target.Path)
	if errCaller != nil || errTarget != nil {
		return false
	}
	return segmentsReach(routeSegments(callerPath), routeSegments(targetPath))
}

// routeSegments splits a path into its non-empty segments, so trailing and
// repeated slashes do not make a different route.
func routeSegments(path string) []string {
	return strings.FieldsFunc(path, func(r rune) bool { return r == '/' })
}

// segmentsReach matches caller segments against target segments. A caller
// segment holding a placeholder covers one or more target segments, because
// its value may carry an encoded '/' that the server decodes before routing.
// A target segment holding a placeholder matches any one caller segment. It
// fills reach[i][j], "caller[i:] can match target[j:]", from the end, in
// O(len(caller) * len(target)).
func segmentsReach(caller, target []string) bool {
	next := make([]bool, len(target)+1)
	next[len(target)] = true
	for i := len(caller) - 1; i >= 0; i-- {
		current := make([]bool, len(target)+1)
		laterMatch := false
		for j := len(target); j >= 0; j-- {
			if strings.Contains(caller[i], "{") {
				current[j] = laterMatch
			} else if j < len(target) {
				current[j] = (caller[i] == target[j] || strings.Contains(target[j], "{")) && next[j+1]
			}
			laterMatch = laterMatch || next[j]
		}
		next = current
	}
	return next[0]
}

// validateAnswerInputs refuses an answer input on every tool except a surface
// answer_tool: top-level, or inside an object body parameter.
func validateAnswerInputs(m Manifest) error {
	answers := answerTools(m.Surfaces)
	for _, tool := range m.Tools {
		name := strings.TrimSpace(tool.Name)
		if answers[name] {
			continue
		}
		properties := schemaProperties(tool.InputSchema)
		if _, ok := properties["answer"]; ok {
			return codedf(CodeAnswerInputForbidden, "tool %q declares an answer input; only a surface answer_tool carries one", name)
		}
		for _, param := range tool.Params {
			if strings.TrimSpace(param.In) != "body" {
				continue
			}
			if _, ok := schemaProperties(properties[strings.TrimSpace(param.Name)])["answer"]; ok {
				return codedf(CodeAnswerInputForbidden, "tool %q declares an answer inside %q; only a surface answer_tool carries one", name, param.Name)
			}
		}
	}
	return nil
}

func validateSurfaceInputs(surface Surface, tools map[string]*Tool) error {
	for _, name := range []string{surface.ReadTool, surface.InvokeTool, surface.AnswerTool} {
		if name == "" {
			continue
		}
		if _, ok := toolParam(tools[name], surface.Inputs.Resource); !ok {
			return codedf(CodeSurfaceInvalid, "surface %q resource input %q is not a param of %q", surface.ID, surface.Inputs.Resource, name)
		}
	}
	for _, name := range []string{surface.InvokeTool, surface.AnswerTool} {
		if name == "" {
			continue
		}
		param, ok := toolParam(tools[name], surface.Inputs.Invocation)
		if !ok || param.In != "body" || schemaType(schemaProperties(tools[name].InputSchema)[param.Name]) != "object" {
			return codedf(CodeSurfaceInvalid, "surface %q invocation input %q is not an object body param of %q", surface.ID, surface.Inputs.Invocation, name)
		}
	}
	return nil
}

func toolParam(tool *Tool, name string) (Param, bool) {
	for _, param := range tool.Params {
		if strings.TrimSpace(param.Name) == name {
			return Param{Name: name, In: strings.TrimSpace(param.In)}, true
		}
	}
	return Param{}, false
}

func resolveSurfaceEventType(eventType, appID string, declared map[string]bool) (string, error) {
	local := eventType
	if strings.Contains(eventType, "/") {
		local = strings.TrimPrefix(eventType, appID+"/")
		if local == eventType || strings.Contains(local, "/") {
			return "", codedf(CodeSurfaceInvalid, "surface event %q is not an event of app %q", eventType, appID)
		}
	}
	if !declared[local] {
		return "", codedf(CodeSurfaceInvalid, "surface event %q is not declared in events", eventType)
	}
	return appID + "/" + local, nil
}

func validateUsage(usage *Usage, tools map[string]*Tool) error {
	if usage == nil {
		return nil
	}
	if !formatPattern.MatchString(usage.Format) {
		return codedf(CodeUsageInvalid, "usage format %q is invalid", usage.Format)
	}
	tool, ok := tools[usage.SnapshotTool]
	if !ok || usage.SnapshotTool == "" {
		return codedf(CodeUsageInvalid, "usage snapshot_tool %q is not a declared tool", usage.SnapshotTool)
	}
	if tool.Mutation || isPublicTool(tool) {
		return codedf(CodeUsageInvalid, "usage snapshot_tool %q must be a member-authenticated read", usage.SnapshotTool)
	}
	return nil
}

func validateLifecycle(lifecycle *Lifecycle, tools map[string]*Tool) error {
	if lifecycle == nil {
		return nil
	}
	refs := []struct {
		role, name string
		mutation   bool
	}{
		{"export_tool", lifecycle.ExportTool, true},
		{"delete_tool", lifecycle.DeleteTool, true},
		{"status_tool", lifecycle.StatusTool, false},
	}
	named := 0
	for _, ref := range refs {
		if ref.name == "" {
			continue
		}
		named++
		tool, ok := tools[ref.name]
		if !ok {
			return codedf(CodeLifecycleInvalid, "lifecycle %s %q is not a declared tool", ref.role, ref.name)
		}
		if isPublicTool(tool) {
			return codedf(CodeLifecycleInvalid, "lifecycle %s %q must be member-authenticated", ref.role, ref.name)
		}
		if tool.Mutation != ref.mutation {
			return codedf(CodeLifecycleInvalid, "lifecycle %s %q has the wrong mutation flag", ref.role, ref.name)
		}
	}
	if named == 0 {
		return codedf(CodeLifecycleInvalid, "lifecycle must name at least one tool")
	}
	return nil
}

func validateHookCatalog(catalog HookCatalog, hook string) error {
	if !hookNamePattern.MatchString(catalog.ID) {
		return codedf(CodeHooksInvalid, "hook catalog id %q is invalid", catalog.ID)
	}
	if catalog.Version < 1 {
		return codedf(CodeHooksInvalid, "hook catalog %q version must be positive", catalog.ID)
	}
	if !hookNamePattern.MatchString(hook) {
		return codedf(CodeHooksInvalid, "hook name %q is invalid", hook)
	}
	return nil
}

func validateDistinctNames(names Names, max int, pattern *regexp.Regexp, what string) error {
	if len(names) > max {
		return codedf(CodeHooksInvalid, "%s exceeds %d", what, max)
	}
	seen := map[string]bool{}
	for _, name := range names {
		if pattern != nil && !pattern.MatchString(name) {
			return codedf(CodeHooksInvalid, "%s %q is invalid", what, name)
		}
		if seen[name] {
			return codedf(CodeHooksInvalid, "%s repeats %q", what, name)
		}
		seen[name] = true
	}
	return nil
}

func validateHooks(hooks *Hooks, tools map[string]*Tool) error {
	if hooks == nil {
		return nil
	}
	if hooks.RegistrationVersion != 1 {
		return codedf(CodeHooksInvalid, "unsupported hooks registration_version %d", hooks.RegistrationVersion)
	}
	if len(hooks.Registrations) > maxHookRegistrations {
		return codedf(CodeHooksInvalid, "hooks.registrations exceeds %d", maxHookRegistrations)
	}
	if len(hooks.Productions) > maxHookProductions {
		return codedf(CodeHooksInvalid, "hooks.productions exceeds %d", maxHookProductions)
	}
	registrations := map[string]bool{}
	for _, reg := range hooks.Registrations {
		if err := validateHookCatalog(reg.Catalog, reg.Hook); err != nil {
			return err
		}
		if err := validateDistinctNames(reg.Scopes, maxHookScopes, scopeNamePattern, "hook registration scopes"); err != nil {
			return err
		}
		key := fmt.Sprintf("%s\x00%d\x00%s\x00%s", reg.Catalog.ID, reg.Catalog.Version, reg.Hook, reg.Tool)
		if registrations[key] {
			return codedf(CodeHooksInvalid, "duplicate hook registration %s/%s -> %s", reg.Catalog.ID, reg.Hook, reg.Tool)
		}
		registrations[key] = true
	}
	productions := map[string]bool{}
	for _, prod := range hooks.Productions {
		if err := validateHookCatalog(prod.Catalog, prod.Hook); err != nil {
			return err
		}
		if err := validateDistinctNames(prod.Reads, maxHookReads, nil, "hook production reads"); err != nil {
			return err
		}
		key := fmt.Sprintf("%s\x00%d\x00%s", prod.Catalog.ID, prod.Catalog.Version, prod.Hook)
		if productions[key] {
			return codedf(CodeHooksInvalid, "duplicate hook production %s/%s", prod.Catalog.ID, prod.Hook)
		}
		productions[key] = true
	}
	for _, reg := range hooks.Registrations {
		tool, ok := tools[reg.Tool]
		if !ok || reg.Tool == "" || !onlyContext(tool, ContextHook) {
			return codedf(CodeHookToolInvalid, "hook registration tool %q must be a local tool declaring invocation_contexts exactly [\"hook\"]", reg.Tool)
		}
	}
	for _, prod := range hooks.Productions {
		for _, read := range prod.Reads {
			tool, ok := tools[read]
			if !ok || tool.Mutation {
				return codedf(CodeHookToolInvalid, "hook production read %q must be a local non-mutating tool", read)
			}
		}
	}
	return nil
}

// Resolved is a validated manifest of either version, read as the
// capabilities a consumer acts on. Its JSON form is the resolved view the
// shared vectors assert.
type Resolved struct {
	Manifest        Manifest           `json:"-"`
	ManifestVersion int                `json:"manifest_version"`
	AppID           string             `json:"app_id"`
	AgentTools      []string           `json:"agent_tools"`
	SurfaceTools    []string           `json:"surface_tools"`
	HookTools       []string           `json:"hook_tools"`
	InstallScopes   []string           `json:"install_scopes"`
	AppKeys         []ResolvedAppKey   `json:"app_keys"`
	Surfaces        []ResolvedSurface  `json:"surfaces"`
	Usage           *Usage             `json:"usage"`
	Lifecycle       *ResolvedLifecycle `json:"lifecycle"`
	Hooks           *ResolvedHooks     `json:"hooks"`
	tools           map[string]*Tool
}

type ResolvedAppKey struct {
	KID      string   `json:"kid"`
	DIDKey   string   `json:"did_key"`
	Purposes []string `json:"purposes"`
}

type ResolvedSurface struct {
	ID              string                 `json:"id"`
	Label           string                 `json:"label"`
	Format          string                 `json:"format"`
	ListTool        string                 `json:"list_tool"`
	ReadTool        string                 `json:"read_tool"`
	InvokeTool      *string                `json:"invoke_tool"`
	AnswerTool      *string                `json:"answer_tool"`
	ResourceParam   string                 `json:"resource_param"`
	InvocationParam *string                `json:"invocation_param"`
	Events          []ResolvedSurfaceEvent `json:"events"`
}

type ResolvedSurfaceEvent struct {
	Type          string `json:"type"`
	ResourceField string `json:"resource_field"`
	RevisionField string `json:"revision_field"`
}

type ResolvedLifecycle struct {
	ExportTool *string `json:"export_tool"`
	DeleteTool *string `json:"delete_tool"`
	StatusTool *string `json:"status_tool"`
}

// ResolvedHooks lists the declared hook targets and producers. Every entry is
// pending: only the team owner's activation, bound to one installation
// generation and manifest digest, makes it active.
type ResolvedHooks struct {
	RegistrationVersion int                        `json:"registration_version"`
	Registrations       []ResolvedHookRegistration `json:"registrations"`
	Productions         []ResolvedHookProduction   `json:"productions"`
}

type ResolvedHookRegistration struct {
	CatalogID      string   `json:"catalog_id"`
	CatalogVersion int      `json:"catalog_version"`
	Hook           string   `json:"hook"`
	Tool           string   `json:"tool"`
	Scopes         []string `json:"scopes"`
}

type ResolvedHookProduction struct {
	CatalogID      string   `json:"catalog_id"`
	CatalogVersion int      `json:"catalog_version"`
	Hook           string   `json:"hook"`
	Reads          []string `json:"reads"`
}

// Load decodes exact manifest bytes of either supported version, validates
// them and resolves them.
func Load(data []byte, reservedNames map[string]bool) (*Resolved, error) {
	if err := checkNestingDepth(data, MaxJSONDepth); err != nil {
		return nil, codedError(CodeManifestInvalid, err)
	}
	var manifest Manifest
	if err := DecodeSingleJSONStrict(data, &manifest); err != nil {
		return nil, codedError(CodeManifestInvalid, fmt.Errorf("decode manifest: %w", err))
	}
	return Resolve(manifest, reservedNames)
}

// Resolve validates a decoded manifest and resolves it.
func Resolve(manifest Manifest, reservedNames map[string]bool) (*Resolved, error) {
	if err := Validate(manifest, reservedNames); err != nil {
		return nil, err
	}
	appID := strings.TrimSpace(manifest.App.ID)
	r := &Resolved{
		Manifest:        manifest,
		ManifestVersion: manifest.ManifestVersion,
		AppID:           appID,
		AgentTools:      []string{},
		SurfaceTools:    []string{},
		HookTools:       []string{},
		InstallScopes:   []string{},
		AppKeys:         []ResolvedAppKey{},
		Surfaces:        []ResolvedSurface{},
		tools:           toolIndex(manifest.Tools),
	}
	installScopes := map[string]bool{}
	for i := range manifest.Tools {
		name := strings.TrimSpace(manifest.Tools[i].Name)
		contexts := toolContexts(&manifest.Tools[i])
		if contexts[ContextAgent] || contexts[ContextSurface] {
			for _, scope := range manifest.Tools[i].Scopes {
				installScopes[scope] = true
			}
		}
		if contexts[ContextAgent] {
			r.AgentTools = append(r.AgentTools, name)
		}
		if contexts[ContextSurface] {
			r.SurfaceTools = append(r.SurfaceTools, name)
		}
		if contexts[ContextHook] {
			r.HookTools = append(r.HookTools, name)
		}
	}
	for scope := range installScopes {
		r.InstallScopes = append(r.InstallScopes, scope)
	}
	sort.Strings(r.InstallScopes)
	for _, emitter := range manifest.EventEmitters {
		r.AppKeys = append(r.AppKeys, ResolvedAppKey{KID: strings.TrimSpace(emitter.KID), DIDKey: strings.TrimSpace(emitter.DIDKey), Purposes: []string{"app-event"}})
	}
	for _, key := range manifest.AppKeys {
		r.AppKeys = append(r.AppKeys, ResolvedAppKey{KID: key.KID, DIDKey: key.DIDKey, Purposes: append([]string{}, key.Purposes...)})
	}
	declaredEvents := map[string]bool{}
	for _, event := range manifest.Events {
		declaredEvents[strings.TrimPrefix(strings.TrimSpace(event.Type), appID+"/")] = true
	}
	for _, surface := range manifest.Surfaces {
		resolved := ResolvedSurface{
			ID:              surface.ID,
			Label:           surface.Label,
			Format:          surface.Format,
			ListTool:        surface.ListTool,
			ReadTool:        surface.ReadTool,
			InvokeTool:      optional(surface.InvokeTool),
			AnswerTool:      optional(surface.AnswerTool),
			ResourceParam:   surface.Inputs.Resource,
			InvocationParam: optional(surface.Inputs.Invocation),
			Events:          []ResolvedSurfaceEvent{},
		}
		for _, event := range surface.Events {
			eventType, _ := resolveSurfaceEventType(event.Type, appID, declaredEvents)
			resolved.Events = append(resolved.Events, ResolvedSurfaceEvent{Type: eventType, ResourceField: event.ResourceField, RevisionField: event.RevisionField})
		}
		r.Surfaces = append(r.Surfaces, resolved)
	}
	if manifest.Usage != nil {
		usage := *manifest.Usage
		r.Usage = &usage
	}
	if manifest.Lifecycle != nil {
		r.Lifecycle = &ResolvedLifecycle{
			ExportTool: optional(manifest.Lifecycle.ExportTool),
			DeleteTool: optional(manifest.Lifecycle.DeleteTool),
			StatusTool: optional(manifest.Lifecycle.StatusTool),
		}
	}
	if manifest.Hooks != nil {
		hooks := &ResolvedHooks{
			RegistrationVersion: manifest.Hooks.RegistrationVersion,
			Registrations:       []ResolvedHookRegistration{},
			Productions:         []ResolvedHookProduction{},
		}
		for _, reg := range manifest.Hooks.Registrations {
			hooks.Registrations = append(hooks.Registrations, ResolvedHookRegistration{
				CatalogID: reg.Catalog.ID, CatalogVersion: reg.Catalog.Version, Hook: reg.Hook, Tool: reg.Tool,
				Scopes: append([]string{}, reg.Scopes...),
			})
		}
		for _, prod := range manifest.Hooks.Productions {
			hooks.Productions = append(hooks.Productions, ResolvedHookProduction{
				CatalogID: prod.Catalog.ID, CatalogVersion: prod.Catalog.Version, Hook: prod.Hook,
				Reads: append([]string{}, prod.Reads...),
			})
		}
		r.Hooks = hooks
	}
	return r, nil
}

func optional(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

// Tool returns a declared tool by name.
func (r *Resolved) Tool(name string) (*Tool, bool) {
	tool, ok := r.tools[strings.TrimSpace(name)]
	return tool, ok
}

// AppKeysFor returns the declared keys usable for one purpose, in manifest
// order. A version 1 event emitter serves only "app-event".
func (r *Resolved) AppKeysFor(purpose string) []ResolvedAppKey {
	out := []ResolvedAppKey{}
	for _, key := range r.AppKeys {
		for _, declared := range key.Purposes {
			if declared == purpose {
				out = append(out, key)
			}
		}
	}
	return out
}

// Attestation is a request's aweb.principal-attestation/1 as a consumer saw
// it: whether its verifier accepted it, and its payload. The verifier is not
// part of this package.
type Attestation struct {
	Verified bool           `json:"verified"`
	Payload  map[string]any `json:"payload"`
}

// CallerContext maps a request's principal attestation to the invocation
// context it may use. No attestation means an agent caller; a dashboard is
// never inferred.
func CallerContext(attestation *Attestation) (string, error) {
	if attestation == nil {
		return ContextAgent, nil
	}
	if !attestation.Verified {
		return "", codedf(CodeAttestationInvalid, "principal attestation did not verify")
	}
	channel, ok := attestation.Payload["channel"].(string)
	if !ok {
		return "", codedf(CodeChannelInvalid, "principal attestation has no channel")
	}
	switch channel {
	case "dashboard":
		return ContextSurface, nil
	case "mcp_l2", "api":
		return ContextAgent, nil
	default:
		return "", codedf(CodeChannelInvalid, "principal attestation channel %q is not recognised", channel)
	}
}

// CheckInvocationContext refuses a call whose caller context is not one of
// the tool's invocation contexts. It only refuses: passing grants nothing,
// and the call still faces the app's grants, roles and policy.
func (r *Resolved) CheckInvocationContext(toolName string, attestation *Attestation) error {
	caller, err := CallerContext(attestation)
	if err != nil {
		return err
	}
	tool, ok := r.Tool(toolName)
	if !ok {
		return codedf(CodeToolNotFound, "tool %q not found", toolName)
	}
	if !toolContexts(tool)[caller] {
		return codedf(CodeToolContextDenied, "tool %q is not available to %s callers", toolName, caller)
	}
	return nil
}

// CheckAnswerPayload refuses a version 2 request body that carries an answer
// member, top-level or in a top-level object member, for any tool except a
// surface answer_tool. Answers reach an app only through that tool.
func (r *Resolved) CheckAnswerPayload(toolName string, body any) error {
	if r.ManifestVersion != 2 || answerTools(r.Manifest.Surfaces)[strings.TrimSpace(toolName)] {
		return nil
	}
	object, ok := body.(map[string]any)
	if !ok {
		return nil
	}
	if _, carries := object["answer"]; carries {
		return codedf(CodeAnswerPayloadRefused, "tool %q cannot carry an answer", toolName)
	}
	for _, value := range object {
		if member, ok := value.(map[string]any); ok {
			if _, carries := member["answer"]; carries {
				return codedf(CodeAnswerPayloadRefused, "tool %q cannot carry an answer", toolName)
			}
		}
	}
	return nil
}
