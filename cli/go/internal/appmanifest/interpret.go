package appmanifest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/awebai/aw/awid"
)

const SupportedManifestVersion = 1

type Manifest struct {
	ManifestVersion int            `json:"manifest_version"`
	App             App            `json:"app"`
	Tools           []Tool         `json:"tools"`
	EventEmitters   []EventEmitter `json:"event_emitters,omitempty"`
}

type App struct {
	ID      string `json:"id"`
	Version string `json:"version"`
	Origin  string `json:"origin"`
	LLMSTxt string `json:"llms_txt,omitempty"`
	Skills  string `json:"skills,omitempty"`
}

type Tool struct {
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	Method      string         `json:"method"`
	Path        string         `json:"path"`
	InputSchema map[string]any `json:"input_schema,omitempty"`
	Params      []Param        `json:"params"`
	Body        Body           `json:"body,omitempty"`
	Scopes      []string       `json:"scopes,omitempty"`
	Auth        string         `json:"auth,omitempty"`
	Mutation    bool           `json:"mutation"`
}

type Param struct {
	Name string `json:"name"`
	In   string `json:"in"`
}

type Body struct {
	Mode        string `json:"mode,omitempty"`
	RawParam    string `json:"raw_param,omitempty"`
	ContentType string `json:"content_type,omitempty"`
}

type EventEmitter struct {
	KID    string `json:"kid"`
	DIDKey string `json:"did_key"`
}

type InterpretRequest struct {
	Manifest      Manifest
	Verb          string
	Args          map[string]any
	RawBody       []byte
	ReservedNames map[string]bool
}

type InterpretedRequest struct {
	Method     string            `json:"method"`
	URL        string            `json:"url"`
	PathQuery  string            `json:"path_query"`
	Headers    map[string]string `json:"headers"`
	Body       []byte            `json:"-"`
	BodyString string            `json:"body"`
	BodySHA256 string            `json:"body_sha256"`
	Auth       string            `json:"auth,omitempty"`
	Mutation   bool              `json:"mutation"`
}

func Validate(manifest Manifest, reservedNames map[string]bool) error {
	if manifest.ManifestVersion != SupportedManifestVersion {
		return fmt.Errorf("unsupported manifest_version %d", manifest.ManifestVersion)
	}
	appID := strings.TrimSpace(manifest.App.ID)
	if appID == "" {
		return fmt.Errorf("app.id is required")
	}
	if reservedNames != nil && reservedNames[appID] {
		return fmt.Errorf("app id %q is reserved built-in command or alias", appID)
	}
	if _, err := parseOrigin(manifest.App.Origin); err != nil {
		return err
	}
	for _, tool := range manifest.Tools {
		if err := validateTool(tool, reservedNames); err != nil {
			return err
		}
	}
	if err := validateEventEmitters(manifest.EventEmitters); err != nil {
		return err
	}
	return nil
}

func normalizeToolAuth(tool Tool) (string, error) {
	// Absent auth defaults to signed team-cert. A present-but-whitespace-only
	// auth is malformed and rejected as unsupported (matching AC), rather than
	// trimmed to "" and silently normalized to team-cert.
	if tool.Auth == "" {
		return "team-cert", nil
	}
	auth := strings.TrimSpace(tool.Auth)
	if auth != "none" {
		return "", fmt.Errorf("tool %q has unsupported auth %q", tool.Name, tool.Auth)
	}
	if tool.Mutation {
		return "", fmt.Errorf("tool %q cannot use auth:none for a mutation", tool.Name)
	}
	return "none", nil
}

func validateEventEmitters(emitters []EventEmitter) error {
	seen := map[string]bool{}
	for _, emitter := range emitters {
		kid := strings.TrimSpace(emitter.KID)
		if kid == "" {
			return fmt.Errorf("event_emitters[].kid is required")
		}
		if seen[kid] {
			return fmt.Errorf("duplicate event emitter kid %q", kid)
		}
		seen[kid] = true
		didKey := strings.TrimSpace(emitter.DIDKey)
		if didKey == "" {
			return fmt.Errorf("event_emitters[].did_key is required")
		}
		if _, err := awid.ExtractPublicKey(didKey); err != nil {
			return fmt.Errorf("event emitter kid %q did_key: %w", kid, err)
		}
	}
	return nil
}

func validateTool(tool Tool, reservedNames map[string]bool) error {
	if strings.TrimSpace(tool.Name) == "" {
		return fmt.Errorf("tool.name is required")
	}
	if reservedNames != nil && reservedNames[strings.TrimSpace(tool.Name)] {
		return fmt.Errorf("tool name %q is reserved built-in command or alias", tool.Name)
	}
	method := strings.ToUpper(strings.TrimSpace(tool.Method))
	if !validMethod(method) {
		return fmt.Errorf("unsupported method %q", tool.Method)
	}
	if _, err := normalizeToolAuth(tool); err != nil {
		return err
	}
	path, err := validateRelativePath(tool.Path)
	if err != nil {
		return err
	}
	properties := schemaProperties(tool.InputSchema)
	paramByName := map[string]Param{}
	for _, param := range tool.Params {
		name := strings.TrimSpace(param.Name)
		if name == "" {
			return fmt.Errorf("tool %q has a param with empty name", tool.Name)
		}
		placement := strings.TrimSpace(param.In)
		switch placement {
		case "path", "query", "body":
		default:
			return fmt.Errorf("param %q has invalid placement %q", name, param.In)
		}
		if _, exists := paramByName[name]; exists {
			return fmt.Errorf("duplicate param %q", name)
		}
		paramByName[name] = Param{Name: name, In: placement}
		if _, ok := properties[name]; !ok {
			return fmt.Errorf("param %q is not declared in input_schema", name)
		}
	}
	for name := range properties {
		if _, ok := paramByName[name]; !ok {
			return fmt.Errorf("input_schema field %q is missing params placement", name)
		}
	}
	placeholders := pathPlaceholders(path)
	for placeholder := range placeholders {
		param, ok := paramByName[placeholder]
		if !ok || param.In != "path" {
			return fmt.Errorf("path placeholder %q has no matching in:path param", placeholder)
		}
	}
	for name, param := range paramByName {
		if param.In == "path" && !placeholders[name] {
			return fmt.Errorf("path param %q has no matching placeholder", name)
		}
	}
	mode := strings.TrimSpace(tool.Body.Mode)
	if mode == "" {
		mode = "json"
	}
	if mode != "json" && mode != "raw" {
		return fmt.Errorf("unsupported body mode %q", tool.Body.Mode)
	}
	if mode == "raw" {
		rawParam := strings.TrimSpace(tool.Body.RawParam)
		if rawParam == "" {
			return fmt.Errorf("raw body mode requires body.raw_param")
		}
		if strings.TrimSpace(tool.Body.ContentType) == "" {
			return fmt.Errorf("raw body mode requires body.content_type")
		}
		param, ok := paramByName[rawParam]
		if !ok || param.In != "body" {
			return fmt.Errorf("raw body param %q must be declared as in:body", rawParam)
		}
		for name, param := range paramByName {
			if param.In == "body" && name != rawParam {
				return fmt.Errorf("raw body mode allows only raw_param %q in body", rawParam)
			}
		}
	}
	if mode == "json" && strings.TrimSpace(tool.Body.RawParam) != "" {
		return fmt.Errorf("body.raw_param is only valid for raw body mode")
	}
	for name, param := range paramByName {
		if param.In == "body" && schemaType(properties[name]) == "number" {
			return fmt.Errorf("body param %q uses unsupported type number: number/float body fields are not supported in manifest v1", name)
		}
	}
	return nil
}

func Interpret(req InterpretRequest) (*InterpretedRequest, error) {
	manifest := req.Manifest
	if err := Validate(manifest, req.ReservedNames); err != nil {
		return nil, err
	}
	origin, err := parseOrigin(manifest.App.Origin)
	if err != nil {
		return nil, err
	}
	tool, err := findTool(manifest.Tools, req.Verb)
	if err != nil {
		return nil, err
	}
	if req.ReservedNames != nil && req.ReservedNames[strings.TrimSpace(tool.Name)] {
		return nil, fmt.Errorf("tool name %q is reserved built-in command or alias", tool.Name)
	}
	method := strings.ToUpper(strings.TrimSpace(tool.Method))
	if !validMethod(method) {
		return nil, fmt.Errorf("unsupported method %q", tool.Method)
	}
	auth, err := normalizeToolAuth(*tool)
	if err != nil {
		return nil, err
	}
	path, err := validateRelativePath(tool.Path)
	if err != nil {
		return nil, err
	}
	properties := schemaProperties(tool.InputSchema)
	args := req.Args
	if args == nil {
		args = map[string]any{}
	}
	pathWithParams, err := substitutePath(path, tool.Params, args)
	if err != nil {
		return nil, err
	}
	query, err := canonicalQuery(tool.Params, args)
	if err != nil {
		return nil, err
	}
	targetPath := joinOriginPath(origin.EscapedPath(), pathWithParams)
	pathQuery := targetPath
	if query != "" {
		pathQuery += "?" + query
	}
	absoluteURL := origin.Scheme + "://" + origin.Host + pathQuery

	body, contentType, err := buildBody(tool, args, properties, req.RawBody)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(body)
	return &InterpretedRequest{
		Method:     method,
		URL:        absoluteURL,
		PathQuery:  pathQuery,
		Headers:    map[string]string{"Content-Type": contentType},
		Body:       body,
		BodyString: string(body),
		BodySHA256: hex.EncodeToString(sum[:]),
		Auth:       auth,
		Mutation:   tool.Mutation,
	}, nil
}

func parseOrigin(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("app.origin is required")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("invalid app.origin %q", raw)
	}
	u.RawQuery = ""
	u.Fragment = ""
	return u, nil
}

func findTool(tools []Tool, verb string) (*Tool, error) {
	verb = strings.TrimSpace(verb)
	for i := range tools {
		if strings.TrimSpace(tools[i].Name) == verb {
			return &tools[i], nil
		}
	}
	return nil, fmt.Errorf("tool %q not found", verb)
}

func validMethod(method string) bool {
	switch method {
	case "GET", "POST", "PUT", "PATCH", "DELETE":
		return true
	default:
		return false
	}
}

func validateRelativePath(raw string) (string, error) {
	path := strings.TrimSpace(raw)
	if path == "" {
		return "", fmt.Errorf("tool.path is required")
	}
	if strings.Contains(path, "://") || strings.HasPrefix(path, "//") {
		return "", fmt.Errorf("tool.path must be relative and cannot include scheme or host")
	}
	u, err := url.Parse(path)
	if err != nil {
		return "", err
	}
	if u.IsAbs() || u.Host != "" || u.Scheme != "" {
		return "", fmt.Errorf("tool.path must be relative and cannot include scheme or host")
	}
	if u.RawQuery != "" {
		return "", fmt.Errorf("tool.path must not include query; use params with in:query")
	}
	if u.Fragment != "" {
		return "", fmt.Errorf("tool.path must not include fragment")
	}
	parts := strings.Split(u.Path, "/")
	for _, part := range parts {
		if part == ".." {
			return "", fmt.Errorf("tool.path must not contain path traversal")
		}
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return path, nil
}

func pathPlaceholders(path string) map[string]bool {
	out := map[string]bool{}
	for {
		start := strings.Index(path, "{")
		if start < 0 {
			return out
		}
		end := strings.Index(path[start+1:], "}")
		if end < 0 {
			return out
		}
		name := strings.TrimSpace(path[start+1 : start+1+end])
		if name != "" {
			out[name] = true
		}
		path = path[start+1+end+1:]
	}
}

func substitutePath(path string, params []Param, args map[string]any) (string, error) {
	out := path
	pathParams := map[string]bool{}
	for _, p := range params {
		if strings.TrimSpace(p.In) == "path" {
			pathParams[strings.TrimSpace(p.Name)] = true
		}
	}
	for name := range pathParams {
		placeholder := "{" + name + "}"
		if !strings.Contains(out, placeholder) {
			return "", fmt.Errorf("path param %q has no matching placeholder", name)
		}
		value, ok := args[name]
		if !ok || isEmpty(value) {
			return "", fmt.Errorf("missing path param %q", name)
		}
		out = strings.ReplaceAll(out, placeholder, escapePathSegment(fmt.Sprint(value)))
	}
	if strings.Contains(out, "{") || strings.Contains(out, "}") {
		return "", fmt.Errorf("tool.path contains placeholder without matching path param")
	}
	return out, nil
}

func canonicalQuery(params []Param, args map[string]any) (string, error) {
	parts := []string{}
	for _, p := range params {
		if strings.TrimSpace(p.In) != "query" {
			continue
		}
		name := strings.TrimSpace(p.Name)
		value, ok := args[name]
		if !ok || isEmpty(value) {
			continue
		}
		values, err := queryValues(value)
		if err != nil {
			return "", fmt.Errorf("query param %s: %w", name, err)
		}
		for _, v := range values {
			parts = append(parts, rfc3986Escape(name)+"="+rfc3986Escape(v))
		}
	}
	return strings.Join(parts, "&"), nil
}

func queryValues(value any) ([]string, error) {
	switch v := value.(type) {
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			out = append(out, fmt.Sprint(item))
		}
		return out, nil
	case []string:
		return v, nil
	default:
		return []string{fmt.Sprint(value)}, nil
	}
}

func buildBody(tool *Tool, args map[string]any, properties map[string]map[string]any, rawBody []byte) ([]byte, string, error) {
	mode := strings.TrimSpace(tool.Body.Mode)
	if mode == "" {
		mode = "json"
	}
	switch mode {
	case "json":
		body := map[string]any{}
		for _, p := range tool.Params {
			if strings.TrimSpace(p.In) != "body" {
				continue
			}
			name := strings.TrimSpace(p.Name)
			value, ok := args[name]
			if !ok || isEmpty(value) {
				continue
			}
			coerced, err := coerceValue(value, schemaType(properties[name]))
			if err != nil {
				return nil, "", fmt.Errorf("body param %s: %w", name, err)
			}
			body[name] = coerced
		}
		if len(body) == 0 {
			return []byte{}, "application/json", nil
		}
		canonical, err := awid.CanonicalJSONValue(body)
		if err != nil {
			return nil, "", err
		}
		return []byte(canonical), "application/json", nil
	case "raw":
		if strings.TrimSpace(tool.Body.RawParam) == "" {
			return nil, "", fmt.Errorf("raw body mode requires body.raw_param")
		}
		contentType := strings.TrimSpace(tool.Body.ContentType)
		if contentType == "" {
			return nil, "", fmt.Errorf("raw body mode requires body.content_type")
		}
		if rawBody != nil {
			return rawBody, contentType, nil
		}
		value, ok := args[strings.TrimSpace(tool.Body.RawParam)]
		if !ok {
			return nil, "", fmt.Errorf("missing raw body param %q", tool.Body.RawParam)
		}
		return []byte(fmt.Sprint(value)), contentType, nil
	default:
		return nil, "", fmt.Errorf("unsupported body mode %q", mode)
	}
}

func schemaProperties(schema map[string]any) map[string]map[string]any {
	out := map[string]map[string]any{}
	raw, _ := schema["properties"].(map[string]any)
	for name, value := range raw {
		if m, ok := value.(map[string]any); ok {
			out[name] = m
		}
	}
	return out
}

func schemaType(prop map[string]any) string {
	if prop == nil {
		return ""
	}
	if raw, ok := prop["type"].(string); ok {
		return strings.TrimSpace(raw)
	}
	return ""
}

func coerceValue(value any, typ string) (any, error) {
	switch typ {
	case "", "string":
		if typ == "string" {
			return fmt.Sprint(value), nil
		}
		return value, nil
	case "integer":
		switch v := value.(type) {
		case float64:
			if v != float64(int64(v)) {
				return nil, fmt.Errorf("expected integer")
			}
			return int64(v), nil
		case json.Number:
			return v.Int64()
		case int, int8, int16, int32, int64:
			return v, nil
		case string:
			return strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		default:
			return nil, fmt.Errorf("expected integer")
		}
	case "boolean":
		switch v := value.(type) {
		case bool:
			return v, nil
		case string:
			return strconv.ParseBool(strings.TrimSpace(v))
		default:
			return nil, fmt.Errorf("expected boolean")
		}
	case "number":
		return nil, fmt.Errorf("number/float body fields are not supported in manifest v1")
	case "array":
		switch v := value.(type) {
		case []any:
			return v, nil
		case string:
			var arr []any
			if err := json.Unmarshal([]byte(v), &arr); err != nil {
				return nil, fmt.Errorf("expected array (JSON): %w", err)
			}
			return arr, nil
		default:
			return nil, fmt.Errorf("expected array")
		}
	case "object":
		switch v := value.(type) {
		case map[string]any:
			return v, nil
		case string:
			var m map[string]any
			if err := json.Unmarshal([]byte(v), &m); err != nil {
				return nil, fmt.Errorf("expected object (JSON): %w", err)
			}
			return m, nil
		default:
			return nil, fmt.Errorf("expected object")
		}
	default:
		return nil, fmt.Errorf("unsupported schema type %q", typ)
	}
}

func joinOriginPath(originPath, toolPath string) string {
	originPath = strings.TrimRight(originPath, "/")
	if originPath == "" {
		return toolPath
	}
	return originPath + toolPath
}

func isEmpty(value any) bool {
	if value == nil {
		return true
	}
	if s, ok := value.(string); ok {
		return s == ""
	}
	return false
}

func escapePathSegment(value string) string {
	return rfc3986Escape(value)
}

func rfc3986Escape(value string) string {
	escaped := url.QueryEscape(value)
	escaped = strings.ReplaceAll(escaped, "+", "%20")
	escaped = strings.ReplaceAll(escaped, "%7E", "~")
	return escaped
}

func SortedHeaderString(headers map[string]string) string {
	keys := make([]string, 0, len(headers))
	for key := range headers {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+":"+headers[key])
	}
	return strings.Join(parts, "\n")
}
