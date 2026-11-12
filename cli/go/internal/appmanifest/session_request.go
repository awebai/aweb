package appmanifest

import (
	"fmt"
	"strings"
)

// SessionRequest is a session action's request: its method, its raw
// request target relative to owner_acts.origin, and its body.
type SessionRequest struct {
	Method    string
	PathQuery string
	Body      []byte
}

// Request builds the action's request from args under the version 2 path,
// query and body rules. A json-mode POST with no body member sends {}, since
// a JSON route reads an object; a GET sends no body.
func (action SessionAction) Request(args map[string]any) (*SessionRequest, error) {
	tool := action.tool()
	method := strings.ToUpper(strings.TrimSpace(tool.Method))
	path, err := validateRelativePath(tool.Path)
	if err != nil {
		return nil, err
	}
	if args == nil {
		args = map[string]any{}
	}
	filled, err := substitutePath(path, tool.Params, args)
	if err != nil {
		return nil, err
	}
	query, err := canonicalQuery(tool.Params, args)
	if err != nil {
		return nil, err
	}
	if query != "" {
		filled += "?" + query
	}
	request := &SessionRequest{Method: method, PathQuery: filled}
	if method == "GET" {
		return request, nil
	}
	body, _, err := buildBody(&tool, args, schemaProperties(tool.InputSchema), nil)
	if err != nil {
		return nil, fmt.Errorf("session action %s: %w", action.Name, err)
	}
	if len(body) == 0 && action.bodyMode() == "json" {
		body = []byte("{}")
	}
	request.Body = body
	return request, nil
}
