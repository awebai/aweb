package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
)

// parseHookJSON implements docs/runtime-hook-configuration.md:3-7.
// All hook edits use offsets in the original JSON. Unrelated user bytes never
// pass through a decoder/encoder round trip (including numbers and escapes).
func parseHookJSON(data []byte) (*hookJSONNode, error) {
	if !json.Valid(data) {
		return nil, &hookJSONError{Problem: invalidHookJSON, Detail: "invalid JSON; settings left unchanged"}
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	root, err := readHookJSONNode(dec, data)
	if err != nil {
		return nil, err
	}
	if root.object == nil {
		return nil, &hookJSONError{Problem: nonObjectHookSettings, Detail: "settings must be a JSON object"}
	}
	return root, nil
}

type hookJSONEdit struct {
	start, end int
	content    []byte
}

func editHookJSON(data []byte, edits []hookJSONEdit) ([]byte, error) {
	sort.SliceStable(edits, func(i, j int) bool { return edits[i].start < edits[j].start })
	var out bytes.Buffer
	pos := 0
	for _, edit := range edits {
		if edit.start < pos || edit.end < edit.start {
			return nil, fmt.Errorf("overlapping hook edits; settings left unchanged")
		}
		out.Write(data[pos:edit.start])
		out.Write(edit.content)
		pos = edit.end
	}
	out.Write(data[pos:])
	if !json.Valid(out.Bytes()) {
		return nil, fmt.Errorf("hook edit would produce invalid JSON; settings left unchanged")
	}
	return out.Bytes(), nil
}

func appendHookJSON(container *hookJSONNode, content string) hookJSONEdit {
	prefix := ""
	if len(container.array) > 0 || len(container.object) > 0 {
		prefix = ","
	}
	return hookJSONEdit{container.end - 1, container.end - 1, []byte(prefix + content)}
}

// This is the matcher installed by aw. Custom matchers remain user-owned.
func ownedNotifyGroup(group *hookJSONNode) bool {
	matcher := group.member("matcher")
	return matcher == nil || matcher.stringValue() == ".*"
}

func notifyHandlers(root *hookJSONNode) ([]*hookJSONNode, error) {
	hooks := root.member("hooks")
	if hooks == nil {
		return nil, nil
	}
	if hooks.object == nil {
		return nil, &hookJSONError{Problem: nonObjectHooks, Detail: "hooks must be a JSON object"}
	}
	post := hooks.member("PostToolUse")
	if post == nil {
		return nil, nil
	}
	if post.value != json.Delim('[') {
		return nil, fmt.Errorf("hooks.PostToolUse must be an array")
	}
	var handlers []*hookJSONNode
	for _, group := range post.array {
		if group.object == nil {
			return nil, fmt.Errorf("hooks.PostToolUse groups must be objects")
		}
		if !ownedNotifyGroup(group) {
			continue
		}
		inner := group.member("hooks")
		if inner == nil {
			handlers = append(handlers, group)
			continue
		}
		if inner.value != json.Delim('[') {
			return nil, fmt.Errorf("PostToolUse handlers must be an array")
		}
		handlers = append(handlers, inner.array...)
	}
	return handlers, nil
}

func notifyHookMatches(n *hookJSONNode, command string) bool {
	kind := n.member("type")
	return n.member("command").stringValue() == command && (kind == nil || kind.stringValue() == string(commandHookKind))
}

func installNotifyHookBytes(data []byte) ([]byte, bool, error) {
	root, err := parseHookJSON(data)
	if err != nil {
		return nil, false, err
	}
	handlers, err := notifyHandlers(root)
	if err != nil {
		return nil, false, err
	}
	for _, handler := range handlers {
		if notifyHookMatches(handler, notifyHookCommand) {
			return data, true, nil
		}
	}
	var edits []hookJSONEdit
	for _, handler := range handlers {
		if notifyHookMatches(handler, legacyNotifyHookCommand) {
			command := handler.member("command")
			edits = append(edits, hookJSONEdit{command.start, command.end, []byte(`"aw notify"`)})
		}
	}
	if len(edits) == 0 {
		group := `{"matcher":".*","hooks":[{"type":"command","command":"aw notify"}]}`
		hooks := root.member("hooks")
		switch {
		case hooks == nil:
			edits = append(edits, appendHookJSON(root, `"hooks":{"PostToolUse":[`+group+`]}`))
		case hooks.member("PostToolUse") == nil:
			edits = append(edits, appendHookJSON(hooks, `"PostToolUse":[`+group+`]`))
		default:
			edits = append(edits, appendHookJSON(hooks.member("PostToolUse"), group))
		}
	}
	updated, err := editHookJSON(data, edits)
	return updated, false, err
}

// hookJSONNode records byte offsets and structure without re-encoding values.
// Duplicate keys are refused because runtimes can disagree about their meaning.
type hookJSONNode struct {
	start, end int
	object     map[string]*hookJSONNode
	array      []*hookJSONNode
	value      any
}

func (n *hookJSONNode) member(key string) *hookJSONNode {
	if n == nil {
		return nil
	}
	return n.object[key]
}
func (n *hookJSONNode) stringValue() string {
	if n == nil {
		return ""
	}
	value, ok := n.value.(string)
	if !ok {
		return ""
	}
	return value
}

func readHookJSONNode(dec *json.Decoder, data []byte) (*hookJSONNode, error) {
	start := int(dec.InputOffset())
	// InputOffset before a value includes the preceding comma/colon and whitespace.
	for start < len(data) && (data[start] == ' ' || data[start] == '\n' || data[start] == '\r' || data[start] == '\t' || data[start] == ':' || data[start] == ',') {
		start++
	}
	token, err := dec.Token()
	if err != nil {
		return nil, err
	}
	n := &hookJSONNode{start: start, value: token}
	if delim, ok := token.(json.Delim); ok {
		switch delim {
		case '{':
			n.object = map[string]*hookJSONNode{}
			for dec.More() {
				keyToken, err := dec.Token()
				if err != nil {
					return nil, err
				}
				key, ok := keyToken.(string)
				if !ok {
					return nil, fmt.Errorf("JSON object key must be a string")
				}
				if _, exists := n.object[key]; exists {
					return nil, &hookJSONError{Problem: duplicateHookJSONKey, Detail: fmt.Sprintf("duplicate JSON key %q", key)}
				}
				child, err := readHookJSONNode(dec, data)
				if err != nil {
					return nil, err
				}
				n.object[key] = child
			}
		case '[':
			for dec.More() {
				child, err := readHookJSONNode(dec, data)
				if err != nil {
					return nil, err
				}
				n.array = append(n.array, child)
			}
		}
		if _, err := dec.Token(); err != nil {
			return nil, err
		}
	}
	n.end = int(dec.InputOffset())
	return n, nil
}

type hookByteSpan struct{ start, end int }

// hookArrayRemovalSpans implements docs/runtime-hook-configuration.md:3-8.
// Remove owned values and separator commas separately; surrounding whitespace is
// user data, including whitespace that precedes an appended handler's comma.
func hookArrayRemovalSpans(data []byte, nodes []*hookJSONNode, remove []bool) ([]hookByteSpan, error) {
	if len(nodes) != len(remove) {
		return nil, fmt.Errorf("hook removal plan does not match the array")
	}
	var spans []hookByteSpan
	for i := 0; i < len(nodes); {
		if !remove[i] {
			i++
			continue
		}
		first := i
		for i < len(nodes) && remove[i] {
			spans = append(spans, hookByteSpan{start: nodes[i].start, end: nodes[i].end})
			i++
		}
		separatorFirst, separatorEnd := first, i
		if i == len(nodes) {
			separatorFirst, separatorEnd = first-1, i-1
		}
		if separatorFirst < 0 {
			separatorFirst = 0
		}
		for j := separatorFirst; j < separatorEnd; j++ {
			gap := nodes[j].end
			comma := bytes.IndexByte(data[gap:nodes[j+1].start], ',')
			if comma < 0 {
				return nil, fmt.Errorf("missing hook array separator; settings left unchanged")
			}
			spans = append(spans, hookByteSpan{start: gap + comma, end: gap + comma + 1})
		}
	}
	return spans, nil
}

type runtimeHookKind string

const commandHookKind runtimeHookKind = "command"
