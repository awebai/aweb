package handoff

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	awid "github.com/awebai/aw/awid"
)

// displayRow is one labelled value of a display: its key and the JSON
// pointer into the frozen request it shows.
type displayRow struct{ key, source string }

// operationDisplay is an operation definition's display, pinned from the
// generated description (scripts/generate_protected_operations.py).
type operationDisplay struct {
	title        string
	consequences []string
	names        []displayRow
	technical    []displayRow
	refusals     map[string]string
}

// RenderedDisplay is what a person is shown for one frozen request.
type RenderedDisplay struct {
	Title        string
	Consequences []string
	Names        [][2]string
	Technical    [][2]string
}

var displayTemplate = regexp.MustCompile(`\{(/[^{}]*)\}`)

func errDisplay() error {
	return coded("operation_mismatch", errors.New("the frozen request does not fill its definition's display"))
}

// RenderDisplay fills selector's display from request exactly as the page,
// the owner page and the approval notice do (operation_display.py): a string
// shows as itself, an integer in decimal, a list of strings joined with ", ".
// Technical rows show any other value as canonical JSON. A pointer ending in
// "|team" shows a team id, or each in a list, by its name; "|kind" names a
// frozen target kind. A missing pointer,
// or a title, consequence or name of another kind, refuses.
func RenderDisplay(selector string, request map[string]any) (RenderedDisplay, error) {
	display, ok := generatedDisplays[selector]
	if !ok {
		return RenderedDisplay{}, errDisplay()
	}
	return display.render(request)
}

func (d operationDisplay) render(request map[string]any) (RenderedDisplay, error) {
	var failed error
	fill := func(template string) string {
		return displayTemplate.ReplaceAllStringFunc(template, func(match string) string {
			value, err := readPointer(request, match[1:len(match)-1])
			if err == nil {
				var text string
				if text, err = displayWords(value); err == nil {
					return text
				}
			}
			failed = err
			return ""
		})
	}
	rendered := RenderedDisplay{Title: fill(d.title)}
	for _, line := range d.consequences {
		rendered.Consequences = append(rendered.Consequences, fill(line))
	}
	if failed != nil {
		return RenderedDisplay{}, failed
	}
	for _, row := range d.names {
		value, err := readPointer(request, row.source)
		if err != nil {
			return RenderedDisplay{}, err
		}
		text, err := displayWords(value)
		if err != nil {
			return RenderedDisplay{}, err
		}
		rendered.Names = append(rendered.Names, [2]string{displayLabel(row.key), text})
	}
	for _, row := range d.technical {
		value, err := readPointer(request, row.source)
		if err != nil {
			return RenderedDisplay{}, err
		}
		text, err := displayWords(value)
		if err != nil {
			canonical, cerr := awid.StrictCanonicalJSON(value)
			if cerr != nil {
				return RenderedDisplay{}, errDisplay()
			}
			text = string(canonical)
		}
		rendered.Technical = append(rendered.Technical, [2]string{displayLabel(row.key), text})
	}
	return rendered, nil
}

func readPointer(request map[string]any, source string) (any, error) {
	pointer, formatter, formatted := strings.Cut(source, "|")
	var value any = request
	for _, part := range strings.Split(pointer, "/")[1:] {
		object, ok := value.(map[string]any)
		if !ok {
			return nil, errDisplay()
		}
		if value, ok = object[part]; !ok {
			return nil, errDisplay()
		}
	}
	if !formatted {
		return value, nil
	}
	if formatter == "period" {
		number, isNumber := value.(json.Number)
		if !isNumber || strings.ContainsAny(number.String(), ".eE") {
			return nil, errDisplay()
		}
		seconds, err := number.Int64()
		if err != nil || seconds <= 0 {
			return nil, errDisplay()
		}
		switch seconds {
		case 3600:
			return "hour", nil
		case 86400:
			return "day", nil
		}
		return fmt.Sprintf("%d seconds", seconds), nil
	}
	if formatter == "kind" {
		kind, ok := value.(string)
		if words, named := displayKinds[kind]; ok && named {
			return words, nil
		}
		return nil, errDisplay()
	}
	if formatter != "team" {
		return nil, errDisplay()
	}
	if items, ok := value.([]any); ok {
		names := make([]any, 0, len(items))
		for _, item := range items {
			name, err := teamName(item)
			if err != nil {
				return nil, err
			}
			names = append(names, name)
		}
		return names, nil
	}
	return teamName(value)
}

// displayKinds names a frozen target kind in the words the owner page uses.
var displayKinds = map[string]string{"agent": "agent", "kind not verified": "agent or person not confirmed"}

// teamName shows a team id ("name:domain") by its name, as the owner page does.
func teamName(value any) (any, error) {
	id, ok := value.(string)
	parts := strings.Split(id, ":")
	if !ok || len(parts) != 2 || parts[0] == "" {
		return nil, errDisplay()
	}
	return parts[0], nil
}

func displayWords(value any) (string, error) {
	switch v := value.(type) {
	case string:
		return v, nil
	case json.Number:
		if _, err := v.Int64(); err == nil && !strings.ContainsAny(v.String(), ".eE") {
			return v.String(), nil
		}
	case []any:
		items := make([]string, 0, len(v))
		for _, item := range v {
			text, ok := item.(string)
			if !ok {
				return "", errDisplay()
			}
			items = append(items, text)
		}
		return strings.Join(items, ", "), nil
	}
	return "", errDisplay()
}

func displayLabel(key string) string {
	text := strings.ReplaceAll(key, "_", " ")
	if text == "" {
		return text
	}
	return strings.ToUpper(text[:1]) + text[1:]
}

// displayRefusal is the definition's own sentence for a refusal code, if any.
func displayRefusal(selector, code string) (string, bool) {
	sentence, ok := generatedDisplays[selector].refusals[code]
	return sentence, ok
}

// selectorOf is the definition selector a prepare body names.
func selectorOf(body map[string]any) string {
	operation, _ := body["operation"].(string)
	variant, _ := body["variant"].(string)
	return operation + "|" + variant
}
