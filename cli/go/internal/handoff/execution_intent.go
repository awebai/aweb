package handoff

import (
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/awebai/aw/awid"
)

// artifactIssuance is generated from the pinned definition. Responses cannot
// choose a signing field, consumer, serializer, or artifact lifetime.
type artifactIssuance struct {
	issued     []string
	expiry     string
	lifetime   int
	route      string
	routeField string
}

type artifactIntent struct {
	template map[string]any
	start    time.Time
	until    time.Time
}

var intentTimestamp = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$`)

func intentTime(value any) (time.Time, bool) {
	text, ok := value.(string)
	if !ok || !intentTimestamp.MatchString(text) {
		return time.Time{}, false
	}
	stamp, err := time.Parse(time.RFC3339Nano, text)
	return stamp, err == nil
}

func objectPath(object map[string]any, path string) (map[string]any, string, bool) {
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if !strings.HasPrefix(path, "/") || len(parts) == 0 {
		return nil, "", false
	}
	for _, part := range parts[:len(parts)-1] {
		next, ok := object[part].(map[string]any)
		if !ok {
			return nil, "", false
		}
		object = next
	}
	return object, parts[len(parts)-1], true
}

func clonedObject(object map[string]any) map[string]any {
	raw, err := awid.StrictCanonicalJSON(object)
	if err != nil {
		return nil
	}
	copied, ok := decodeObject(raw)
	if !ok {
		return nil
	}
	return copied
}

func (rule *artifactIssuance) intent(request, descriptor map[string]any) (*artifactIntent, error) {
	invalid := errors.New("its execution intent differs from the pinned definition")
	if request["approval_format"] != "intent_v1" || !exactMembers(descriptor, []string{"v", "type", "template", "delivery", "issuance_window"}) ||
		!sameJSON(descriptor["v"], 1) || descriptor["type"] != "aweb.protected-artifact-intent" {
		return nil, invalid
	}
	template, _ := descriptor["template"].(map[string]any)
	delivery, _ := descriptor["delivery"].(map[string]any)
	window, _ := descriptor["issuance_window"].(map[string]any)
	if template == nil || !exactMembers(delivery, []string{"audience", "method", "path"}) ||
		delivery["audience"] != request["audience"] || delivery["method"] != "POST" ||
		!exactMembers(window, []string{"not_before", "not_after"}) {
		return nil, invalid
	}
	start, validStart := intentTime(window["not_before"])
	until, validUntil := intentTime(window["not_after"])
	if !validStart || !validUntil || !start.Before(until) || until.Sub(start) > 24*time.Hour {
		return nil, invalid
	}
	route := rule.route
	if rule.routeField != "" {
		parent, name, ok := objectPath(template, rule.routeField)
		if !ok {
			return nil, invalid
		}
		route, _ = parent[name].(string)
	}
	if route == "" || delivery["path"] != route {
		return nil, invalid
	}
	absent := append([]string{}, rule.issued...)
	if rule.expiry != "" {
		absent = append(absent, rule.expiry)
	}
	for _, path := range absent {
		parent, name, ok := objectPath(template, path)
		if !ok {
			return nil, invalid
		}
		if _, present := parent[name]; present {
			return nil, invalid
		}
	}
	return &artifactIntent{template, start, until}, nil
}

// preparedArtifact projects the unsigned template into the existing static
// codec validator. These are validation placeholders, never issued or signed.
func (rule *artifactIssuance) preparedArtifact(request, descriptor map[string]any) (map[string]any, error) {
	intent, err := rule.intent(request, descriptor)
	if err != nil {
		return nil, err
	}
	artifact := clonedObject(intent.template)
	for _, path := range rule.issued {
		parent, name, ok := objectPath(artifact, path)
		if !ok {
			return nil, errors.New("invalid issued field")
		}
		parent[name] = intent.start.UTC().Format(time.RFC3339)
	}
	if rule.expiry != "" {
		parent, name, ok := objectPath(artifact, rule.expiry)
		if !ok {
			return nil, errors.New("invalid expiry field")
		}
		until := intent.start.Add(time.Duration(rule.lifetime) * time.Second)
		if intent.until.Before(until) {
			until = intent.until
		}
		parent[name] = until.UTC().Truncate(time.Second).Format(time.RFC3339)
	}
	return artifact, nil
}

// IntentTemplate returns the verified operation's static artifact template.
// Callers still pin their configured controller and requester independently.
func IntentTemplate(request map[string]any) (map[string]any, error) {
	shape, ok := preparedShapeOf(request)
	descriptor, _ := request["artifact"].(map[string]any)
	if !ok || shape.issuance == nil {
		return nil, coded("operation_mismatch", errors.New("no pinned intent definition"))
	}
	intent, err := shape.issuance.intent(request, descriptor)
	if err != nil {
		return nil, coded("operation_mismatch", err)
	}
	artifact, err := shape.issuance.preparedArtifact(request, descriptor)
	if err != nil {
		return nil, coded("operation_mismatch", err)
	}
	if reason := shape.check(request, request, artifact); reason != "" {
		return nil, coded("operation_mismatch", errors.New(reason))
	}
	return clonedObject(intent.template), nil
}

// VerifyIssuedArtifact verifies issuance as history, without a current-clock
// freshness gate or any delivery. The caller verifies the consumer encoding,
// authority signature, and exact applied receipt reference separately.
func VerifyIssuedArtifact(request, actual map[string]any) error {
	shape, ok := preparedShapeOf(request)
	descriptor, _ := request["artifact"].(map[string]any)
	invalid := func() error {
		return coded("operation_mismatch", errors.New("issued artifact differs from the frozen intent"))
	}
	if !ok || shape.issuance == nil {
		return invalid()
	}
	rule := shape.issuance
	intent, err := rule.intent(request, descriptor)
	if err != nil {
		return invalid()
	}
	if reason := shape.check(request, request, actual); reason != "" {
		return invalid()
	}
	stripped := clonedObject(actual)
	var issued time.Time
	for index, path := range rule.issued {
		parent, name, ok := objectPath(stripped, path)
		if !ok {
			return invalid()
		}
		stamp, valid := intentTime(parent[name])
		if !valid || stamp.Nanosecond() != 0 || stamp.Before(intent.start) || !stamp.Before(intent.until) {
			return invalid()
		}
		if index > 0 && !stamp.Equal(issued) {
			return invalid()
		}
		issued = stamp
		delete(parent, name)
	}
	if rule.expiry != "" {
		parent, name, ok := objectPath(stripped, rule.expiry)
		if !ok {
			return invalid()
		}
		expiry, valid := intentTime(parent[name])
		until := issued.Add(time.Duration(rule.lifetime) * time.Second)
		if intent.until.Before(until) {
			until = intent.until
		}
		until = until.Truncate(time.Second)
		if !valid || !expiry.Equal(until) || !expiry.After(issued) {
			return invalid()
		}
		delete(parent, name)
	}
	if !sameJSON(stripped, intent.template) {
		return invalid()
	}
	return nil
}

// An old saved intent may only enter the caller's read-only migration guard.
// It cannot be re-prepared or implicitly decorated with a new version.
func requireIntentFormat(body map[string]any) error {
	shape, defined := preparedShapeOf(body)
	if defined && shape.issuance != nil && body["approval_format"] != "intent_v1" {
		return coded("upgrade_aw_required", errors.New("upgrade aw to use this protected approval format"))
	}
	return nil
}
