package wake

import (
	"fmt"
	"sort"
	"strings"
)

// maxDetailLines bounds the hint summary; the remainder is reported as a count
// so a large backlog cannot type an unbounded paste into a terminal.
const maxDetailLines = 12

// maxComposedBytes bounds the whole message for the same reason.
const maxComposedBytes = 1600

// maxTokenRunes bounds one sender alias or id inside the summary.
const maxTokenRunes = 64

// Compose renders the message the broker types: a fixed instruction to fetch,
// plus a hint summary of metadata and counts (§4, §7).
//
// It cannot render a subject or a body, because Hint carries neither. What it
// does render — sender aliases and ids — comes off the wire, so every one of
// them goes through safeToken before it reaches text destined for a terminal.
func Compose(hints []Hint) string {
	if len(hints) == 0 {
		return ""
	}

	ordered := make([]Hint, len(hints))
	copy(ordered, hints)
	sort.SliceStable(ordered, func(i, j int) bool {
		if a, b := batchRank(ordered[i]), batchRank(ordered[j]); a != b {
			return a < b
		}
		return ordered[i].At.Before(ordered[j].At)
	})

	var b strings.Builder
	b.WriteString("aweb: ")
	b.WriteString(pluralItems(len(ordered)))
	if hasIdentityContext(ordered) {
		b.WriteString(" waiting. Check the listed identity contexts with aw, then handle what is there.\n")
		for _, line := range commandLines(ordered) {
			b.WriteString("  ")
			b.WriteString(line)
			b.WriteString("\n")
		}
	} else {
		b.WriteString(" waiting. Check them from this instance with `aw mail inbox`\n")
		b.WriteString("and `aw chat pending`, then handle what is there.\n")
	}

	lines := summaryLines(ordered)
	shown := lines
	if len(shown) > maxDetailLines {
		shown = shown[:maxDetailLines]
	}
	for _, line := range shown {
		b.WriteString("  ")
		b.WriteString(line)
		b.WriteString("\n")
	}
	if len(lines) > len(shown) {
		fmt.Fprintf(&b, "  and %d more\n", len(lines)-len(shown))
	}

	out := b.String()
	if len(out) > maxComposedBytes {
		out = out[:maxComposedBytes]
		if idx := strings.LastIndexByte(out, '\n'); idx > 0 {
			out = out[:idx+1]
		}
	}
	return out
}

func pluralItems(n int) string {
	if n == 1 {
		return "1 item"
	}
	return fmt.Sprintf("%d items", n)
}

func hasIdentityContext(hints []Hint) bool {
	for _, h := range hints {
		if strings.TrimSpace(h.IdentityHome) != "" || strings.TrimSpace(h.TeamID) != "" || strings.TrimSpace(h.IdentityLabel) != "" {
			return true
		}
	}
	return false
}

func commandLines(hints []Hint) []string {
	type commandContext struct {
		label string
		home  string
		team  string
	}
	seen := map[string]struct{}{}
	contexts := []commandContext{}
	for _, h := range hints {
		home := strings.TrimSpace(h.IdentityHome)
		team := strings.TrimSpace(h.TeamID)
		if home == "" && team == "" {
			continue
		}
		key := home + "|" + team
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		contexts = append(contexts, commandContext{label: safeToken(firstNonEmpty(h.IdentityLabel, team, home)), home: home, team: team})
	}
	sort.SliceStable(contexts, func(i, j int) bool { return contexts[i].label < contexts[j].label })
	out := make([]string, 0, len(contexts))
	for _, ctx := range contexts {
		args := "aw"
		if ctx.home != "" {
			args += " --identity-home " + shellQuote(ctx.home)
		}
		if ctx.team != "" {
			args += " --team " + shellQuote(ctx.team)
		}
		label := ctx.label
		if label == "" {
			label = "identity"
		}
		out = append(out, fmt.Sprintf("%s: `%s mail inbox` and `%s chat pending`", label, args, args))
	}
	return out
}

func contextPrefix(context string) string {
	if context == "" {
		return ""
	}
	return context + ": "
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

type summaryGroup struct {
	order int
	key   string
	line  func(g *groupState) string
	state groupState
}

type groupState struct {
	count   int
	waiting bool
	ids     []string
	from    string
	context string
}

func summaryLines(hints []Hint) []string {
	groups := []*summaryGroup{}
	index := map[string]*summaryGroup{}

	add := func(key string, render func(g *groupState) string, mutate func(g *groupState)) {
		g, ok := index[key]
		if !ok {
			g = &summaryGroup{order: len(groups), key: key, line: render}
			index[key] = g
			groups = append(groups, g)
		}
		g.state.count++
		if mutate != nil {
			mutate(&g.state)
		}
	}

	for _, h := range hints {
		from := safeToken(h.From)
		contextKey := h.IdentityHome + "|" + h.TeamID + "|" + h.IdentityLabel
		context := safeToken(firstNonEmpty(h.IdentityLabel, h.TeamID, h.IdentityHome))
		switch h.Kind {
		case KindMail:
			add("mail|"+contextKey+"|"+from, renderMail, func(g *groupState) { g.from = from; g.context = context })
		case KindChat:
			add("chat|"+contextKey+"|"+from, renderChat, func(g *groupState) {
				g.from = from
				g.context = context
				if h.SenderWaiting {
					g.waiting = true
				}
			})
		case KindControl:
			// Never called an interrupt — in the code, the logs, or the text
			// typed into the terminal (§4, §6). Queued text is not an interrupt.
			add("control", renderControl, nil)
		case KindReconnect:
			add("reconnect", renderReconnect, nil)
		case KindWork:
			add("work", renderWork, func(g *groupState) { g.ids = appendID(g.ids, safeToken(h.TaskID)) })
		case KindClaim:
			add("claim", renderClaim, func(g *groupState) { g.ids = appendID(g.ids, safeToken(h.TaskID)) })
		case KindClaimRemoved:
			add("claim_removed", renderClaimRemoved, func(g *groupState) { g.ids = appendID(g.ids, safeToken(h.TaskID)) })
		case KindApp:
			key := "app|" + safeToken(h.AppID) + "|" + safeToken(h.AppEventType)
			add(key, renderApp, func(g *groupState) {
				g.from = strings.TrimPrefix(key, "app|")
			})
		default:
			add("other", renderOther, nil)
		}
	}

	out := make([]string, 0, len(groups))
	for _, g := range groups {
		out = append(out, g.line(&g.state))
	}
	return out
}

func renderMail(g *groupState) string {
	prefix := contextPrefix(g.context)
	if g.from == "" {
		return prefix + fmt.Sprintf("mail (%d unread)", g.count)
	}
	return prefix + fmt.Sprintf("mail from %s (%d unread)", g.from, g.count)
}

func renderChat(g *groupState) string {
	who := "chat"
	if g.from != "" {
		who = "chat from " + g.from
	}
	who = contextPrefix(g.context) + who
	if g.waiting {
		return who + " — sender waiting"
	}
	return fmt.Sprintf("%s (%d)", who, g.count)
}

func renderControl(g *groupState) string {
	if g.count == 1 {
		return "control signal"
	}
	return fmt.Sprintf("control signals (%d)", g.count)
}

func renderReconnect(_ *groupState) string {
	return "reconnected — earlier items may still be unread"
}

func renderWork(g *groupState) string {
	return withIDs(fmt.Sprintf("work available (%d)", g.count), g.ids)
}

func renderClaim(g *groupState) string {
	return withIDs(fmt.Sprintf("claim update (%d)", g.count), g.ids)
}

func renderClaimRemoved(g *groupState) string {
	return withIDs(fmt.Sprintf("claim removed (%d)", g.count), g.ids)
}

func renderApp(g *groupState) string {
	label := strings.Trim(strings.ReplaceAll(g.from, "|", "/"), "/")
	if label == "" {
		label = "app event"
	} else {
		label = "app event " + label
	}
	return fmt.Sprintf("%s (%d)", label, g.count)
}

func renderOther(g *groupState) string {
	return fmt.Sprintf("item (%d)", g.count)
}

func appendID(ids []string, id string) []string {
	if id == "" || len(ids) >= 3 {
		return ids
	}
	for _, existing := range ids {
		if existing == id {
			return ids
		}
	}
	return append(ids, id)
}

func withIDs(label string, ids []string) string {
	if len(ids) == 0 {
		return label
	}
	return label + ": " + strings.Join(ids, ", ")
}

// safeToken reduces a wire-supplied alias or id to characters that are safe to
// paste into a terminal, and bounds its length. Nothing here comes from a
// message body, but an alias is still remote input and this text is typed.
func safeToken(raw string) string {
	var b strings.Builder
	runes := 0
	for _, r := range strings.TrimSpace(raw) {
		if runes >= maxTokenRunes {
			break
		}
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.' || r == '_' || r == '-' || r == ':' || r == '@' || r == '/' || r == '+':
		default:
			continue
		}
		b.WriteRune(r)
		runes++
	}
	return b.String()
}
