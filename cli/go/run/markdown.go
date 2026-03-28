package run

import (
	"io"
	"os"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/charmbracelet/glamour"
	"github.com/charmbracelet/glamour/ansi"
	glamourstyles "github.com/charmbracelet/glamour/styles"
	"github.com/muesli/termenv"
	"golang.org/x/term"
)

const (
	displayLeftMargin      = 2
	defaultDisplayWidth    = 80
	minMarkdownRenderWidth = 24
	assistantBulletPrefix  = primaryBulletPrefix
)

var ansiEscapePattern = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func renderAssistantText(providerName string, text string, out io.Writer, startsAtLine bool) string {
	if strings.TrimSpace(text) == "" {
		return text
	}

	switch strings.ToLower(strings.TrimSpace(providerName)) {
	case "codex":
		rendered := renderCodexAssistantTextWithOptions(text, displayWidth(out), outputSupportsANSI(out), out)
		return prefixAssistantDisplayText(rendered, startsAtLine)
	case "claude":
		return prefixAssistantDisplayText(text, startsAtLine)
	default:
		return prefixAssistantDisplayText(text, startsAtLine)
	}
}

func renderCodexAssistantText(text string, width int) string {
	return prefixAssistantDisplayText(renderCodexAssistantTextWithOptions(text, width, false, nil), true)
}

func renderCodexAssistantTextWithOptions(text string, width int, supportsANSI bool, out io.Writer) string {
	if text == "" {
		return ""
	}

	wrapWidth := max(minMarkdownRenderWidth, width-displayLeftMargin)
	style := codexMarkdownStyle(supportsANSI, out)
	renderer, err := glamour.NewTermRenderer(
		glamour.WithStyles(style),
		glamour.WithWordWrap(wrapWidth),
		glamour.WithPreservedNewLines(),
	)
	if err != nil {
		return text
	}

	rendered, err := renderer.Render(text)
	if err != nil {
		return text
	}
	return stripANSIEscapeCodes(trimRenderedTrailingWhitespace(rendered))
}

func prefixAssistantDisplayText(text string, startsAtLine bool) string {
	if text == "" {
		return text
	}

	continuation := strings.Repeat(" ", utf8.RuneCountInString(assistantBulletPrefix))
	var out strings.Builder
	atLineStart := startsAtLine
	linePrefix := assistantBulletPrefix
	if !startsAtLine {
		linePrefix = ""
	}
	for _, r := range text {
		if atLineStart && r != '\n' && r != '\r' {
			if linePrefix != "" {
				out.WriteString(linePrefix)
			} else {
				out.WriteString(continuation)
			}
			linePrefix = continuation
			atLineStart = false
		}
		out.WriteRune(r)
		if r == '\n' || r == '\r' {
			atLineStart = true
			linePrefix = continuation
		}
	}
	return out.String()
}

func displayWidth(out io.Writer) int {
	file, ok := out.(*os.File)
	if !ok {
		return defaultDisplayWidth
	}
	width, _, err := term.GetSize(int(file.Fd()))
	if err != nil || width <= 0 {
		return defaultDisplayWidth
	}
	return width
}

func outputSupportsANSI(out io.Writer) bool {
	file, ok := out.(*os.File)
	if !ok {
		return false
	}
	return term.IsTerminal(int(file.Fd()))
}

func stripANSIEscapeCodes(s string) string {
	return ansiEscapePattern.ReplaceAllString(s, "")
}

func codexMarkdownStyle(supportsANSI bool, out io.Writer) ansi.StyleConfig {
	_ = supportsANSI
	_ = out
	style := glamourstyles.NoTTYStyleConfig

	// Let the loop own the left gutter and spacing; remove markdown heading markers.
	style.Document.BlockPrefix = ""
	style.Document.BlockSuffix = ""
	style.Document.Margin = uintPtr(0)
	style.H1.Prefix = ""
	style.H1.Suffix = ""
	style.H2.Prefix = ""
	style.H3.Prefix = ""
	style.H4.Prefix = ""
	style.H5.Prefix = ""
	style.H6.Prefix = ""
	return style
}

func hasDarkBackground(out io.Writer) bool {
	file, ok := out.(*os.File)
	if !ok {
		return true
	}
	return termenv.NewOutput(file).HasDarkBackground()
}

var trailingWhitespacePattern = regexp.MustCompile(`([ \t]+)((?:\x1b\[[0-9;]*m)*)$`)

func trimRenderedTrailingWhitespace(text string) string {
	if text == "" {
		return ""
	}
	hasTrailingNewline := strings.HasSuffix(text, "\n")
	lines := strings.Split(strings.TrimRight(text, "\n"), "\n")
	for i, line := range lines {
		lines[i] = trailingWhitespacePattern.ReplaceAllString(line, "$2")
	}
	result := strings.Join(lines, "\n")
	if hasTrailingNewline {
		result += "\n"
	}
	return result
}

func uintPtr(v uint) *uint {
	return &v
}
