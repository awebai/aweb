package blueprint

import (
	"fmt"
	"strings"
)

// ValidateHomePath is the profile boundary for materialization, refresh and
// pruning, per docs/blueprint-materialization-contract.md, “5. Materialization semantics,” lines 200–214.
// A managed-set entry records an effect; it never grants new paths.
func ValidateHomePath(rel string) error {
	refuse := func() error {
		return fmt.Errorf("Library profile path %q is outside the profile layout or is not normalized (traversal is forbidden). Use a profile destination: AGENTS.md, CLAUDE.md, skills/, artifacts/, .aw/profile/, or a .claude/skills/ projection", rel)
	}
	if err := validateNormalizedPOSIXRelativePath("profile destination", rel); err != nil {
		return refuse()
	}
	parts := strings.Split(rel, "/")
	switch {
	case rel == "AGENTS.md" || rel == "CLAUDE.md":
		return nil
	case strings.HasPrefix(rel, ".claude/skills/") && (len(parts) == 3 || len(parts) == 4 && parts[3] == "SKILL.md"):
		if strings.HasPrefix(parts[2], ".") {
			return refuse()
		}
		return nil
	case strings.HasPrefix(rel, ".aw/profile/"):
		parts = parts[2:]
	case (parts[0] == "skills" || parts[0] == "artifacts") && len(parts) > 1:
		parts = parts[1:]
	default:
		return refuse()
	}
	for _, part := range parts {
		switch strings.ToLower(part) {
		case ".aw", ".git", ".hg", ".svn", ".claude", ".codex", ".agents":
			return refuse()
		}
	}
	return nil
}

func validateHomeOp(op materializeWriteOp) error {
	if err := ValidateHomePath(op.Rel); err != nil {
		return err
	}
	if op.Kind == opSymlink {
		want := "AGENTS.md"
		if strings.HasPrefix(op.Rel, ".claude/skills/") {
			if len(strings.Split(op.Rel, "/")) != 3 {
				return fmt.Errorf("Library skill link %q uses a file projection. Use a directory projection at .claude/skills/<name>", op.Rel)
			}
			want = "../../skills/" + strings.TrimPrefix(op.Rel, ".claude/skills/")
		} else if op.Rel != "CLAUDE.md" {
			return fmt.Errorf("Library symlink %q is not a runtime projection. Use CLAUDE.md -> AGENTS.md or .claude/skills/<name> -> ../../skills/<name>", op.Rel)
		}
		if op.LinkTarget != want {
			return fmt.Errorf("Library symlink %q has target %q. Use the runtime projection target %q", op.Rel, op.LinkTarget, want)
		}
	} else if op.Rel == "CLAUDE.md" || strings.HasPrefix(op.Rel, ".claude/skills/") {
		return fmt.Errorf("Library path %q must be a symlink. Use the documented runtime projection", op.Rel)
	}
	return nil
}
