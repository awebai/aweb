package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAgentsSequenceCandidateClassicAndStar(t *testing.T) {
	tests := []struct {
		sequence string
		index    int
		want     string
	}{
		{agentsSequenceClassic, 0, "alice"},
		{agentsSequenceClassic, 1, "bob"},
		{agentsSequenceClassic, len(agentsClassicNames), "alice-01"},
		{agentsSequenceStar, 0, "sirius"},
		{agentsSequenceStar, 1, "vega"},
		{agentsSequenceStar, len(agentsStarNames), "sirius-01"},
	}
	for _, tt := range tests {
		got, err := agentsSequenceCandidate(tt.sequence, tt.index)
		if err != nil {
			t.Fatalf("agentsSequenceCandidate(%s, %d): %v", tt.sequence, tt.index, err)
		}
		if got != tt.want {
			t.Fatalf("agentsSequenceCandidate(%s, %d)=%q, want %q", tt.sequence, tt.index, got, tt.want)
		}
	}
}

func TestBuildAgentsNamingPlanDefaults(t *testing.T) {
	plan, err := buildAgentsNamingPlan(agentsNamingInput{
		AgentsDir: "agents",
		Namespace: "JuanReyero.COM.",
		User:      "juan",
		Agents: []agentsNamingAgentInput{
			{Responsibility: "coordinator", IdentityScope: agentsIdentityScopeGlobal, WorkBinding: agentsWorkRepoRoot},
			{Responsibility: "developer", IdentityScope: agentsIdentityScopeLocal, WorkBinding: agentsWorkGitWorktree},
			{Responsibility: "reviewer", IdentityScope: agentsIdentityScopeLocal, WorkBinding: agentsWorkGitWorktree},
		},
		ExistingAliases: map[string]bool{"alice": true},
	})
	if err != nil {
		t.Fatalf("buildAgentsNamingPlan: %v", err)
	}
	if len(plan.Agents) != 3 {
		t.Fatalf("agents=%d, want 3", len(plan.Agents))
	}
	byResponsibility := map[string]agentsNamingAgentPlan{}
	for _, agent := range plan.Agents {
		byResponsibility[agent.Responsibility] = agent
	}
	if got := byResponsibility["coordinator"].TeamAlias; got != "juan-alice" {
		t.Fatalf("coordinator alias=%q, want juan-alice", got)
	}
	if got := byResponsibility["coordinator"].GlobalName; got != "juan-coordinator" {
		t.Fatalf("coordinator global=%q, want juan-coordinator", got)
	}
	if got := byResponsibility["coordinator"].GlobalAddress; got != "juanreyero.com/juan-coordinator" {
		t.Fatalf("coordinator address=%q, want juanreyero.com/juan-coordinator", got)
	}
	if got := byResponsibility["developer"].TeamAlias; got != "bob" {
		t.Fatalf("developer alias=%q, want bob", got)
	}
	if got := byResponsibility["reviewer"].TeamAlias; got != "charlie" {
		t.Fatalf("reviewer alias=%q, want charlie", got)
	}
	if got := byResponsibility["developer"].WorktreePath; got != "agents/worktrees/developer" {
		t.Fatalf("developer worktree=%q, want agents/worktrees/developer", got)
	}
}

func TestBuildAgentsNamingPlanGlobalStarPatternSkipsUnavailable(t *testing.T) {
	plan, err := buildAgentsNamingPlan(agentsNamingInput{
		AgentsDir: "agents",
		User:      "juan",
		Policy: agentsNamingPolicy{
			GlobalNameSequence: agentsSequenceStar,
			GlobalNamePattern:  "{user}-{star-name}",
		},
		Agents: []agentsNamingAgentInput{
			{Responsibility: "coordinator", IdentityScope: agentsIdentityScopeGlobal},
			{Responsibility: "reviewer", IdentityScope: agentsIdentityScopeGlobal},
		},
		ExistingGlobalNames: map[string]bool{"juan-sirius": true},
	})
	if err != nil {
		t.Fatalf("buildAgentsNamingPlan: %v", err)
	}
	byResponsibility := map[string]agentsNamingAgentPlan{}
	for _, agent := range plan.Agents {
		byResponsibility[agent.Responsibility] = agent
	}
	if got := byResponsibility["coordinator"].GlobalName; got != "juan-vega" {
		t.Fatalf("coordinator global=%q, want juan-vega", got)
	}
	if got := byResponsibility["reviewer"].GlobalName; got != "juan-altair" {
		t.Fatalf("reviewer global=%q, want juan-altair", got)
	}
}

func TestBuildAgentsNamingPlanRejectsExpandedFieldTraversalBeforeMutation(t *testing.T) {
	root := t.TempDir()
	_, err := buildAgentsNamingPlan(agentsNamingInput{
		AgentsDir: "agents",
		User:      "../escape",
		Agents: []agentsNamingAgentInput{
			{Responsibility: "developer", IdentityScope: agentsIdentityScopeGlobal},
		},
	})
	if err == nil {
		t.Fatal("expected traversal user to fail")
	}
	if !strings.Contains(err.Error(), "path separators or path traversal") {
		t.Fatalf("error=%q, want path traversal message", err)
	}
	assertPathMissing(t, filepath.Join(root, "agents"))
	assertPathMissing(t, filepath.Join(root, "escape"))
}

func TestBuildAgentsNamingPlanRejectsAgentsDirTraversal(t *testing.T) {
	_, err := buildAgentsNamingPlan(agentsNamingInput{
		AgentsDir: "../agents",
		User:      "juan",
		Agents: []agentsNamingAgentInput{
			{Responsibility: "developer", IdentityScope: agentsIdentityScopeLocal},
		},
	})
	if err == nil {
		t.Fatal("expected agents-dir traversal to fail")
	}
	if !strings.Contains(err.Error(), "path separators or path traversal") {
		t.Fatalf("error=%q, want path traversal message", err)
	}
}

func TestBuildAgentsNamingPlanRejectsUnnormalizedExpandedField(t *testing.T) {
	_, err := buildAgentsNamingPlan(agentsNamingInput{
		AgentsDir: "agents",
		User:      "Juan",
		Agents: []agentsNamingAgentInput{
			{Responsibility: "coordinator", IdentityScope: agentsIdentityScopeGlobal},
		},
	})
	if err == nil {
		t.Fatal("expected uppercase user field to fail")
	}
	if !strings.Contains(err.Error(), "must be a slug") {
		t.Fatalf("error=%q, want slug message", err)
	}
}

func TestBuildAgentsNamingPlanRejectsResponsibilityTraversal(t *testing.T) {
	_, err := buildAgentsNamingPlan(agentsNamingInput{
		AgentsDir: "agents",
		User:      "juan",
		Agents: []agentsNamingAgentInput{
			{Responsibility: "../escape", IdentityScope: agentsIdentityScopeLocal},
		},
	})
	if err == nil {
		t.Fatal("expected responsibility traversal to fail")
	}
	if !strings.Contains(err.Error(), "path separators or path traversal") {
		t.Fatalf("error=%q, want path traversal message", err)
	}
}

func TestBuildAgentsNamingPlanRejectsInvalidPatternBeforeExpansion(t *testing.T) {
	_, err := buildAgentsNamingPlan(agentsNamingInput{
		AgentsDir: "agents",
		User:      "juan",
		Policy: agentsNamingPolicy{
			GlobalNamePattern: "{user}/escape",
		},
		Agents: []agentsNamingAgentInput{
			{Responsibility: "coordinator", IdentityScope: agentsIdentityScopeGlobal},
		},
	})
	if err == nil {
		t.Fatal("expected bad pattern to fail")
	}
	if !strings.Contains(err.Error(), "must not contain path separators") {
		t.Fatalf("error=%q, want pattern separator message", err)
	}
}

func TestBuildAgentsNamingPlanRejectsUnknownPatternField(t *testing.T) {
	_, err := buildAgentsNamingPlan(agentsNamingInput{
		AgentsDir: "agents",
		User:      "juan",
		Policy: agentsNamingPolicy{
			LocalAliasPattern: "{planet-name}",
		},
		Agents: []agentsNamingAgentInput{
			{Responsibility: "developer", IdentityScope: agentsIdentityScopeLocal},
		},
	})
	if err == nil {
		t.Fatal("expected unknown pattern field to fail")
	}
	if !strings.Contains(err.Error(), "unsupported field") {
		t.Fatalf("error=%q, want unsupported field", err)
	}
}

func TestBuildAgentsNamingPlanRejectsUnknownSequence(t *testing.T) {
	_, err := buildAgentsNamingPlan(agentsNamingInput{
		AgentsDir: "agents",
		User:      "juan",
		Policy: agentsNamingPolicy{
			LocalAliasSequence: "planet-name",
			LocalAliasPattern:  "{classic-name}",
		},
		Agents: []agentsNamingAgentInput{
			{Responsibility: "developer", IdentityScope: agentsIdentityScopeLocal},
		},
	})
	if err == nil {
		t.Fatal("expected unknown sequence to fail")
	}
	if !strings.Contains(err.Error(), "unsupported naming sequence") {
		t.Fatalf("error=%q, want unsupported naming sequence", err)
	}
}

func TestBuildAgentsNamingPlanRejectsUnavailableGlobalWithoutSequence(t *testing.T) {
	_, err := buildAgentsNamingPlan(agentsNamingInput{
		AgentsDir: "agents",
		User:      "juan",
		Agents: []agentsNamingAgentInput{
			{Responsibility: "coordinator", IdentityScope: agentsIdentityScopeGlobal},
		},
		ExistingGlobalNames: map[string]bool{"juan-coordinator": true},
	})
	if err == nil {
		t.Fatal("expected unavailable global name to fail")
	}
	if !strings.Contains(err.Error(), "global name") || !strings.Contains(err.Error(), "already in use") {
		t.Fatalf("error=%q, want global name already in use", err)
	}
}

func TestBuildAgentsNamingPlanRejectsDuplicateResponsibilities(t *testing.T) {
	_, err := buildAgentsNamingPlan(agentsNamingInput{
		AgentsDir: "agents",
		User:      "juan",
		Agents: []agentsNamingAgentInput{
			{Responsibility: "developer", IdentityScope: agentsIdentityScopeLocal},
			{Responsibility: "developer", IdentityScope: agentsIdentityScopeLocal},
		},
	})
	if err == nil {
		t.Fatal("expected duplicate home/responsibility to fail")
	}
	if !strings.Contains(err.Error(), "already planned or exists") {
		t.Fatalf("error=%q, want duplicate home message", err)
	}
}

func TestBuildAgentsNamingPlanRejectsWorktreeCollision(t *testing.T) {
	_, err := buildAgentsNamingPlan(agentsNamingInput{
		AgentsDir: "agents",
		User:      "juan",
		Agents: []agentsNamingAgentInput{
			{Responsibility: "developer", IdentityScope: agentsIdentityScopeLocal, WorkBinding: agentsWorkGitWorktree},
		},
		ExistingWorktrees: map[string]bool{"developer": true},
	})
	if err == nil {
		t.Fatal("expected worktree collision to fail")
	}
	if !strings.Contains(err.Error(), "worktree name") || !strings.Contains(err.Error(), "already in use") {
		t.Fatalf("error=%q, want worktree already in use", err)
	}
}

func assertPathMissing(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); err == nil {
		t.Fatalf("path %s exists after failed plan", path)
	} else if !os.IsNotExist(err) {
		t.Fatalf("stat %s: %v", path, err)
	}
}
