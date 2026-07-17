package lsec

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var (
	canonicalExternalUsesPattern = regexp.MustCompile(`^ +uses: [A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}(?: # [^#\r\n]+)?$`)
	canonicalLocalUsesPattern    = regexp.MustCompile(`^ +uses: \./[A-Za-z0-9_./-]+(?: # [^#\r\n]+)?$`)
)

func TestReleaseWorkflowPinsGitHubActionsToCommitSHAs(t *testing.T) {
	root := repoRootForTest(t)
	workflow, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatal(err)
	}

	externalCount, invalid := validateWorkflowUses(workflow)
	if externalCount == 0 {
		t.Fatal("release workflow does not contain any external actions")
	}
	for _, target := range invalid {
		t.Errorf("release workflow uses a non-immutable action reference %q", target)
	}
}

func TestValidateWorkflowUses(t *testing.T) {
	const pinnedCheckout = "actions/checkout@93cb6efe18208431cddfb8368fd83d5badbf9bfd"
	shortSHA := "publisher/action@" + strings.Repeat("a", 39)
	tests := []struct {
		name            string
		workflow        string
		wantExternal    int
		wantInvalidUses string
	}{
		{
			name:            "mutable action from another publisher",
			workflow:        "steps:\n  - name: Checkout\n    uses: " + pinnedCheckout + "\n  - name: Other\n    uses: publisher/action@v1\n",
			wantExternal:    1,
			wantInvalidUses: "uses: publisher/action@v1",
		},
		{
			name:            "uppercase SHA",
			workflow:        "steps:\n    uses: publisher/action@93CB6EFE18208431CDDFB8368FD83D5BADBF9BFD\n",
			wantInvalidUses: "uses: publisher/action@93CB6EFE18208431CDDFB8368FD83D5BADBF9BFD",
		},
		{
			name:            "short SHA",
			workflow:        "steps:\n    uses: " + shortSHA + "\n",
			wantInvalidUses: "uses: " + shortSHA,
		},
		{
			name:         "local action",
			workflow:     "steps:\n    uses: ./.github/actions/release\n",
			wantExternal: 0,
		},
		{
			name:         "pinned external action",
			workflow:     "steps:\n    uses: " + pinnedCheckout + " # v5\n",
			wantExternal: 1,
		},
		{
			name:            "inline flow mapping",
			workflow:        "steps:\n  - {uses: publisher/action@v1}\n",
			wantInvalidUses: "- {uses: publisher/action@v1}",
		},
		{
			name:            "spaced key",
			workflow:        "steps:\n    uses : publisher/action@v1\n",
			wantInvalidUses: "uses : publisher/action@v1",
		},
		{
			name:            "quoted key",
			workflow:        "steps:\n    \"uses\": publisher/action@v1\n",
			wantInvalidUses: "\"uses\": publisher/action@v1",
		},
		{
			name:            "quoted flow mapping",
			workflow:        "steps:\n  - {\"uses\": \"publisher/action@v1\"}\n",
			wantInvalidUses: "- {\"uses\": \"publisher/action@v1\"}",
		},
		{
			name:            "quoted value",
			workflow:        "steps:\n    uses: \"" + pinnedCheckout + "\"\n",
			wantInvalidUses: "uses: \"" + pinnedCheckout + "\"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			externalCount, invalid := validateWorkflowUses([]byte(tt.workflow))
			if externalCount != tt.wantExternal {
				t.Fatalf("external action count = %d, want %d", externalCount, tt.wantExternal)
			}
			if got := strings.Join(invalid, ","); got != tt.wantInvalidUses {
				t.Fatalf("invalid action references = %q, want %q", got, tt.wantInvalidUses)
			}
		})
	}
}

func validateWorkflowUses(workflow []byte) (int, []string) {
	externalCount := 0
	var invalid []string
	for _, line := range strings.Split(string(workflow), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || !strings.Contains(line, "uses") {
			continue
		}
		if canonicalExternalUsesPattern.MatchString(line) {
			externalCount++
			continue
		}
		if !canonicalLocalUsesPattern.MatchString(line) {
			invalid = append(invalid, trimmed)
		}
	}
	return externalCount, invalid
}
