package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const hookScript = `#!/bin/sh
# dotguard pre-commit hook — https://github.com/YOUR_USER/dotguard
# Scans staged files for secrets before allowing commit

echo "🔒 dotguard: scanning staged files..."

dotguard scan -staged
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    echo ""
    echo "❌ Commit blocked — secrets detected!"
    echo "   Fix the issues above, then try again."
    echo ""
    echo "   To allowlist a false positive, add its hash to .dotguard.json"
    echo "   To skip this check: git commit --no-verify"
    exit 1
fi

echo "✅ dotguard: all clear"
exit 0
`

const hookMarker = "# dotguard pre-commit hook"

func findGitDir() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}

	for {
		gitDir := filepath.Join(dir, ".git")
		if info, err := os.Stat(gitDir); err == nil && info.IsDir() {
			return gitDir, nil
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("not a git repository (or any parent up to root)")
		}
		dir = parent
	}
}

func InstallHook() error {
	gitDir, err := findGitDir()
	if err != nil {
		return err
	}

	hooksDir := filepath.Join(gitDir, "hooks")
	if err := os.MkdirAll(hooksDir, 0755); err != nil {
		return fmt.Errorf("failed to create hooks directory: %w", err)
	}

	hookPath := filepath.Join(hooksDir, "pre-commit")

	if existing, err := os.ReadFile(hookPath); err == nil {
		content := string(existing)
		if strings.Contains(content, hookMarker) {
			return fmt.Errorf("dotguard hook already installed")
		}

		// Append to existing hook
		combined := content + "\n\n" + hookScript
		if err := os.WriteFile(hookPath, []byte(combined), 0755); err != nil {
			return fmt.Errorf("failed to update existing hook: %w", err)
		}
		fmt.Println("  Appended dotguard to existing pre-commit hook")
		return nil
	}

	if err := os.WriteFile(hookPath, []byte(hookScript), 0755); err != nil {
		return fmt.Errorf("failed to write hook: %w", err)
	}

	return nil
}

func UninstallHook() error {
	gitDir, err := findGitDir()
	if err != nil {
		return err
	}

	hookPath := filepath.Join(gitDir, "hooks", "pre-commit")

	existing, err := os.ReadFile(hookPath)
	if err != nil {
		return fmt.Errorf("no pre-commit hook found")
	}

	content := string(existing)
	if !strings.Contains(content, hookMarker) {
		return fmt.Errorf("dotguard hook not found in pre-commit")
	}

	// If the hook is only dotguard, remove the file
	lines := strings.Split(content, "\n")
	var otherLines []string
	inDotguard := false

	for _, line := range lines {
		if strings.Contains(line, hookMarker) {
			inDotguard = true
			continue
		}
		if inDotguard && line == "" {
			continue
		}
		if inDotguard && !strings.HasPrefix(line, "#") && !strings.HasPrefix(line, "dotguard") && !strings.HasPrefix(line, "EXIT_CODE") && !strings.HasPrefix(line, "if ") && !strings.HasPrefix(line, "    ") && !strings.HasPrefix(line, "echo") && !strings.HasPrefix(line, "exit") && !strings.HasPrefix(line, "fi") {
			inDotguard = false
			otherLines = append(otherLines, line)
			continue
		}
		if !inDotguard {
			otherLines = append(otherLines, line)
		}
	}

	remaining := strings.TrimSpace(strings.Join(otherLines, "\n"))

	if remaining == "" || remaining == "#!/bin/sh" {
		return os.Remove(hookPath)
	}

	return os.WriteFile(hookPath, []byte(remaining+"\n"), 0755)
}
