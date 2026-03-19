package main

import (
	"bufio"
	"crypto/sha256"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"
)

type Severity int

const (
	SeverityLow Severity = iota
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

func (s Severity) String() string {
	switch s {
	case SeverityLow:
		return "LOW"
	case SeverityMedium:
		return "MEDIUM"
	case SeverityHigh:
		return "HIGH"
	case SeverityCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

type Finding struct {
	File       string   `json:"file"`
	Line       int      `json:"line"`
	Content    string   `json:"content"`
	Redacted   string   `json:"redacted"`
	Rule       string   `json:"rule"`
	Severity   Severity `json:"severity"`
	Hash       string   `json:"hash"`
	AIAnalysis string   `json:"ai_analysis,omitempty"`
}

type Scanner struct {
	config  *Config
	rules   []Rule
	verbose bool
}

type Rule struct {
	ID       string
	Name     string
	Pattern  *regexp.Regexp
	Severity Severity
}

func NewScanner(cfg *Config, verbose bool) *Scanner {
	return &Scanner{
		config:  cfg,
		rules:   CompileRules(),
		verbose: verbose,
	}
}

func (s *Scanner) ScanPath(root string) []Finding {
	var findings []Finding

	filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		if info.IsDir() {
			if s.isExcludedDir(path) {
				return filepath.SkipDir
			}
			return nil
		}

		if s.isExcludedFile(path) || isBinaryFile(path) || info.Size() > 1<<20 {
			return nil
		}

		fileFindings := s.scanFile(path)
		findings = append(findings, fileFindings...)
		return nil
	})

	return s.filterAllowlisted(findings)
}

func (s *Scanner) ScanFiles(files []string) []Finding {
	var findings []Finding

	for _, file := range files {
		if s.isExcludedFile(file) || isBinaryFile(file) {
			continue
		}
		fileFindings := s.scanFile(file)
		findings = append(findings, fileFindings...)
	}

	return s.filterAllowlisted(findings)
}

func (s *Scanner) scanFile(path string) []Finding {
	var findings []Finding

	f, err := os.Open(path)
	if err != nil {
		return findings
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		for _, rule := range s.rules {
			matches := rule.Pattern.FindAllString(line, -1)
			for _, match := range matches {
				hash := hashContent(fmt.Sprintf("%s:%d:%s", path, lineNum, match))
				findings = append(findings, Finding{
					File:     path,
					Line:     lineNum,
					Content:  match,
					Redacted: redact(match),
					Rule:     rule.Name,
					Severity: rule.Severity,
					Hash:     hash,
				})
			}
		}

		if isEnvLine(line) {
			_, value := parseEnvLine(line)
			if value != "" && shannonEntropy(value) > 4.0 && len(value) >= 16 {
				hash := hashContent(fmt.Sprintf("%s:%d:entropy", path, lineNum))
				findings = append(findings, Finding{
					File:     path,
					Line:     lineNum,
					Content:  value,
					Redacted: redact(value),
					Rule:     "High-entropy string",
					Severity: SeverityMedium,
					Hash:     hash,
				})
			}
		}
	}

	if s.verbose && lineNum > 0 {
		fmt.Printf("  scanned %s (%d lines)\n", path, lineNum)
	}

	return findings
}

func (s *Scanner) isExcludedDir(path string) bool {
	base := filepath.Base(path)

	defaults := []string{".git", "node_modules", "vendor", "__pycache__", ".venv", "venv", "dist", "build", ".next", "target"}
	for _, d := range defaults {
		if base == d {
			return true
		}
	}

	for _, exc := range s.config.Scan.ExcludePaths {
		matched, _ := filepath.Match(exc, path)
		if matched || strings.HasPrefix(path, strings.TrimSuffix(exc, "/")) {
			return true
		}
	}

	return false
}

func (s *Scanner) isExcludedFile(path string) bool {
	base := filepath.Base(path)

	defaults := []string{"*.min.js", "*.min.css", "*.map", "*.lock", "go.sum", "package-lock.json", "yarn.lock", "*.wasm", "*.png", "*.jpg", "*.jpeg", "*.gif", "*.svg", "*.ico", "*.woff", "*.woff2", "*.ttf", "*.eot", "*.mp4", "*.webm", "*.pdf", "*.zip", "*.tar.gz", "*.exe", "*.dll", "*.so", "*.dylib"}
	for _, pattern := range defaults {
		if matched, _ := filepath.Match(pattern, base); matched {
			return true
		}
	}

	for _, exc := range s.config.Scan.ExcludeFiles {
		if matched, _ := filepath.Match(exc, base); matched {
			return true
		}
		if matched, _ := filepath.Match(exc, path); matched {
			return true
		}
	}

	return false
}

func (s *Scanner) filterAllowlisted(findings []Finding) []Finding {
	if len(s.config.Allowlist) == 0 {
		return findings
	}

	var filtered []Finding
	for _, f := range findings {
		allowed := false
		for _, entry := range s.config.Allowlist {
			if entry.Hash != "" && entry.Hash == f.Hash {
				allowed = true
				break
			}
			if entry.Pattern != "" {
				if matched, _ := filepath.Match(entry.Pattern, f.Content); matched {
					allowed = true
					break
				}
				if re, err := regexp.Compile(entry.Pattern); err == nil && re.MatchString(f.Content) {
					allowed = true
					break
				}
			}
			if entry.File != "" {
				if matched, _ := filepath.Match(entry.File, f.File); matched {
					allowed = true
					break
				}
			}
		}
		if !allowed {
			filtered = append(filtered, f)
		}
	}

	return filtered
}

// --- Pattern Rules ---

func CompileRules() []Rule {
	defs := []struct {
		id       string
		name     string
		pattern  string
		severity Severity
	}{
		// AWS
		{"aws-key", "AWS Access Key", `AKIA[0-9A-Z]{16}`, SeverityCritical},
		{"aws-secret", "AWS Secret Key", `(?i)aws_secret_access_key\s*[=:]\s*[A-Za-z0-9/+=]{40}`, SeverityCritical},

		// GCP
		{"gcp-key", "GCP API Key", `AIza[0-9A-Za-z\-_]{35}`, SeverityHigh},
		{"gcp-sa", "GCP Service Account", `"type"\s*:\s*"service_account"`, SeverityHigh},

		// GitHub
		{"gh-pat", "GitHub Personal Access Token", `ghp_[0-9a-zA-Z]{36}`, SeverityCritical},
		{"gh-oauth", "GitHub OAuth Token", `gho_[0-9a-zA-Z]{36}`, SeverityHigh},
		{"gh-app", "GitHub App Token", `(?:ghu|ghs)_[0-9a-zA-Z]{36}`, SeverityHigh},
		{"gh-fine", "GitHub Fine-Grained Token", `github_pat_[0-9a-zA-Z_]{82}`, SeverityCritical},

		// GitLab
		{"gl-pat", "GitLab Personal Access Token", `glpat-[0-9a-zA-Z\-_]{20}`, SeverityCritical},

		// Slack
		{"slack-token", "Slack Token", `xox[baprs]-[0-9]{10,13}-[0-9a-zA-Z\-]{20,}`, SeverityCritical},
		{"slack-webhook", "Slack Webhook", `https://hooks\.slack\.com/services/T[0-9A-Z]{8,}/B[0-9A-Z]{8,}/[a-zA-Z0-9]{20,}`, SeverityHigh},

		// Stripe
		{"stripe-live", "Stripe Live Key", `sk_live_[0-9a-zA-Z]{24,}`, SeverityCritical},
		{"stripe-pub", "Stripe Publishable Key", `pk_live_[0-9a-zA-Z]{24,}`, SeverityMedium},

		// Twilio
		{"twilio", "Twilio API Key", `SK[0-9a-fA-F]{32}`, SeverityHigh},

		// SendGrid
		{"sendgrid", "SendGrid API Key", `SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}`, SeverityHigh},

		// Heroku
		{"heroku", "Heroku API Key", `(?i)heroku.*[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`, SeverityHigh},

		// Database URLs
		{"db-url", "Database Connection String", `(?i)(?:mysql|postgres|postgresql|mongodb|redis|amqp)://[^\s'"]{10,}`, SeverityCritical},

		// Private Keys
		{"private-key", "Private Key", `-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`, SeverityCritical},

		// JWT
		{"jwt", "JSON Web Token", `eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_.+/=]+`, SeverityHigh},

		// Generic API key patterns
		{"generic-api", "Generic API Key", `(?i)(?:api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*['"]?[A-Za-z0-9\-_]{20,}['"]?`, SeverityMedium},
		{"generic-secret", "Generic Secret", `(?i)(?:secret|password|passwd|pwd|token|auth)\s*[=:]\s*['"]?[A-Za-z0-9\-_!@#$%^&*]{8,}['"]?`, SeverityMedium},

		// Anthropic
		{"anthropic-key", "Anthropic API Key", `sk-ant-[0-9a-zA-Z\-_]{80,}`, SeverityCritical},

		// OpenAI
		{"openai-key", "OpenAI API Key", `sk-[0-9a-zA-Z]{20,}`, SeverityHigh},

		// Discord
		{"discord-webhook", "Discord Webhook", `https://discord(?:app)?\.com/api/webhooks/[0-9]{17,20}/[A-Za-z0-9_\-]{60,}`, SeverityHigh},
		{"discord-token", "Discord Bot Token", `[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27,}`, SeverityHigh},

		// NPM
		{"npm-token", "NPM Access Token", `npm_[A-Za-z0-9]{36}`, SeverityHigh},

		// PyPI
		{"pypi-token", "PyPI API Token", `pypi-AgE[A-Za-z0-9\-_]{50,}`, SeverityHigh},

		// Mailgun
		{"mailgun", "Mailgun API Key", `key-[0-9a-zA-Z]{32}`, SeverityHigh},

		// .env file patterns
		{"env-password", "Password in env file", `(?i)(?:DB_PASSWORD|DATABASE_PASSWORD|MYSQL_PASSWORD|POSTGRES_PASSWORD|REDIS_PASSWORD)\s*=\s*\S+`, SeverityHigh},
	}

	rules := make([]Rule, 0, len(defs))
	for _, d := range defs {
		re, err := regexp.Compile(d.pattern)
		if err != nil {
			continue
		}
		rules = append(rules, Rule{
			ID:       d.id,
			Name:     d.name,
			Pattern:  re,
			Severity: d.severity,
		})
	}

	return rules
}

// --- Entropy ---

func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	freq := make(map[rune]float64)
	length := float64(utf8.RuneCountInString(s))

	for _, c := range s {
		freq[c]++
	}

	var entropy float64
	for _, count := range freq {
		p := count / length
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}

func isEnvLine(line string) bool {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return false
	}
	return strings.Contains(trimmed, "=") && !strings.HasPrefix(trimmed, "//") && !strings.HasPrefix(trimmed, "/*")
}

func parseEnvLine(line string) (string, string) {
	parts := strings.SplitN(strings.TrimSpace(line), "=", 2)
	if len(parts) != 2 {
		return "", ""
	}
	key := strings.TrimSpace(parts[0])
	value := strings.TrimSpace(parts[1])
	value = strings.Trim(value, `'"`)
	return key, value
}

// --- Helpers ---

func isBinaryFile(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return true
	}
	defer f.Close()

	buf := make([]byte, 512)
	n, err := f.Read(buf)
	if err != nil || n == 0 {
		return true
	}

	for _, b := range buf[:n] {
		if b == 0 {
			return true
		}
	}

	return false
}

func redact(s string) string {
	if len(s) <= 8 {
		return "****"
	}
	return s[:4] + strings.Repeat("*", len(s)-8) + s[len(s)-4:]
}

func hashContent(s string) string {
	h := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", h)[:16]
}

func GitStagedFiles() ([]string, error) {
	cmd := exec.Command("git", "diff", "--cached", "--name-only", "--diff-filter=ACMR")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git command failed: %w", err)
	}

	var files []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line != "" {
			files = append(files, line)
		}
	}

	return files, nil
}
