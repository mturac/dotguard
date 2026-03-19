package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// --- Colors ---

var useColor = os.Getenv("NO_COLOR") == "" && os.Getenv("TERM") != "dumb"

func colorRed(s string) string {
	if !useColor {
		return s
	}
	return "\033[31m" + s + "\033[0m"
}

func colorGreen(s string) string {
	if !useColor {
		return s
	}
	return "\033[32m" + s + "\033[0m"
}

func colorYellow(s string) string {
	if !useColor {
		return s
	}
	return "\033[33m" + s + "\033[0m"
}

func colorBlue(s string) string {
	if !useColor {
		return s
	}
	return "\033[34m" + s + "\033[0m"
}

func colorBold(s string) string {
	if !useColor {
		return s
	}
	return "\033[1m" + s + "\033[0m"
}

func colorDim(s string) string {
	if !useColor {
		return s
	}
	return "\033[2m" + s + "\033[0m"
}

func severityColor(s Severity) string {
	switch s {
	case SeverityCritical:
		return "\033[31;1m" // bold red
	case SeverityHigh:
		return "\033[31m" // red
	case SeverityMedium:
		return "\033[33m" // yellow
	default:
		return "\033[36m" // cyan
	}
}

func colorSeverity(s Severity) string {
	if !useColor {
		return s.String()
	}
	return severityColor(s) + s.String() + "\033[0m"
}

// --- Output ---

func PrintFindings(findings []Finding, verbose bool) {
	if len(findings) == 0 {
		return
	}

	fmt.Println()
	fmt.Printf("%s\n", colorBold("dotguard scan results"))
	fmt.Println(strings.Repeat("─", 60))

	for i, f := range findings {
		fmt.Printf("\n  %s  %s\n", colorSeverity(f.Severity), colorBold(f.Rule))
		fmt.Printf("  %s %s:%d\n", colorDim("file:"), f.File, f.Line)
		fmt.Printf("  %s %s\n", colorDim("match:"), f.Redacted)

		if verbose {
			fmt.Printf("  %s %s\n", colorDim("hash:"), f.Hash)
		}

		if f.AIAnalysis != "" {
			fmt.Printf("  %s %s\n", colorDim("ai:"), f.AIAnalysis)
		}

		if i < len(findings)-1 {
			fmt.Println()
		}
	}

	fmt.Println()
	fmt.Println(strings.Repeat("─", 60))

	// Summary by severity
	counts := map[Severity]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}

	var parts []string
	for _, sev := range []Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow} {
		if c, ok := counts[sev]; ok {
			parts = append(parts, fmt.Sprintf("%s: %d", colorSeverity(sev), c))
		}
	}

	fmt.Printf("  %s\n", strings.Join(parts, "  "))
}

func PrintFindingsJSON(findings []Finding) {
	type jsonFinding struct {
		File       string `json:"file"`
		Line       int    `json:"line"`
		Rule       string `json:"rule"`
		Severity   string `json:"severity"`
		Redacted   string `json:"redacted"`
		Hash       string `json:"hash"`
		AIAnalysis string `json:"ai_analysis,omitempty"`
	}

	output := struct {
		Version  string        `json:"version"`
		Total    int           `json:"total"`
		Findings []jsonFinding `json:"findings"`
	}{
		Version: Version,
		Total:   len(findings),
	}

	for _, f := range findings {
		output.Findings = append(output.Findings, jsonFinding{
			File:       f.File,
			Line:       f.Line,
			Rule:       f.Rule,
			Severity:   f.Severity.String(),
			Redacted:   f.Redacted,
			Hash:       f.Hash,
			AIAnalysis: f.AIAnalysis,
		})
	}

	data, _ := json.MarshalIndent(output, "", "  ")
	fmt.Println(string(data))
}
