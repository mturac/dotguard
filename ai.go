package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

func AnalyzeWithAI(cfg *Config, findings []Finding) []Finding {
	apiKey := os.Getenv(cfg.AI.KeyEnv)
	if apiKey == "" {
		fmt.Fprintf(os.Stderr, "%s AI analysis skipped: %s not set\n", colorYellow("!"), cfg.AI.KeyEnv)
		return findings
	}

	fmt.Printf("%s Analyzing %d finding(s) with AI...\n", colorBlue("⚡"), len(findings))

	switch cfg.AI.Provider {
	case "anthropic":
		return analyzeAnthropic(apiKey, cfg, findings)
	case "openai":
		return analyzeOpenAI(apiKey, cfg, findings)
	default:
		fmt.Fprintf(os.Stderr, "%s Unknown AI provider: %s\n", colorYellow("!"), cfg.AI.Provider)
		return findings
	}
}

func analyzeAnthropic(apiKey string, cfg *Config, findings []Finding) []Finding {
	prompt := buildPrompt(findings)

	body := map[string]interface{}{
		"model":      cfg.AI.Model,
		"max_tokens": cfg.AI.MaxTokens,
		"messages": []map[string]interface{}{
			{
				"role":    "user",
				"content": prompt,
			},
		},
	}

	data, _ := json.Marshal(body)
	req, err := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", bytes.NewReader(data))
	if err != nil {
		fmt.Fprintf(os.Stderr, "AI request error: %v\n", err)
		return findings
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "AI request failed: %v\n", err)
		return findings
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	var result struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}

	if err := json.Unmarshal(respBody, &result); err != nil || len(result.Content) == 0 {
		fmt.Fprintf(os.Stderr, "AI response parse error\n")
		return findings
	}

	return parseAIResponse(findings, result.Content[0].Text)
}

func analyzeOpenAI(apiKey string, cfg *Config, findings []Finding) []Finding {
	prompt := buildPrompt(findings)

	body := map[string]interface{}{
		"model":      cfg.AI.Model,
		"max_tokens": cfg.AI.MaxTokens,
		"messages": []map[string]interface{}{
			{
				"role":    "system",
				"content": "You are a security analyst. Analyze potential secret leaks and assess their risk. Respond with JSON.",
			},
			{
				"role":    "user",
				"content": prompt,
			},
		},
	}

	data, _ := json.Marshal(body)
	req, err := http.NewRequest("POST", "https://api.openai.com/v1/chat/completions", bytes.NewReader(data))
	if err != nil {
		fmt.Fprintf(os.Stderr, "AI request error: %v\n", err)
		return findings
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "AI request failed: %v\n", err)
		return findings
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	var result struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}

	if err := json.Unmarshal(respBody, &result); err != nil || len(result.Choices) == 0 {
		fmt.Fprintf(os.Stderr, "AI response parse error\n")
		return findings
	}

	return parseAIResponse(findings, result.Choices[0].Message.Content)
}

func buildPrompt(findings []Finding) string {
	var sb bytes.Buffer
	sb.WriteString("Analyze these potential secret leaks found in a codebase. For each finding, assess:\n")
	sb.WriteString("1. Is this likely a real secret or a false positive?\n")
	sb.WriteString("2. What type of credential is it?\n")
	sb.WriteString("3. What is the risk level?\n\n")
	sb.WriteString("Respond ONLY with a JSON array. Each element: {\"index\": N, \"analysis\": \"brief assessment\", \"is_real\": true/false}\n\n")
	sb.WriteString("Findings:\n")

	for i, f := range findings {
		sb.WriteString(fmt.Sprintf("[%d] Rule: %s | File: %s:%d | Redacted: %s\n", i, f.Rule, f.File, f.Line, f.Redacted))
	}

	return sb.String()
}

func parseAIResponse(findings []Finding, response string) []Finding {
	var analyses []struct {
		Index    int    `json:"index"`
		Analysis string `json:"analysis"`
		IsReal   bool   `json:"is_real"`
	}

	// Try to find JSON array in response
	start := -1
	end := -1
	for i, c := range response {
		if c == '[' && start == -1 {
			start = i
		}
		if c == ']' {
			end = i + 1
		}
	}

	if start >= 0 && end > start {
		json.Unmarshal([]byte(response[start:end]), &analyses)
	}

	for _, a := range analyses {
		if a.Index >= 0 && a.Index < len(findings) {
			prefix := colorGreen("✓ likely safe")
			if a.IsReal {
				prefix = colorRed("⚠ likely real")
			}
			findings[a.Index].AIAnalysis = fmt.Sprintf("%s — %s", prefix, a.Analysis)
		}
	}

	return findings
}
