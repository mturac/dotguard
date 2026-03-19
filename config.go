package main

import (
	"encoding/json"
	"os"
)

type Config struct {
	Version   int              `json:"version"`
	Scan      ScanConfig       `json:"scan"`
	Allowlist []AllowlistEntry `json:"allowlist"`
	Notify    NotifyConfig     `json:"notify"`
	AI        AIConfig         `json:"ai"`
}

type ScanConfig struct {
	Paths        []string `json:"paths"`
	ExcludePaths []string `json:"exclude_paths"`
	ExcludeFiles []string `json:"exclude_files"`
	MaxFileSize  int64    `json:"max_file_size_kb"`
}

type AllowlistEntry struct {
	Hash    string `json:"hash,omitempty"`
	Pattern string `json:"pattern,omitempty"`
	File    string `json:"file,omitempty"`
	Reason  string `json:"reason,omitempty"`
}

type NotifyConfig struct {
	SlackWebhook   string `json:"slack_webhook"`
	DiscordWebhook string `json:"discord_webhook"`
}

type AIConfig struct {
	Provider  string `json:"provider"`
	KeyEnv    string `json:"api_key_env"`
	Model     string `json:"model"`
	MaxTokens int    `json:"max_tokens"`
}

var DefaultConfig = `{
  "version": 1,
  "scan": {
    "paths": ["."],
    "exclude_paths": [
      "vendor/",
      "node_modules/",
      ".git/",
      "dist/",
      "build/"
    ],
    "exclude_files": [
      "*.min.js",
      "*.min.css",
      "*.lock",
      "go.sum"
    ],
    "max_file_size_kb": 1024
  },
  "allowlist": [
    {
      "pattern": "EXAMPLE_.*",
      "reason": "Placeholder values"
    }
  ],
  "notify": {
    "slack_webhook": "",
    "discord_webhook": ""
  },
  "ai": {
    "provider": "anthropic",
    "api_key_env": "ANTHROPIC_API_KEY",
    "model": "claude-sonnet-4-20250514",
    "max_tokens": 512
  }
}
`

func LoadConfig(path string) *Config {
	cfg := &Config{
		Version: 1,
		Scan: ScanConfig{
			Paths:       []string{"."},
			MaxFileSize: 1024,
		},
		AI: AIConfig{
			Provider:  "anthropic",
			KeyEnv:    "ANTHROPIC_API_KEY",
			Model:     "claude-sonnet-4-20250514",
			MaxTokens: 512,
		},
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return cfg
	}

	json.Unmarshal(data, cfg)
	return cfg
}
