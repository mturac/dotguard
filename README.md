# 🔒 dotguard

**Catch secrets before they leak.** Zero dependencies. Single binary. Instant setup.

[![Go](https://img.shields.io/badge/Go-1.22+-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/YOUR_USER/dotguard)](https://github.com/YOUR_USER/dotguard/releases)

dotguard is a lightweight secret scanner that prevents API keys, tokens, passwords, and other credentials from being committed to your git repositories. It runs as a pre-commit hook, a CI step, or a standalone CLI tool.

## Why dotguard?

| | dotguard | gitleaks | trufflehog |
|---|---|---|---|
| **Binary size** | ~5 MB | ~15 MB | ~50 MB |
| **Dependencies** | 0 | 0 | Many |
| **Config** | Optional JSON | TOML | YAML |
| **AI analysis** | ✅ Optional | ❌ | ❌ |
| **Hook install** | 1 command | Manual | Manual |
| **CI mode** | Built-in | Separate | Separate |

## Install

```bash
# Go install (recommended)
go install github.com/YOUR_USER/dotguard@latest

# Or download binary
curl -sSL https://raw.githubusercontent.com/YOUR_USER/dotguard/main/scripts/install.sh | bash

# Or build from source
git clone https://github.com/YOUR_USER/dotguard.git
cd dotguard && go build -o dotguard .
```

## Quick Start

```bash
# 1. Initialize config (optional)
dotguard init

# 2. Install pre-commit hook
dotguard hook install

# 3. That's it! Try committing a file with a secret:
echo "AWS_SECRET=AKIAIOSFODNN7EXAMPLE" > test.env
git add test.env
git commit -m "test"
# ❌ Commit blocked — secrets detected!
```

## Usage

### Scan files

```bash
# Scan current directory
dotguard scan

# Scan specific path
dotguard scan ./src

# Scan only staged files
dotguard scan -staged

# Verbose output
dotguard scan -verbose

# With AI-powered analysis
dotguard scan -ai
```

### Pre-commit hook

```bash
# Install hook
dotguard hook install

# Remove hook
dotguard hook uninstall
```

When installed, dotguard automatically scans staged files before every commit. If secrets are found, the commit is blocked with a detailed report.

To bypass in emergencies: `git commit --no-verify`

### CI/CD mode

```bash
# Basic CI scan (exits with code 1 if secrets found)
dotguard ci

# JSON output for parsing
dotguard ci -json

# With notifications
dotguard ci -notify

# Full CI with AI analysis + notifications
dotguard ci -ai -notify
```

### GitHub Actions

Add to your workflow:

```yaml
- name: Install dotguard
  run: go install github.com/YOUR_USER/dotguard@latest

- name: Secret scan
  run: dotguard ci -json
```

See [`.github/workflows/dotguard.yml`](.github/workflows/dotguard.yml) for a complete example.

## What it detects

dotguard scans for **30+ secret patterns** including:

- **AWS** — Access keys, secret keys
- **GCP** — API keys, service account files
- **GitHub** — Personal access tokens, OAuth tokens, fine-grained tokens
- **GitLab** — Personal access tokens
- **Slack** — Bot tokens, webhook URLs
- **Stripe** — Live/test API keys
- **Anthropic** — API keys
- **OpenAI** — API keys
- **Discord** — Bot tokens, webhook URLs
- **Database URLs** — PostgreSQL, MySQL, MongoDB, Redis connection strings
- **Private keys** — RSA, EC, DSA, OpenSSH
- **JWTs** — JSON Web Tokens
- **Generic patterns** — `api_key=`, `secret=`, `password=`, `token=`
- **High-entropy strings** — Shannon entropy detection for unknown secret formats

## Configuration

Run `dotguard init` to create a `.dotguard.json` config file:

```json
{
  "version": 1,
  "scan": {
    "paths": ["."],
    "exclude_paths": ["vendor/", "node_modules/"],
    "exclude_files": ["*.min.js", "*.lock"],
    "max_file_size_kb": 1024
  },
  "allowlist": [
    {
      "pattern": "EXAMPLE_.*",
      "reason": "Placeholder values"
    },
    {
      "hash": "a1b2c3d4e5f6g7h8",
      "reason": "Known false positive"
    },
    {
      "file": "*.test.*",
      "reason": "Test fixtures"
    }
  ],
  "notify": {
    "slack_webhook": "https://hooks.slack.com/services/...",
    "discord_webhook": "https://discord.com/api/webhooks/..."
  },
  "ai": {
    "provider": "anthropic",
    "api_key_env": "ANTHROPIC_API_KEY",
    "model": "claude-sonnet-4-20250514",
    "max_tokens": 512
  }
}
```

### Allowlisting false positives

When dotguard reports a false positive, you can allowlist it by:

1. **Hash** — Copy the hash from verbose output (`-verbose` flag) and add it to `allowlist`
2. **Pattern** — Match content with a regex or glob pattern
3. **File** — Exclude entire files by glob pattern

## AI Analysis (Optional)

dotguard can optionally use AI to analyze findings and distinguish real secrets from false positives.

```bash
# Set your API key
export ANTHROPIC_API_KEY="sk-ant-..."

# Scan with AI
dotguard scan -ai
```

Supported providers:
- **Anthropic** (default) — Claude Sonnet
- **OpenAI** — GPT-4o

The AI flag is completely optional. Without it, dotguard works entirely offline using regex patterns and entropy analysis.

## Webhook Notifications

Configure Slack and/or Discord webhooks in `.dotguard.json` to get notified when secrets are found in CI:

```bash
dotguard ci -notify
```

Notifications include file locations, severity levels, and redacted secret previews.

## Environment Variables

| Variable | Description |
|---|---|
| `NO_COLOR` | Disable colored output |
| `ANTHROPIC_API_KEY` | API key for Anthropic AI analysis |
| `OPENAI_API_KEY` | API key for OpenAI analysis |

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | No secrets found |
| `1` | Secrets detected or error |

## Contributing

Contributions welcome! Feel free to open issues and PRs.

```bash
git clone https://github.com/YOUR_USER/dotguard.git
cd dotguard
go build -o dotguard .
./dotguard scan
```

## License

MIT — see [LICENSE](LICENSE)
