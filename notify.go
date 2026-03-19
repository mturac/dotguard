package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"
)

func NotifyWebhooks(cfg *Config, findings []Finding) {
	if cfg.Notify.SlackWebhook != "" {
		if err := notifySlack(cfg.Notify.SlackWebhook, findings); err != nil {
			fmt.Fprintf(os.Stderr, "Slack notification failed: %v\n", err)
		} else {
			fmt.Printf("%s Slack notification sent\n", colorGreen("✓"))
		}
	}

	if cfg.Notify.DiscordWebhook != "" {
		if err := notifyDiscord(cfg.Notify.DiscordWebhook, findings); err != nil {
			fmt.Fprintf(os.Stderr, "Discord notification failed: %v\n", err)
		} else {
			fmt.Printf("%s Discord notification sent\n", colorGreen("✓"))
		}
	}
}

func notifySlack(webhook string, findings []Finding) error {
	hostname, _ := os.Hostname()
	cwd, _ := os.Getwd()

	var blocks []map[string]interface{}

	blocks = append(blocks, map[string]interface{}{
		"type": "header",
		"text": map[string]interface{}{
			"type": "plain_text",
			"text": fmt.Sprintf("🔒 dotguard: %d secret(s) detected", len(findings)),
		},
	})

	blocks = append(blocks, map[string]interface{}{
		"type": "section",
		"text": map[string]interface{}{
			"type": "mrkdwn",
			"text": fmt.Sprintf("*Host:* %s\n*Directory:* `%s`\n*Time:* %s", hostname, cwd, time.Now().Format(time.RFC3339)),
		},
	})

	blocks = append(blocks, map[string]interface{}{
		"type": "divider",
	})

	limit := len(findings)
	if limit > 10 {
		limit = 10
	}

	for _, f := range findings[:limit] {
		blocks = append(blocks, map[string]interface{}{
			"type": "section",
			"text": map[string]interface{}{
				"type": "mrkdwn",
				"text": fmt.Sprintf("*%s* [%s]\n`%s` line %d\n`%s`",
					f.Rule, f.Severity, f.File, f.Line, f.Redacted),
			},
		})
	}

	if len(findings) > 10 {
		blocks = append(blocks, map[string]interface{}{
			"type": "section",
			"text": map[string]interface{}{
				"type": "mrkdwn",
				"text": fmt.Sprintf("_...and %d more findings_", len(findings)-10),
			},
		})
	}

	payload := map[string]interface{}{
		"blocks": blocks,
	}

	return sendWebhook(webhook, payload)
}

func notifyDiscord(webhook string, findings []Finding) error {
	hostname, _ := os.Hostname()
	cwd, _ := os.Getwd()

	var fields []map[string]interface{}

	limit := len(findings)
	if limit > 10 {
		limit = 10
	}

	for _, f := range findings[:limit] {
		fields = append(fields, map[string]interface{}{
			"name":   fmt.Sprintf("%s [%s]", f.Rule, f.Severity),
			"value":  fmt.Sprintf("`%s` line %d\n`%s`", f.File, f.Line, f.Redacted),
			"inline": false,
		})
	}

	embed := map[string]interface{}{
		"title":       fmt.Sprintf("🔒 dotguard: %d secret(s) detected", len(findings)),
		"color":       16711680, // red
		"description": fmt.Sprintf("**Host:** %s\n**Directory:** `%s`", hostname, cwd),
		"fields":      fields,
		"timestamp":   time.Now().Format(time.RFC3339),
		"footer": map[string]interface{}{
			"text": "dotguard — secret leak prevention",
		},
	}

	if len(findings) > 10 {
		embed["description"] = fmt.Sprintf("**Host:** %s\n**Directory:** `%s`\n\n_Showing 10 of %d findings_", hostname, cwd, len(findings))
	}

	payload := map[string]interface{}{
		"embeds": []map[string]interface{}{embed},
	}

	return sendWebhook(webhook, payload)
}

func sendWebhook(url string, payload interface{}) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}

	return nil
}
