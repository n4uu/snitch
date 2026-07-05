// Package notify posts snitch alerts to a webhook, auto-detecting the Discord
// and Slack incoming-webhook shapes from the URL and falling back to a generic
// JSON body otherwise. Standard library only.
package notify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Message is a provider-agnostic alert. Callers build the human-readable Body
// (plain text with light markdown); notify wraps it for the target platform.
type Message struct {
	Title string
	Body  string
}

// maxLen keeps us safely under Discord's 2000-character content limit.
const maxLen = 1900

// Send posts m to webhookURL, formatting the payload for whichever provider the
// URL points at. It returns an error on transport failure or a non-2xx reply.
func Send(webhookURL string, m Message) error {
	payload, err := encode(detect(webhookURL), m)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, webhookURL, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("webhook returned %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	return nil
}

type provider int

const (
	generic provider = iota
	discord
	slack
)

func detect(url string) provider {
	switch {
	case strings.Contains(url, "discord.com/api/webhooks"), strings.Contains(url, "discordapp.com/api/webhooks"):
		return discord
	case strings.Contains(url, "hooks.slack.com"):
		return slack
	default:
		return generic
	}
}

func encode(p provider, m Message) ([]byte, error) {
	switch p {
	case discord:
		return json.Marshal(map[string]string{"content": truncate("**"+m.Title+"**\n"+m.Body, maxLen)})
	case slack:
		return json.Marshal(map[string]string{"text": truncate("*"+m.Title+"*\n"+m.Body, maxLen)})
	default:
		return json.Marshal(map[string]string{"title": m.Title, "body": m.Body})
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.TrimSpace(s[:n-1]) + "…"
}
