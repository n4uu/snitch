package notify

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDetect(t *testing.T) {
	cases := map[string]provider{
		"https://discord.com/api/webhooks/123/abc":    discord,
		"https://discordapp.com/api/webhooks/123/abc": discord,
		"https://hooks.slack.com/services/T/B/x":      slack,
		"https://example.com/my/webhook":              generic,
		"https://n8n.local/webhook/abc":               generic,
	}
	for url, want := range cases {
		if got := detect(url); got != want {
			t.Errorf("detect(%q) = %v, want %v", url, got, want)
		}
	}
}

func TestEncodeShapes(t *testing.T) {
	m := Message{Title: "hi", Body: "line1\nline2"}

	if b, _ := encode(discord, m); !strings.Contains(string(b), `"content"`) {
		t.Errorf("discord payload should use 'content' key: %s", b)
	}
	if b, _ := encode(slack, m); !strings.Contains(string(b), `"text"`) {
		t.Errorf("slack payload should use 'text' key: %s", b)
	}
	b, _ := encode(generic, m)
	var got map[string]string
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("generic payload not valid JSON: %v", err)
	}
	if got["title"] != "hi" || got["body"] != "line1\nline2" {
		t.Errorf("generic payload lost fields: %v", got)
	}
}

func TestSendPostsAndChecksStatus(t *testing.T) {
	var gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("expected JSON content-type, got %q", ct)
		}
		body, _ := io.ReadAll(r.Body)
		gotBody = string(body)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	if err := Send(srv.URL, Message{Title: "t", Body: "b"}); err != nil {
		t.Fatalf("Send returned error on 2xx: %v", err)
	}
	if !strings.Contains(gotBody, "t") {
		t.Errorf("server did not receive the message body: %q", gotBody)
	}

	// Non-2xx must surface as an error.
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer bad.Close()
	if err := Send(bad.URL, Message{Title: "t", Body: "b"}); err == nil {
		t.Error("Send should error on a 500 response")
	}
}
