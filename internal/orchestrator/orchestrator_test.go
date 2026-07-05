package orchestrator

import "testing"

func TestInScopeURLs(t *testing.T) {
	target := "example.com"
	hosts := []string{"example.com", "www.example.com"}
	urls := []string{
		"https://example.com/a?x=1",        // target itself
		"https://www.example.com/b?y=1",    // enumerated host
		"https://api.example.com/c?z=1",    // subdomain (suffix match)
		"https://cdn.thirdparty.com/d?e=1", // third-party — must be dropped
		"http://evil.com/?q=1",             // out of scope — must be dropped
	}

	got := inScopeURLs(urls, target, hosts)
	if len(got) != 3 {
		t.Fatalf("expected 3 in-scope URLs, got %d: %v", len(got), got)
	}
	for _, u := range got {
		if u == "https://cdn.thirdparty.com/d?e=1" || u == "http://evil.com/?q=1" {
			t.Errorf("out-of-scope URL leaked through: %s", u)
		}
	}
}
