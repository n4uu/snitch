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

func TestDedupeParamURLs(t *testing.T) {
	urls := []string{
		"https://x.com/search?q=1",            // \
		"https://x.com/search?q=2",            //  } same host+path+param{q} -> 1
		"https://x.com/search?q=hello",        // /
		"https://x.com/search?category=books", // different param name -> kept
		"https://x.com/view?id=1&ref=a",       // param set {id,ref} -> kept
		"https://x.com/view?ref=b&id=2",       // same set {id,ref}, order/values differ -> collapsed
		"https://x.com/other?id=9",            // different path -> kept
	}
	got := dedupeParamURLs(urls)
	if len(got) != 4 {
		t.Fatalf("expected 4 unique parameter surfaces, got %d: %v", len(got), got)
	}
}
