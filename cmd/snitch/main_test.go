package main

import "testing"

func TestNormalizeTarget(t *testing.T) {
	cases := map[string]string{
		"https://phenomena-experience.com/": "phenomena-experience.com",
		"example.com":                       "example.com",
		"http://Sub.Example.COM/path?x=1":   "sub.example.com",
		"https://user:pass@example.com/":    "example.com",
		"example.com.":                      "example.com",
		"  https://example.com  ":           "example.com",
	}
	for in, want := range cases {
		if got := normalizeTarget(in); got != want {
			t.Errorf("normalizeTarget(%q) = %q, want %q", in, got, want)
		}
	}
}
