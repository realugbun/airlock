package proxy

import (
	"strings"
	"testing"
)

// FuzzMatchPattern throws random paths at various patterns to find panics
// or unexpected matches. The fuzzer will explore path traversal tricks,
// URL encoding, null bytes, double slashes, etc.
func FuzzMatchPattern(f *testing.F) {
	// Seed corpus with known edge cases and bypass attempts.
	seeds := []string{
		"/v1/chat/completions",
		"/v1/models",
		"/",
		"",
		"//",
		"/../../../etc/passwd",
		"/v1/../v1/chat/completions",
		"/v1/chat/completions/",
		"/v1/chat/completions//",
		"/v1//chat//completions",
		"/%2e%2e/admin",
		"/v1/chat/completions%00",
		"/v1/chat/completions\x00extra",
		"/v1/chat/completions?query=1",
		"/v1/chat/completions#fragment",
		"/../admin/settings",
		"/./v1/chat/completions",
		"/v1/chat/../chat/completions",
		"/v1/CHAT/COMPLETIONS",
		"/V1/Chat/Completions",
		strings.Repeat("/a", 1000),
		"/v1/" + strings.Repeat("*", 100),
		"/v1/" + strings.Repeat(".", 100),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	// Pattern: exact match. Only "/v1/chat/completions" should match.
	f.Fuzz(func(t *testing.T, path string) {
		result := matchPattern("/v1/chat/completions", path)

		// If it matched, verify the normalized segments are correct.
		if result {
			parts := splitPath(path)
			expected := []string{"v1", "chat", "completions"}
			if len(parts) != len(expected) {
				t.Errorf("exact pattern matched unexpected path: %q (parts=%v)", path, parts)
			} else {
				for i, p := range parts {
					if p != expected[i] {
						t.Errorf("exact pattern matched unexpected path: %q (parts=%v)", path, parts)
						break
					}
				}
			}
		}
	})
}

// FuzzMatchPatternWildcard fuzzes single-segment wildcard patterns.
func FuzzMatchPatternWildcard(f *testing.F) {
	seeds := []string{
		"/users/123/detail",
		"/users//detail",
		"/users/../../detail",
		"/users/*/detail",
		"/users",
		"/users/",
		"/users/123/detail/extra",
		"/users/123",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, path string) {
		result := matchPattern("/users/*/detail", path)
		if result {
			parts := splitPath(path)
			// Must be exactly 3 segments: "users", <anything>, "detail"
			if len(parts) != 3 || parts[0] != "users" || parts[2] != "detail" {
				t.Errorf("wildcard pattern matched unexpected path: %q (parts=%v)", path, parts)
			}
		}
	})
}

// FuzzMatchPatternDoublestar fuzzes multi-segment wildcard patterns.
func FuzzMatchPatternDoublestar(f *testing.F) {
	seeds := []string{
		"/repos",
		"/repos/foo",
		"/repos/foo/bar/baz",
		"/other",
		"",
		"/repos/../admin",
		"/repos/",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, path string) {
		result := matchPattern("/repos/**", path)
		if result {
			parts := splitPath(path)
			if len(parts) == 0 || parts[0] != "repos" {
				t.Errorf("doublestar pattern matched path not starting with repos: %q", path)
			}
		}
	})
}

// FuzzAccessPolicyBypass tries to bypass an allow-only policy.
// Only POST /v1/chat/completions should be allowed. Everything else must be denied.
func FuzzAccessPolicyBypass(f *testing.F) {
	seeds := []struct {
		method string
		path   string
	}{
		{"POST", "/v1/chat/completions"},
		{"GET", "/v1/chat/completions"},
		{"POST", "/v1/models"},
		{"POST", "/v1/chat/completions/"},
		{"POST", "/v1/../v1/chat/completions"},
		{"POST", "/v1/chat/completions%00"},
		{"POST", "/v1//chat//completions"},
		{"post", "/v1/chat/completions"},
		{"POST", "/V1/CHAT/COMPLETIONS"},
		{"DELETE", "/v1/chat/completions"},
		{"POST", "/v1/chat/completions/../../../admin"},
	}
	for _, s := range seeds {
		f.Add(s.method, s.path)
	}

	policy, err := NewAccessPolicy([]AccessRuleInput{
		{Action: "ALLOW", Method: "POST", Path: "/v1/chat/completions"},
	}, false)
	if err != nil {
		f.Fatal(err)
	}

	f.Fuzz(func(t *testing.T, method, path string) {
		result := policy.Allowed(method, path)

		if result {
			// If allowed, method must be POST and normalized segments must match.
			if method != "POST" {
				t.Errorf("non-POST method %q was allowed for path %q", method, path)
			}
			parts := splitPath(path)
			expected := []string{"v1", "chat", "completions"}
			if len(parts) != len(expected) {
				t.Errorf("POST allowed for unexpected path: %q (parts=%v)", path, parts)
			} else {
				for i, p := range parts {
					if p != expected[i] {
						t.Errorf("POST allowed for unexpected path: %q (parts=%v)", path, parts)
						break
					}
				}
			}
		}
	})
}

// FuzzAccessPolicyDenyBypass tries to get past a DENY rule.
// DELETE on any path should always be denied.
func FuzzAccessPolicyDenyBypass(f *testing.F) {
	seeds := []string{
		"/anything",
		"/",
		"",
		"/v1/chat/completions",
		"/../../../etc/passwd",
		strings.Repeat("/a", 500),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	policy, err := NewAccessPolicy([]AccessRuleInput{
		{Action: "DENY", Method: "DELETE", Path: "/**"},
		{Action: "ALLOW", Method: "ALL", Path: "/**"},
	}, false)
	if err != nil {
		f.Fatal(err)
	}

	f.Fuzz(func(t *testing.T, path string) {
		if policy.Allowed("DELETE", path) {
			t.Errorf("DELETE was allowed for path %q — should be denied", path)
		}
	})
}

// FuzzMatchPatternNoPanic ensures matchPattern never panics on any input.
func FuzzMatchPatternNoPanic(f *testing.F) {
	f.Add("/**", "/foo/bar")
	f.Add("/**/*/end", "/a/b/c/end")
	f.Add("", "")
	f.Add("*", "*")
	f.Add("**", "**")
	f.Add(strings.Repeat("**/", 50)+"end", strings.Repeat("a/", 50)+"end")

	f.Fuzz(func(t *testing.T, pattern, path string) {
		// Must not panic — that's the only assertion.
		matchPattern(pattern, path)
	})
}
