package proxy

import (
	"fmt"
	"regexp"
	"strings"
)

// MaxPathRegexLen mirrors the cap enforced at config load. Duplicated here so the
// proxy package rejects oversized regexes even when called outside the config loader.
const MaxPathRegexLen = 512

type action int

const (
	actionAllow action = iota
	actionDeny
)

// accessRule is a single firewall-style rule: action + method + path matcher.
// Exactly one of pattern (glob) or regex (RE2) is populated.
type accessRule struct {
	action  action
	method  string // "ALL" matches any method
	pattern string
	regex   *regexp.Regexp
}

// AccessPolicy evaluates firewall-style rules in order. First match wins.
// If rules are defined but none match, the request is denied (implicit deny).
// If no rules are defined, all requests are allowed (no restrictions).
// If denyAll is set (explicit empty access_rules: []), all requests are denied.
type AccessPolicy struct {
	rules   []accessRule
	denyAll bool
}

// AccessRuleInput is the structured input for a single rule.
// Exactly one of Path (glob) or PathRegex (RE2) must be set.
type AccessRuleInput struct {
	Action    string
	Method    string
	Path      string
	PathRegex string
}

// NewAccessPolicy creates an access policy from ordered structured rules.
//
// Rules are evaluated in order — first match wins.
// If rules exist but none match, the request is denied (implicit deny at end).
// An empty rule list means no restrictions (all requests allowed).
// Set denyAll to true for explicit empty access_rules: [] (deny everything).
func NewAccessPolicy(rules []AccessRuleInput, denyAll bool) (*AccessPolicy, error) {
	if len(rules) == 0 {
		return &AccessPolicy{denyAll: denyAll}, nil
	}
	parsed := make([]accessRule, 0, len(rules))
	for i, input := range rules {
		r, err := parseRuleInput(input)
		if err != nil {
			return nil, fmt.Errorf("access_rules[%d]: %w", i, err)
		}
		parsed = append(parsed, r)
	}
	return &AccessPolicy{rules: parsed}, nil
}

// Allowed evaluates the rules in order. First match wins.
// Returns true if allowed, false if denied.
func (p *AccessPolicy) Allowed(method, path string) bool {
	if p.denyAll {
		return false
	}
	if len(p.rules) == 0 {
		return true
	}
	// Enforce the segment cap once, for the whole request. matchSegments caps
	// only the rules it evaluates, so without this an overlong path fails every
	// glob rule (including a trailing DENY /**) and can then be caught by a
	// later ALLOW path_regex, which has no such cap — a fail-open bypass that
	// only appears once both matchers coexist.
	if len(splitPath(path)) > maxPathSegments {
		return false
	}
	normalized := normalizePath(path)
	for _, r := range p.rules {
		if r.method != "ALL" && r.method != method {
			continue
		}
		var hit bool
		if r.regex != nil {
			hit = r.regex.MatchString(normalized)
		} else {
			hit = matchPattern(r.pattern, path)
		}
		if hit {
			return r.action == actionAllow
		}
	}
	// No rule matched — implicit deny
	return false
}

func parseRuleInput(input AccessRuleInput) (accessRule, error) {
	var act action
	switch input.Action {
	case "ALLOW":
		act = actionAllow
	case "DENY":
		act = actionDeny
	case "":
		return accessRule{}, fmt.Errorf("action is required (ALLOW or DENY)")
	default:
		return accessRule{}, fmt.Errorf("invalid action %q — use ALLOW or DENY", input.Action)
	}

	if input.Method == "" {
		return accessRule{}, fmt.Errorf("method is required (GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS, or ALL)")
	}
	if !isValidMethod(input.Method) {
		return accessRule{}, fmt.Errorf("invalid method %q — use GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS, or ALL", input.Method)
	}

	hasPath := input.Path != ""
	hasRegex := input.PathRegex != ""
	if hasPath && hasRegex {
		return accessRule{}, fmt.Errorf("only one of path or path_regex may be set")
	}
	if !hasPath && !hasRegex {
		return accessRule{}, fmt.Errorf("one of path or path_regex is required")
	}

	if hasRegex {
		if len(input.PathRegex) > MaxPathRegexLen {
			return accessRule{}, fmt.Errorf("path_regex exceeds %d characters", MaxPathRegexLen)
		}
		// Reject patterns that are not valid regexes on their own BEFORE
		// wrapping. An unbalanced ")" would otherwise re-parenthesise the
		// wrapper and silently defeat the anchoring: "/v1/ok)|(.*" compiles as
		// \A(?:/v1/ok)|(.*)\z, whose second alternative is unanchored and
		// matches every path — turning an ALLOW rule into allow-all.
		if _, err := regexp.Compile(input.PathRegex); err != nil {
			return accessRule{}, fmt.Errorf("invalid path_regex %q: %w", input.PathRegex, err)
		}
		// Wrap as \A(?:user)\z so the user pattern is fully anchored
		// regardless of any internal alternations like "foo|bar". User-supplied
		// ^/$ anchors are harmless inside the non-capturing group.
		wrapped := `\A(?:` + input.PathRegex + `)\z`
		re, err := regexp.Compile(wrapped)
		if err != nil {
			return accessRule{}, fmt.Errorf("invalid path_regex %q: %w", input.PathRegex, err)
		}
		return accessRule{action: act, method: input.Method, regex: re}, nil
	}

	return accessRule{action: act, method: input.Method, pattern: input.Path}, nil
}

// normalizePath rewrites a request path into the canonical form regex rules see:
// single leading slash, no trailing slash (root stays "/"), interior "//" collapsed.
// This keeps regex semantics consistent with glob — both run against the same shape.
func normalizePath(p string) string {
	parts := splitPath(p)
	if len(parts) == 0 {
		return "/"
	}
	return "/" + strings.Join(parts, "/")
}

func isValidMethod(s string) bool {
	switch s {
	case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "ALL":
		return true
	}
	return false
}

// matchPattern supports:
//   - exact match: "/v1/chat/completions"
//   - single-segment wildcard: "/users/*/detail" (* matches one segment)
//   - multi-segment wildcard: "/repos/**" (** matches zero or more segments)
//   - mixed: "/api/*/files/**"
func matchPattern(pattern, path string) bool {
	patParts := splitPath(pattern)
	patParts = collapseDoublestar(patParts)
	pathParts := splitPath(path)
	return matchSegments(patParts, pathParts)
}

func splitPath(p string) []string {
	p = strings.Trim(p, "/")
	if p == "" {
		return nil
	}
	raw := strings.Split(p, "/")
	// Filter empty segments (from interior "//") to normalize paths.
	// This prevents "/v1//chat" from being treated differently than "/v1/chat".
	out := raw[:0]
	for _, s := range raw {
		if s != "" {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// collapseDoublestar merges consecutive "**" segments into a single "**".
// This prevents exponential backtracking in matchSegments: N consecutive **
// would otherwise create O(path_length^N) branching.
func collapseDoublestar(parts []string) []string {
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p == "**" && len(out) > 0 && out[len(out)-1] == "**" {
			continue
		}
		out = append(out, p)
	}
	return out
}

// Safety caps: deny if pattern or path exceeds these limits.
const (
	maxPatternSegments = 64
	maxPathSegments    = 256
)

// matchSegments uses iterative bottom-up DP to match pattern against path.
// dp[p][s] == true means pattern[p:] matches path[s:].
// Time: O(P*S), Space: O(P*S). No recursion, no backtracking.
func matchSegments(pattern, path []string) bool {
	P, S := len(pattern), len(path)
	if P > maxPatternSegments || S > maxPathSegments {
		return false
	}

	dp := make([][]bool, P+1)
	for i := range dp {
		dp[i] = make([]bool, S+1)
	}
	dp[P][S] = true // empty pattern matches empty path

	for p := P - 1; p >= 0; p-- {
		seg := pattern[p]
		if seg == "**" {
			// ** matches zero or more segments.
			// dp[p][s] = dp[p+1][s]  (skip **, match zero)
			//         || dp[p][s+1]  (** consumes segment s, keep trying)
			for s := S; s >= 0; s-- {
				dp[p][s] = dp[p+1][s]
				if s < S {
					dp[p][s] = dp[p][s] || dp[p][s+1]
				}
			}
		} else {
			// Literal or * — must match exactly one segment.
			for s := S - 1; s >= 0; s-- {
				if matchSegment(seg, path[s]) {
					dp[p][s] = dp[p+1][s+1]
				}
			}
		}
	}
	return dp[0][0]
}

func matchSegment(pattern, segment string) bool {
	if pattern == "*" {
		return segment != "" // * matches exactly one non-empty segment
	}
	return pattern == segment
}
