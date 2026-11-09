package proxy

// Differential tests tying the shipped MCP tool authorization to the
// Dafny model in formal/mcp.dfy.
//
// Two separate jobs are done here.
//
//  1. THE DECISION. Reference implementations named after each Dafny
//     definition mirror it line for line: MatchesAny, IsToolDenied,
//     CheckSingle, CheckBatch, FilterNames, AllowedIdx. The proofs are
//     statements ABOUT those definitions; these tests are what makes
//     them statements about isToolDenied, checkSingle, checkBatch and
//     filterJSONToolsList too.
//
//     path.Match is uninterpreted in the model, and the SAME field is
//     used by the call check and the list filter. The references below
//     therefore call path.Match directly, errors discarded exactly as
//     the shipped code discards them, and every theorem holds whatever
//     it returns.
//
//  2. THE PARSER. JSON decoding is trusted: it is not modelled, so a
//     proof cannot cover it. Instead refDecodeStrictObject and
//     refParseRPCMessage re-derive the policy-relevant fields with an
//     independent JSON scanner -- own tokenizer, own escape decoding,
//     own case folding, no encoding/json and no strings.EqualFold --
//     and the adversarial corpus below checks that every input where
//     the two readings could differ is REJECTED by the shipped parser
//     rather than decided one way or the other.
//
// Every exhaustive or randomized loop here is explicitly bounded and
// generates its cases one at a time.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"path"
	"strings"
	"testing"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =====================================================================
// Reference implementation of the decision model (formal/mcp.dfy).
// =====================================================================

// refMCPPolicy mirrors Dafny Policy. A non-nil Go map is always a
// non-empty one (NewMCPToolPolicy only allocates it immediately before
// writing an entry), which is why a nil-vs-empty distinction is not
// needed here; TestNewMCPToolPolicyMatchesDafnyConstructor checks that.
type refMCPPolicy struct {
	allowedExact    map[string]struct{}
	allowedPatterns []string
	deniedExact     map[string]struct{}
	deniedPatterns  []string
	matcher         func(pat, name string) bool
}

// refPathMatch is path.Match with the error discarded, exactly as
// isToolDenied discards it. This is the uninterpreted `matcher` field.
func refPathMatch(pat, name string) bool {
	matched, _ := path.Match(pat, name)
	return matched
}

// refMCPMatchesAny mirrors Dafny MatchesAny.
func refMCPMatchesAny(m func(string, string) bool, pats []string, name string) bool {
	if len(pats) == 0 {
		return false
	}
	return m(pats[0], name) || refMCPMatchesAny(m, pats[1:], name)
}

// refMCPHasAllowRules mirrors Dafny HasAllowRules.
func refMCPHasAllowRules(p refMCPPolicy) bool {
	return len(p.allowedExact) > 0 || len(p.allowedPatterns) > 0
}

// refMCPHasDenyRules mirrors Dafny HasDenyRules.
func refMCPHasDenyRules(p refMCPPolicy) bool {
	return len(p.deniedExact) > 0 || len(p.deniedPatterns) > 0
}

// refMCPHasToolRules mirrors Dafny HasToolRules.
func refMCPHasToolRules(p refMCPPolicy) bool {
	return refMCPHasAllowRules(p) || refMCPHasDenyRules(p)
}

// refMCPIsToolDenied mirrors Dafny IsToolDenied.
func refMCPIsToolDenied(p refMCPPolicy, name string) bool {
	if refMCPHasAllowRules(p) {
		if _, ok := p.allowedExact[name]; ok {
			return false
		}
		return !refMCPMatchesAny(p.matcher, p.allowedPatterns, name)
	}
	if refMCPHasDenyRules(p) {
		if _, ok := p.deniedExact[name]; ok {
			return true
		}
		return refMCPMatchesAny(p.matcher, p.deniedPatterns, name)
	}
	return false
}

// refMCPIsToolAllowed mirrors Dafny IsToolAllowed.
func refMCPIsToolAllowed(p refMCPPolicy, name string) bool {
	return !refMCPIsToolDenied(p, name)
}

// refMCPParsed mirrors Dafny Parsed: either Malformed, or a message
// carrying (method, tool name, id).
type refMCPParsed struct {
	malformed bool
	method    string
	toolName  string
	id        []byte
}

// refMCPIsToolCall mirrors Dafny IsToolCall.
func refMCPIsToolCall(x refMCPParsed) bool {
	return !x.malformed && x.method == "tools/call"
}

// refMCPDecision mirrors Dafny Decision.
type refMCPDecision struct {
	kind     string // "forward" | "deny" | "reject"
	method   string
	toolName string
}

func refMCPForward(method string) refMCPDecision {
	return refMCPDecision{kind: "forward", method: method}
}

// refMCPCheckSingle mirrors Dafny CheckSingle.
func refMCPCheckSingle(p refMCPPolicy, x refMCPParsed) refMCPDecision {
	if x.malformed {
		return refMCPDecision{kind: "reject"}
	}
	if x.method == "tools/call" && refMCPIsToolDenied(p, x.toolName) {
		return refMCPDecision{kind: "deny", toolName: x.toolName, method: "tools/call"}
	}
	return refMCPForward(x.method)
}

// refMCPCheckBatch mirrors Dafny CheckBatch: two passes, every element
// parsed before any element is executed.
func refMCPCheckBatch(p refMCPPolicy, xs []refMCPParsed) refMCPDecision {
	for _, x := range xs {
		if x.malformed {
			return refMCPDecision{kind: "reject"}
		}
	}
	for _, x := range xs {
		if refMCPIsToolCall(x) && refMCPIsToolDenied(p, x.toolName) {
			return refMCPDecision{kind: "deny", toolName: x.toolName, method: "tools/call"}
		}
	}
	return refMCPForward("batch")
}

// refMCPFilterNames mirrors Dafny FilterNames.
func refMCPFilterNames(p refMCPPolicy, names []string) []string {
	if len(names) == 0 {
		return nil
	}
	if refMCPIsToolAllowed(p, names[0]) {
		return append([]string{names[0]}, refMCPFilterNames(p, names[1:])...)
	}
	return refMCPFilterNames(p, names[1:])
}

// refMCPAllowedIdx mirrors Dafny AllowedIdx: the ascending index map of
// the positions that survive the filter.
func refMCPAllowedIdx(p refMCPPolicy, names []string, from int) []int {
	if from == len(names) {
		return nil
	}
	if refMCPIsToolAllowed(p, names[from]) {
		return append([]int{from}, refMCPAllowedIdx(p, names, from+1)...)
	}
	return refMCPAllowedIdx(p, names, from+1)
}

// refMCPPolicyFrom lifts a shipped *MCPToolPolicy into the model.
func refMCPPolicyFrom(p *MCPToolPolicy) refMCPPolicy {
	return refMCPPolicy{
		allowedExact:    p.allowedExact,
		allowedPatterns: p.allowedPatterns,
		deniedExact:     p.deniedExact,
		deniedPatterns:  p.deniedPatterns,
		matcher:         refPathMatch,
	}
}

// mcpDecisionOf maps a (*MCPCheckResult, reason) pair from checkSingle
// or checkBatch onto the model's Decision.
func mcpDecisionOf(res *MCPCheckResult, reason string) refMCPDecision {
	if reason != "" {
		return refMCPDecision{kind: "reject"}
	}
	if res.Denied {
		return refMCPDecision{kind: "deny", toolName: res.ToolName, method: res.Method}
	}
	return refMCPForward(res.Method)
}

// =====================================================================
// An independent JSON scanner.
//
// Used only by the parser differential tests. It shares no code with
// encoding/json: its own value grammar, its own string unescaping
// (including \uXXXX and surrogate pairs), and its own Unicode simple
// case folding.
// =====================================================================

type refJSONScanner struct {
	b []byte
	i int
}

func refIsJSONDigit(c byte) bool { return c >= '0' && c <= '9' }

func (s *refJSONScanner) skipWS() {
	for s.i < len(s.b) {
		switch s.b[s.i] {
		case ' ', '\t', '\n', '\r':
			s.i++
		default:
			return
		}
	}
}

func (s *refJSONScanner) scanHex4() (rune, bool) {
	if s.i+4 > len(s.b) {
		return 0, false
	}
	var v rune
	for k := 0; k < 4; k++ {
		c := s.b[s.i+k]
		switch {
		case c >= '0' && c <= '9':
			v = v*16 + rune(c-'0')
		case c >= 'a' && c <= 'f':
			v = v*16 + rune(c-'a'+10)
		case c >= 'A' && c <= 'F':
			v = v*16 + rune(c-'A'+10)
		default:
			return 0, false
		}
	}
	s.i += 4
	return v, true
}

// scanEscape handles the part after a backslash.
func (s *refJSONScanner) scanEscape() ([]rune, bool) {
	if s.i >= len(s.b) {
		return nil, false
	}
	c := s.b[s.i]
	s.i++
	switch c {
	case '"':
		return []rune{'"'}, true
	case '\\':
		return []rune{'\\'}, true
	case '/':
		return []rune{'/'}, true
	case 'b':
		return []rune{'\b'}, true
	case 'f':
		return []rune{'\f'}, true
	case 'n':
		return []rune{'\n'}, true
	case 'r':
		return []rune{'\r'}, true
	case 't':
		return []rune{'\t'}, true
	case 'u':
		r1, ok := s.scanHex4()
		if !ok {
			return nil, false
		}
		if !utf16.IsSurrogate(r1) {
			return []rune{r1}, true
		}
		// A surrogate is only a character when it is paired.
		save := s.i
		if s.i+1 < len(s.b) && s.b[s.i] == '\\' && s.b[s.i+1] == 'u' {
			s.i += 2
			r2, ok := s.scanHex4()
			if !ok {
				return nil, false
			}
			if dec := utf16.DecodeRune(r1, r2); dec != unicode.ReplacementChar {
				return []rune{dec}, true
			}
			s.i = save
		}
		return []rune{unicode.ReplacementChar}, true
	default:
		return nil, false
	}
}

// scanString scans a JSON string and returns its decoded value.
func (s *refJSONScanner) scanString() (string, bool) {
	if s.i >= len(s.b) || s.b[s.i] != '"' {
		return "", false
	}
	s.i++
	out := make([]rune, 0, 8)
	for {
		if s.i >= len(s.b) {
			return "", false
		}
		c := s.b[s.i]
		switch {
		case c == '"':
			s.i++
			return string(out), true
		case c == '\\':
			s.i++
			rs, ok := s.scanEscape()
			if !ok {
				return "", false
			}
			out = append(out, rs...)
		case c < 0x20:
			return "", false
		default:
			r, size := utf8.DecodeRune(s.b[s.i:])
			out = append(out, r)
			s.i += size
		}
	}
}

func (s *refJSONScanner) scanLit(lit string) bool {
	if s.i+len(lit) > len(s.b) || string(s.b[s.i:s.i+len(lit)]) != lit {
		return false
	}
	s.i += len(lit)
	return true
}

func (s *refJSONScanner) scanNumber() bool {
	if s.i < len(s.b) && s.b[s.i] == '-' {
		s.i++
	}
	if s.i >= len(s.b) {
		return false
	}
	switch {
	case s.b[s.i] == '0':
		s.i++
	case s.b[s.i] >= '1' && s.b[s.i] <= '9':
		for s.i < len(s.b) && refIsJSONDigit(s.b[s.i]) {
			s.i++
		}
	default:
		return false
	}
	if s.i < len(s.b) && s.b[s.i] == '.' {
		s.i++
		if s.i >= len(s.b) || !refIsJSONDigit(s.b[s.i]) {
			return false
		}
		for s.i < len(s.b) && refIsJSONDigit(s.b[s.i]) {
			s.i++
		}
	}
	if s.i < len(s.b) && (s.b[s.i] == 'e' || s.b[s.i] == 'E') {
		s.i++
		if s.i < len(s.b) && (s.b[s.i] == '+' || s.b[s.i] == '-') {
			s.i++
		}
		if s.i >= len(s.b) || !refIsJSONDigit(s.b[s.i]) {
			return false
		}
		for s.i < len(s.b) && refIsJSONDigit(s.b[s.i]) {
			s.i++
		}
	}
	return true
}

func (s *refJSONScanner) scanObject() bool {
	s.i++ // '{'
	s.skipWS()
	if s.i < len(s.b) && s.b[s.i] == '}' {
		s.i++
		return true
	}
	for {
		s.skipWS()
		if _, ok := s.scanString(); !ok {
			return false
		}
		s.skipWS()
		if s.i >= len(s.b) || s.b[s.i] != ':' {
			return false
		}
		s.i++
		if _, ok := s.scanValue(); !ok {
			return false
		}
		s.skipWS()
		if s.i >= len(s.b) {
			return false
		}
		switch s.b[s.i] {
		case ',':
			s.i++
		case '}':
			s.i++
			return true
		default:
			return false
		}
	}
}

func (s *refJSONScanner) scanArray() bool {
	s.i++ // '['
	s.skipWS()
	if s.i < len(s.b) && s.b[s.i] == ']' {
		s.i++
		return true
	}
	for {
		if _, ok := s.scanValue(); !ok {
			return false
		}
		s.skipWS()
		if s.i >= len(s.b) {
			return false
		}
		switch s.b[s.i] {
		case ',':
			s.i++
		case ']':
			s.i++
			return true
		default:
			return false
		}
	}
}

// scanValue scans one JSON value and returns its raw bytes.
func (s *refJSONScanner) scanValue() ([]byte, bool) {
	s.skipWS()
	if s.i >= len(s.b) {
		return nil, false
	}
	start := s.i
	var ok bool
	switch c := s.b[s.i]; c {
	case '{':
		ok = s.scanObject()
	case '[':
		ok = s.scanArray()
	case '"':
		_, ok = s.scanString()
	case 't':
		ok = s.scanLit("true")
	case 'f':
		ok = s.scanLit("false")
	case 'n':
		ok = s.scanLit("null")
	default:
		ok = s.scanNumber()
	}
	if !ok {
		return nil, false
	}
	return s.b[start:s.i], true
}

// refValidJSON is an independent json.Valid.
func refValidJSON(b []byte) bool {
	s := &refJSONScanner{b: b}
	if _, ok := s.scanValue(); !ok {
		return false
	}
	s.skipWS()
	return s.i == len(s.b)
}

// refJSONStringValue decodes raw as a complete JSON string value.
func refJSONStringValue(raw []byte) (string, bool) {
	s := &refJSONScanner{b: raw}
	s.skipWS()
	v, ok := s.scanString()
	if !ok {
		return "", false
	}
	s.skipWS()
	return v, s.i == len(s.b)
}

// refIsJSONNull reports whether raw is the JSON literal null.
func refIsJSONNull(raw []byte) bool {
	s := &refJSONScanner{b: raw}
	s.skipWS()
	if !s.scanLit("null") {
		return false
	}
	s.skipWS()
	return s.i == len(s.b)
}

// refJSONStringInto mirrors json.Unmarshal(raw, &someString). A JSON
// string sets it; JSON null leaves it untouched and reports NO error,
// which is an encoding/json rule rather than a JSON-RPC one; anything
// else is an error.
//
// So `{"method":null}` is read by the shipped parser as a message with
// no method, and forwarded. That is not a policy-relevant ambiguity:
// an empty method is not tools/call under any reading, and no upstream
// can dispatch a null method to a tool. It is pinned by
// TestNullMethodIsReadAsNoMethod so it stays visible.
func refJSONStringInto(raw []byte) (string, bool) {
	if refIsJSONNull(raw) {
		return "", true
	}
	return refJSONStringValue(raw)
}

// refJSONArrayElements splits raw, a JSON array, into its elements.
// Mirrors json.Unmarshal(body, &[]json.RawMessage{}).
func refJSONArrayElements(raw []byte) ([][]byte, bool) {
	if !refValidJSON(raw) {
		return nil, false
	}
	s := &refJSONScanner{b: raw}
	s.skipWS()
	if s.i >= len(s.b) || s.b[s.i] != '[' {
		return nil, false
	}
	s.i++
	var out [][]byte
	s.skipWS()
	if s.i < len(s.b) && s.b[s.i] == ']' {
		return out, true
	}
	for {
		v, ok := s.scanValue()
		if !ok {
			return nil, false
		}
		out = append(out, v)
		s.skipWS()
		if s.i >= len(s.b) {
			return nil, false
		}
		switch s.b[s.i] {
		case ',':
			s.i++
		case ']':
			return out, true
		default:
			return nil, false
		}
	}
}

// refFoldRuneEq is Unicode simple case folding, written out rather than
// borrowed from strings.EqualFold.
func refFoldRuneEq(sr, tr rune) bool {
	if sr == tr {
		return true
	}
	if tr < sr {
		sr, tr = tr, sr
	}
	for r := unicode.SimpleFold(sr); r != sr; r = unicode.SimpleFold(r) {
		if r == tr {
			return true
		}
	}
	return false
}

// refFoldEq is an independent strings.EqualFold.
func refFoldEq(a, b string) bool {
	ar, br := []rune(a), []rune(b)
	if len(ar) != len(br) {
		return false
	}
	for i := range ar {
		if !refFoldRuneEq(ar[i], br[i]) {
			return false
		}
	}
	return true
}

// =====================================================================
// Independent reference for decodeStrictObject and parseRPCMessage.
// =====================================================================

// refDecodeStrictObject mirrors decodeStrictObject. A guarded key must
// appear exactly once, in exact case, after escape decoding.
func refDecodeStrictObject(raw []byte, guarded ...string) (map[string][]byte, string) {
	if !refValidJSON(raw) {
		return nil, "malformed JSON"
	}
	s := &refJSONScanner{b: raw}
	s.skipWS()
	if s.i >= len(s.b) || s.b[s.i] != '{' {
		return nil, "not an object"
	}
	s.i++
	fields := make(map[string][]byte)
	seen := make(map[string]bool, len(guarded))
	s.skipWS()
	if s.i < len(s.b) && s.b[s.i] == '}' {
		return fields, ""
	}
	for {
		s.skipWS()
		key, ok := s.scanString()
		if !ok {
			return nil, "malformed JSON"
		}
		for _, g := range guarded {
			if !refFoldEq(key, g) {
				continue
			}
			if key != g {
				return nil, fmt.Sprintf("key %q is a case variant of %q", key, g)
			}
			if seen[g] {
				return nil, fmt.Sprintf("duplicate key %q", g)
			}
			seen[g] = true
		}
		s.skipWS()
		if s.i >= len(s.b) || s.b[s.i] != ':' {
			return nil, "malformed JSON"
		}
		s.i++
		v, ok := s.scanValue()
		if !ok {
			return nil, "malformed JSON"
		}
		fields[key] = v
		s.skipWS()
		if s.i < len(s.b) && s.b[s.i] == ',' {
			s.i++
			continue
		}
		return fields, ""
	}
}

// refParseRPCMessage mirrors parseRPCMessage.
func refParseRPCMessage(raw []byte) refMCPParsed {
	bad := refMCPParsed{malformed: true}
	fields, reason := refDecodeStrictObject(raw, "method", "params")
	if reason != "" {
		return bad
	}
	msg := refMCPParsed{id: fields["id"]}

	methodRaw, ok := fields["method"]
	if !ok {
		return msg
	}
	method, ok := refJSONStringInto(methodRaw)
	if !ok {
		return bad
	}
	msg.method = method
	if method != "tools/call" {
		return msg
	}
	paramsRaw, ok := fields["params"]
	if !ok {
		return bad
	}
	params, reason := refDecodeStrictObject(paramsRaw, "name")
	if reason != "" {
		return bad
	}
	nameRaw, ok := params["name"]
	if !ok {
		return bad
	}
	name, ok := refJSONStringInto(nameRaw)
	if !ok || name == "" {
		return bad
	}
	msg.toolName = name
	return msg
}

// =====================================================================
// Corpora. Fixed size, no generated collections held in memory.
// =====================================================================

func mcpFormalPolicies(t *testing.T) []*MCPToolPolicy {
	t.Helper()
	cfgs := []*MCPToolPolicyConfig{
		{},
		{AllowedTools: []string{"calendar_read"}},
		{AllowedTools: []string{"calendar_*", "drive_get_*"}},
		{AllowedTools: []string{"calendar_read", "a?c", "x[yz]"}},
		{AllowedTools: []string{"*"}},
		{AllowedTools: []string{""}},
		{DeniedTools: []string{"admin_delete"}},
		{DeniedTools: []string{"*_delete", "admin_*"}},
		{DeniedTools: []string{"*"}},
		{DeniedTools: []string{"a?c", "x[yz]", "exact_one"}},
	}
	out := make([]*MCPToolPolicy, 0, len(cfgs))
	for _, c := range cfgs {
		p, err := NewMCPToolPolicy(c)
		require.NoError(t, err)
		out = append(out, p)
	}
	return out
}

func mcpFormalToolNames() []string {
	return []string{
		"", "a", "abc", "a/c", "axc", "xy", "xz", "xq", "exact_one",
		"calendar_read", "calendar_write", "calendar_", "Calendar_read",
		"drive_get_file", "drive_put_file", "admin_delete", "user_delete",
		"admin_", "delete", "*", "?", "[", "**", "a*c", "tools/call",
		"name with spaces", "ünïcode", "x\x00y",
	}
}

// =====================================================================
// 1. The decision over a tool name: isToolDenied vs Dafny IsToolDenied.
// =====================================================================

func TestIsToolDeniedMatchesDafnyIsToolDenied(t *testing.T) {
	policies := mcpFormalPolicies(t)
	names := mcpFormalToolNames()
	for pi, p := range policies {
		ref := refMCPPolicyFrom(p)
		for _, name := range names {
			assert.Equal(t, refMCPIsToolDenied(ref, name), p.isToolDenied(name),
				"policy %d, tool %q", pi, name)
			assert.Equal(t, refMCPIsToolAllowed(ref, name), p.isToolAllowed(name),
				"policy %d, tool %q", pi, name)
		}
		assert.Equal(t, refMCPHasToolRules(ref), p.hasToolRules(), "policy %d", pi)
	}
}

// Dafny A1: in allowlist mode a tool is allowed only if it is named in
// the exact set or matched by a pattern.
func TestAllowlistAllowsOnlyListedTools(t *testing.T) {
	p, err := NewMCPToolPolicy(&MCPToolPolicyConfig{
		AllowedTools: []string{"calendar_read", "drive_get_*"},
	})
	require.NoError(t, err)
	for _, name := range mcpFormalToolNames() {
		if !p.isToolDenied(name) {
			_, exact := p.allowedExact[name]
			assert.True(t, exact || refMCPMatchesAny(refPathMatch, p.allowedPatterns, name),
				"allowed %q is neither listed nor matched by a pattern", name)
		}
	}
}

// Dafny A2.
func TestDenylistDeniesExactlyListedTools(t *testing.T) {
	p, err := NewMCPToolPolicy(&MCPToolPolicyConfig{
		DeniedTools: []string{"admin_delete", "*_delete"},
	})
	require.NoError(t, err)
	for _, name := range mcpFormalToolNames() {
		_, exact := p.deniedExact[name]
		want := exact || refMCPMatchesAny(refPathMatch, p.deniedPatterns, name)
		assert.Equal(t, want, p.isToolDenied(name), "tool %q", name)
	}
}

// Dafny A3.
func TestPassThroughDeniesNothing(t *testing.T) {
	p, err := NewMCPToolPolicy(&MCPToolPolicyConfig{})
	require.NoError(t, err)
	require.False(t, p.hasToolRules())
	for _, name := range mcpFormalToolNames() {
		assert.False(t, p.isToolDenied(name), "tool %q", name)
	}
}

// =====================================================================
// 2. The constructor: Dafny C1 and C2.
// =====================================================================

func TestNewMCPToolPolicyMatchesDafnyConstructor(t *testing.T) {
	// C1: both lists set is refused, in either order and at any size.
	for _, cfg := range []*MCPToolPolicyConfig{
		{AllowedTools: []string{"a"}, DeniedTools: []string{"b"}},
		{AllowedTools: []string{"a", "b*"}, DeniedTools: []string{"c"}},
		{AllowedTools: []string{"*"}, DeniedTools: []string{"*"}},
	} {
		p, err := NewMCPToolPolicy(cfg)
		require.Error(t, err)
		require.Nil(t, p)
	}

	// C2: every entry lands in exactly one bucket, so a non-empty list
	// always selects its own mode and never pass-through. The nil map
	// the model elides is also checked here: a non-nil exact map is
	// always a non-empty one.
	cases := []struct {
		allowed, denied []string
	}{
		{nil, nil},
		{[]string{"a"}, nil},
		{[]string{"a*"}, nil},
		{[]string{"a", "b*", "c?", "d[ef]"}, nil},
		{[]string{""}, nil},
		{nil, []string{"a"}},
		{nil, []string{"a*"}},
		{nil, []string{"a", "b*"}},
	}
	for _, c := range cases {
		p, err := NewMCPToolPolicy(&MCPToolPolicyConfig{AllowedTools: c.allowed, DeniedTools: c.denied})
		require.NoError(t, err)
		ref := refMCPPolicyFrom(p)

		assert.Equal(t, len(c.allowed) > 0, refMCPHasAllowRules(ref),
			"allowed=%v", c.allowed)
		assert.Equal(t, len(c.denied) > 0, refMCPHasDenyRules(ref),
			"denied=%v", c.denied)
		assert.Equal(t, len(c.allowed) > 0 || len(c.denied) > 0, p.hasToolRules())

		// WellFormed: never both modes at once.
		assert.False(t, refMCPHasAllowRules(ref) && refMCPHasDenyRules(ref))

		// Every entry accounted for exactly once.
		assert.Equal(t, len(c.allowed), len(p.allowedExact)+len(p.allowedPatterns))
		assert.Equal(t, len(c.denied), len(p.deniedExact)+len(p.deniedPatterns))

		if p.allowedExact != nil {
			assert.NotEmpty(t, p.allowedExact, "a non-nil exact map must be non-empty")
		}
		if p.deniedExact != nil {
			assert.NotEmpty(t, p.deniedExact, "a non-nil exact map must be non-empty")
		}
	}

	// An invalid glob is refused at construction, so no policy ever
	// carries a pattern whose matcher behaviour is undefined.
	_, err := NewMCPToolPolicy(&MCPToolPolicyConfig{AllowedTools: []string{"a[b"}})
	require.Error(t, err)
}

// =====================================================================
// 3. checkSingle: Dafny M1.
// =====================================================================

func mcpFormalSingleBodies() []string {
	return []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"calendar_read"}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"admin_delete"}}`,
		`{"id":3,"method":"tools/call","params":{"name":"drive_get_file","arguments":{"x":1}}}`,
		`{"id":4,"method":"tools/call","params":{"name":"tools/call"}}`,
		`{"id":5,"method":"tools/list"}`,
		`{"id":6,"method":"initialize","params":{"name":"admin_delete"}}`,
		`{"id":7,"method":"ping"}`,
		`{"id":8,"result":{"ok":true}}`,
		`{"method":"tools\/call","params":{"name":"admin_delete"}}`,
		`{"method":"tools/call","params":{"name":"admin_delete"}}`,
		`{"method":"tools/call","params":{"name":"exact_one"}}`,
		`{"method":"tools/call","params":{"name":"xy"}}`,
		`{"method":"tools/call","params":{"name":"a/c"}}`,
		`{"method":"tools/call"}`,
		`{"method":"tools/call","params":{"name":""}}`,
		`{"method":"tools/call","params":{"name":123}}`,
		`{"method":"tools/call","params":"nope"}`,
		`{"method":"tools/call","params":{"name":"a","Name":"b"}}`,
		`{"method":"tools/call","METHOD":"ping","params":{"name":"a"}}`,
		`{"method":123}`,
		`{}`,
		`not json`,
		`[]`,
	}
}

func TestCheckSingleMatchesDafnyCheckSingle(t *testing.T) {
	for pi, p := range mcpFormalPolicies(t) {
		ref := refMCPPolicyFrom(p)
		for _, body := range mcpFormalSingleBodies() {
			got := mcpDecisionOf(p.checkSingle([]byte(body)))
			want := refMCPCheckSingle(ref, refParseRPCMessage([]byte(body)))
			assert.Equal(t, want.kind, got.kind, "policy %d, body %s", pi, body)
			if want.kind == "deny" {
				assert.Equal(t, want.toolName, got.toolName, "policy %d, body %s", pi, body)
			}
			if want.kind == "forward" {
				assert.Equal(t, want.method, got.method, "policy %d, body %s", pi, body)
			}
			// M1 itself: a forwarded tools/call names an allowed tool.
			if got.kind == "forward" {
				msg := refParseRPCMessage([]byte(body))
				if refMCPIsToolCall(msg) {
					assert.True(t, p.isToolAllowed(msg.toolName),
						"forwarded a tools/call for a tool that is not allowed: %q", msg.toolName)
				}
			}
		}
	}
}

// The precondition the model carries about the trusted parser: a
// tools/call that reaches the decision always names a non-empty tool.
func TestParseRPCMessageToolCallAlwaysNamesATool(t *testing.T) {
	for _, body := range mcpFormalSingleBodies() {
		msg, reason := parseRPCMessage([]byte(body))
		if reason != "" {
			require.Nil(t, msg)
			continue
		}
		if msg.method == "tools/call" {
			assert.NotEmpty(t, msg.toolName, "body %s", body)
		}
	}
}

// =====================================================================
// 4. checkBatch: Dafny M2.
// =====================================================================

func mcpFormalBatchBodies() []string {
	return []string{
		`[]`,
		`[{"method":"ping"}]`,
		`[{"method":"tools/call","params":{"name":"calendar_read"}}]`,
		`[{"method":"tools/call","params":{"name":"admin_delete"}}]`,
		`[{"method":"ping"},{"method":"tools/call","params":{"name":"calendar_read"}}]`,
		`[{"method":"tools/call","params":{"name":"calendar_read"}},` +
			`{"method":"tools/call","params":{"name":"admin_delete"}}]`,
		`[{"method":"tools/call","params":{"name":"admin_delete"}},` +
			`{"method":"tools/call","params":{"name":"calendar_read"}}]`,
		`[{"method":"ping"},{"method":"tools/call"}]`,
		`[{"method":"tools/call","params":{"name":"calendar_read"}},{"method":123}]`,
		`[{"method":"tools/call","params":{"name":"calendar_read"}},"bare"]`,
		`[{"method":"tools/call","params":{"name":"calendar_read"}},1]`,
		`[null]`,
		`[{"method":"tools/call","params":{"name":"a","Name":"b"}},{"method":"ping"}]`,
		`[{"method":"tools/call","params":{"name":"drive_get_file"}},` +
			`{"method":"tools/call","params":{"name":"drive_put_file"}}]`,
		`[{"method":"tools/call","params":{"name":"calendar_read"}},`,
		`[1,2`,
	}
}

func refMCPBatchDecision(ref refMCPPolicy, body []byte) refMCPDecision {
	elems, ok := refJSONArrayElements(body)
	if !ok {
		return refMCPDecision{kind: "reject"}
	}
	xs := make([]refMCPParsed, 0, len(elems))
	for _, e := range elems {
		xs = append(xs, refParseRPCMessage(e))
	}
	return refMCPCheckBatch(ref, xs)
}

func TestCheckBatchMatchesDafnyCheckBatch(t *testing.T) {
	for pi, p := range mcpFormalPolicies(t) {
		ref := refMCPPolicyFrom(p)
		for _, body := range mcpFormalBatchBodies() {
			got := mcpDecisionOf(p.checkBatch([]byte(body)))
			want := refMCPBatchDecision(ref, []byte(body))
			assert.Equal(t, want.kind, got.kind, "policy %d, body %s", pi, body)
			if want.kind == "deny" {
				assert.Equal(t, want.toolName, got.toolName, "policy %d, body %s", pi, body)
			}

			// M2 itself: forwarded only if every element is well-formed
			// and no element is a denied tools/call.
			elems, arrOK := refJSONArrayElements([]byte(body))
			allParsed := arrOK
			noDenied := true
			for _, e := range elems {
				m := refParseRPCMessage(e)
				if m.malformed {
					allParsed = false
					continue
				}
				if refMCPIsToolCall(m) && p.isToolDenied(m.toolName) {
					noDenied = false
				}
			}
			assert.Equal(t, allParsed && noDenied, got.kind == "forward",
				"policy %d, body %s", pi, body)
		}
	}
}

// One malformed element rejects the batch even when every other element
// is an allowed call, and one denied element denies it.
func TestBatchIsAllOrNothing(t *testing.T) {
	p, err := NewMCPToolPolicy(&MCPToolPolicyConfig{AllowedTools: []string{"calendar_*"}})
	require.NoError(t, err)

	good := `{"method":"tools/call","params":{"name":"calendar_read"}}`
	for _, bad := range []string{
		`{"method":123}`,
		`{"method":"tools/call"}`,
		`{"method":"tools/call","params":{"name":"a","Name":"b"}}`,
		`"bare"`,
		`null`,
	} {
		// The bad element in every position of a 3-element batch.
		for pos := 0; pos < 3; pos++ {
			elems := []string{good, good, good}
			elems[pos] = bad
			body := "[" + strings.Join(elems, ",") + "]"
			res, reason := p.checkBatch([]byte(body))
			assert.NotEmpty(t, reason, "body %s", body)
			assert.Nil(t, res, "body %s", body)
		}
	}
	for pos := 0; pos < 3; pos++ {
		elems := []string{good, good, good}
		elems[pos] = `{"method":"tools/call","params":{"name":"admin_delete"}}`
		body := "[" + strings.Join(elems, ",") + "]"
		res, reason := p.checkBatch([]byte(body))
		require.Empty(t, reason, "body %s", body)
		require.NotNil(t, res)
		assert.True(t, res.Denied, "body %s", body)
		assert.Equal(t, "admin_delete", res.ToolName)
	}
}

// =====================================================================
// 5. The enforcement path: Dafny M3, fail closed.
// =====================================================================

type mcpFormalUninspectable struct {
	name   string
	status int
	build  func() *http.Request
}

func mcpFormalPostJSON(body string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	return r
}

// mcpFormalRepeatReader streams a byte without materializing the body.
type mcpFormalRepeatReader struct {
	c    byte
	left int
}

func (r *mcpFormalRepeatReader) Read(p []byte) (int, error) {
	if r.left == 0 {
		return 0, io.EOF
	}
	n := len(p)
	if n > r.left {
		n = r.left
	}
	for i := 0; i < n; i++ {
		p[i] = r.c
	}
	r.left -= n
	return n, nil
}

func mcpFormalUninspectableRequests() []mcpFormalUninspectable {
	good := `{"method":"tools/call","params":{"name":"calendar_read"}}`
	return []mcpFormalUninspectable{
		{"content-encoding gzip", http.StatusUnsupportedMediaType, func() *http.Request {
			r := mcpFormalPostJSON(good)
			r.Header.Set("Content-Encoding", "gzip")
			return r
		}},
		{"content-encoding list with identity", http.StatusUnsupportedMediaType, func() *http.Request {
			r := mcpFormalPostJSON(good)
			r.Header.Set("Content-Encoding", "identity, br")
			return r
		}},
		{"two content-type headers", http.StatusBadRequest, func() *http.Request {
			r := mcpFormalPostJSON(good)
			r.Header.Add("Content-Type", "application/json")
			return r
		}},
		{"non-json content-type", http.StatusUnsupportedMediaType, func() *http.Request {
			r := mcpFormalPostJSON(good)
			r.Header.Set("Content-Type", "text/plain")
			return r
		}},
		{"non-utf8 charset", http.StatusUnsupportedMediaType, func() *http.Request {
			r := mcpFormalPostJSON(good)
			r.Header.Set("Content-Type", "application/json; charset=utf-16")
			return r
		}},
		{"declared content-length over cap", http.StatusRequestEntityTooLarge, func() *http.Request {
			r := mcpFormalPostJSON(good)
			r.ContentLength = maxMCPBodySize + 1
			return r
		}},
		{"streamed body over cap", http.StatusRequestEntityTooLarge, func() *http.Request {
			r := httptest.NewRequest(http.MethodPost, "/mcp",
				&mcpFormalRepeatReader{c: ' ', left: maxMCPBodySize + 1})
			r.Header.Set("Content-Type", "application/json")
			r.ContentLength = -1
			return r
		}},
		{"invalid utf-8 body", http.StatusBadRequest, func() *http.Request {
			return mcpFormalPostJSON("{\"method\":\"tools/call\",\"params\":{\"name\":\"\xff\xfe\"}}")
		}},
		{"malformed json", http.StatusBadRequest, func() *http.Request {
			return mcpFormalPostJSON(`{"method":"tools/call",`)
		}},
		{"duplicate method key", http.StatusBadRequest, func() *http.Request {
			return mcpFormalPostJSON(`{"method":"ping","method":"tools/call","params":{"name":"a"}}`)
		}},
		{"case-variant name key", http.StatusBadRequest, func() *http.Request {
			return mcpFormalPostJSON(`{"method":"tools/call","params":{"Name":"calendar_read"}}`)
		}},
		{"duplicate name key", http.StatusBadRequest, func() *http.Request {
			return mcpFormalPostJSON(`{"method":"tools/call","params":{"name":"admin_delete","Name":"calendar_read"}}`)
		}},
		{"unicode-escaped duplicate name key", http.StatusBadRequest, func() *http.Request {
			return mcpFormalPostJSON(`{"method":"tools/call","params":{"name":"admin_delete","name":"calendar_read"}}`)
		}},
		{"non-object message", http.StatusBadRequest, func() *http.Request {
			return mcpFormalPostJSON(`"tools/call"`)
		}},
		{"batch with a malformed element", http.StatusBadRequest, func() *http.Request {
			return mcpFormalPostJSON(`[{"method":"ping"},{"method":123}]`)
		}},
		{"batch that is not an array of objects", http.StatusBadRequest, func() *http.Request {
			return mcpFormalPostJSON(`[1,2]`)
		}},
		{"truncated batch", http.StatusBadRequest, func() *http.Request {
			return mcpFormalPostJSON(`[{"method":"ping"}`)
		}},
	}
}

func TestEnforceRequestNeverForwardsAnUninspectableBody(t *testing.T) {
	withRules, err := NewMCPToolPolicy(&MCPToolPolicyConfig{AllowedTools: []string{"calendar_*"}})
	require.NoError(t, err)
	require.True(t, withRules.hasToolRules())

	for _, c := range mcpFormalUninspectableRequests() {
		t.Run(c.name, func(t *testing.T) {
			res, err := withRules.CheckRequest(c.build())
			require.Error(t, err, "an uninspectable body must not be forwarded")
			assert.Nil(t, res, "no check result may be produced")
			var mcpErr *MCPRequestError
			require.ErrorAs(t, err, &mcpErr)
			assert.Equal(t, c.status, mcpErr.Status)
		})
	}
}

// The other side of M3's guard: with no tool rules the same bodies are
// forwarded, because there is nothing to enforce. Dafny ObserveRequest.
func TestPassThroughNeverRejects(t *testing.T) {
	passThrough, err := NewMCPToolPolicy(&MCPToolPolicyConfig{})
	require.NoError(t, err)
	require.False(t, passThrough.hasToolRules())

	for _, c := range mcpFormalUninspectableRequests() {
		t.Run(c.name, func(t *testing.T) {
			res, err := passThrough.CheckRequest(c.build())
			require.NoError(t, err)
			require.NotNil(t, res)
			assert.False(t, res.Denied)
		})
	}
}

// A non-POST request is forwarded uninspected, which is what the model
// says and why the request theorems are stated for POST.
func TestNonPostIsForwardedUninspected(t *testing.T) {
	p, err := NewMCPToolPolicy(&MCPToolPolicyConfig{AllowedTools: []string{"calendar_*"}})
	require.NoError(t, err)
	for _, m := range []string{http.MethodGet, http.MethodDelete} {
		r := httptest.NewRequest(m, "/mcp", nil)
		res, err := p.CheckRequest(r)
		require.NoError(t, err)
		require.NotNil(t, res)
		assert.False(t, res.Denied)
		assert.Empty(t, res.Method)
	}
}

// An empty body is inspectable, carries no call, and is forwarded.
func TestEmptyBodyIsForwardedWithNoCall(t *testing.T) {
	p, err := NewMCPToolPolicy(&MCPToolPolicyConfig{AllowedTools: []string{"calendar_*"}})
	require.NoError(t, err)
	for _, body := range []string{"", "   ", "\n\t "} {
		res, err := p.CheckRequest(mcpFormalPostJSON(body))
		require.NoError(t, err, "body %q", body)
		require.NotNil(t, res)
		assert.False(t, res.Denied)
		assert.Empty(t, res.Method)
	}
}

// Dafny M4 over the whole request path: a forwarded POST carries no
// tools/call the policy does not allow.
func TestForwardedRequestsCarryOnlyAllowedCalls(t *testing.T) {
	bodies := append(mcpFormalSingleBodies(), mcpFormalBatchBodies()...)
	for pi, p := range mcpFormalPolicies(t) {
		for _, body := range bodies {
			res, err := p.CheckRequest(mcpFormalPostJSON(body))
			if err != nil || res.Denied {
				continue // rejected or denied: not forwarded
			}
			for _, name := range mcpFormalCallNamesIn(body) {
				assert.True(t, p.isToolAllowed(name),
					"policy %d forwarded %s which calls %q", pi, body, name)
			}
		}
	}
}

// mcpFormalCallNamesIn mirrors Dafny ToolCallsIn: the tool names a body
// would have the upstream execute, read with the independent scanner.
func mcpFormalCallNamesIn(body string) []string {
	raw := []byte(strings.TrimSpace(body))
	if len(raw) == 0 {
		return nil
	}
	if raw[0] == '[' {
		elems, ok := refJSONArrayElements(raw)
		if !ok {
			return nil
		}
		var out []string
		for _, e := range elems {
			if m := refParseRPCMessage(e); refMCPIsToolCall(m) {
				out = append(out, m.toolName)
			}
		}
		return out
	}
	if m := refParseRPCMessage(raw); refMCPIsToolCall(m) {
		return []string{m.toolName}
	}
	return nil
}

// =====================================================================
// 6. tools/list filtering: Dafny L1 and L2.
// =====================================================================

// mcpFormalListEntry is a Dafny ToolEntry: Named carries a name the
// response filter can read, Unnamed is an entry that does not decode
// into {name string} and is preserved untouched.
type mcpFormalListEntry struct {
	raw   string
	named bool
	name  string
}

func mcpFormalListEntries() []mcpFormalListEntry {
	return []mcpFormalListEntry{
		{`{"name":"calendar_read","description":"r"}`, true, "calendar_read"},
		{`{"name":"calendar_write"}`, true, "calendar_write"},
		{`{"name":"admin_delete"}`, true, "admin_delete"},
		{`{"name":"drive_get_file"}`, true, "drive_get_file"},
		{`{"name":"exact_one"}`, true, "exact_one"},
		{`{"name":"xy"}`, true, "xy"},
		{`{"description":"no name at all"}`, true, ""},
		{`{"name":""}`, true, ""},
		{`"a bare string"`, false, ""},
		{`42`, false, ""},
		{`[1,2]`, false, ""},
		{`null`, true, ""},
	}
}

func mcpFormalToolsListBody(entries []mcpFormalListEntry) string {
	parts := make([]string, 0, len(entries))
	for _, e := range entries {
		parts = append(parts, e.raw)
	}
	return `{"jsonrpc":"2.0","id":1,"result":{"tools":[` +
		strings.Join(parts, ",") + `],"nextCursor":"c"}}`
}

func mcpFormalKeptNames(t *testing.T, body []byte) []string {
	t.Helper()
	var env struct {
		Result struct {
			Tools []json.RawMessage `json:"tools"`
		} `json:"result"`
	}
	require.NoError(t, json.Unmarshal(body, &env))
	var out []string
	for _, raw := range env.Result.Tools {
		var e struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(raw, &e); err != nil {
			continue // an Unnamed entry contributes no name
		}
		out = append(out, e.Name)
	}
	return out
}

func TestFilterToolsListMatchesDafnyFilterNames(t *testing.T) {
	entries := mcpFormalListEntries()
	body := mcpFormalToolsListBody(entries)

	// Dafny NamesOf: the upstream names, in order.
	var names []string
	for _, e := range entries {
		if e.named {
			names = append(names, e.name)
		}
	}

	for pi, p := range mcpFormalPolicies(t) {
		ref := refMCPPolicyFrom(p)
		fr, err := p.FilterToolsListResponse([]byte(body), "application/json")
		require.NoError(t, err)

		// allNames is NamesOf(entries) unchanged.
		assert.Equal(t, names, fr.AllTools, "policy %d", pi)

		// L1: allowedNames is FilterNames over the same predicate.
		want := refMCPFilterNames(ref, names)
		assert.Equal(t, want, fr.AllowedTools, "policy %d", pi)

		// L1 as the ascending index map: the kept names are the
		// upstream list read at strictly increasing allowed positions.
		idx := refMCPAllowedIdx(ref, names, 0)
		require.Equal(t, len(idx), len(fr.AllowedTools), "policy %d", pi)
		for j, i := range idx {
			assert.Equal(t, names[i], fr.AllowedTools[j], "policy %d", pi)
			assert.True(t, p.isToolAllowed(names[i]), "policy %d", pi)
			if j > 0 {
				assert.Less(t, idx[j-1], i, "index map must be ascending")
			}
		}
		for i, n := range names {
			inIdx := false
			for _, k := range idx {
				if k == i {
					inIdx = true
				}
			}
			assert.Equal(t, p.isToolAllowed(n), inIdx,
				"policy %d, position %d (%q)", pi, i, n)
		}

		// The emitted body carries exactly those names, in order, and
		// every entry with no readable name is preserved.
		assert.Equal(t, fr.AllowedTools, mcpFormalKeptNames(t, fr.Body), "policy %d", pi)
		for _, e := range entries {
			if !e.named {
				assert.Contains(t, string(fr.Body), e.raw,
					"policy %d dropped an entry it cannot read: %s", pi, e.raw)
			}
		}
		// Untouched sibling fields survive.
		assert.Contains(t, string(fr.Body), `"nextCursor":"c"`)
	}
}

// Dafny L2: a tool survives the list filter if and only if a tools/call
// naming it is forwarded. Both sides are isToolAllowed over the same
// path.Match, so they cannot drift.
func TestListingAndCallingAgree(t *testing.T) {
	for pi, p := range mcpFormalPolicies(t) {
		for _, name := range mcpFormalToolNames() {
			if name == "" || !json.Valid([]byte(`"`+name+`"`)) {
				continue
			}
			entry := mcpFormalListEntry{raw: `{"name":` + mcpFormalJSONQuote(name) + `}`, named: true, name: name}
			body := mcpFormalToolsListBody([]mcpFormalListEntry{entry})
			fr, err := p.FilterToolsListResponse([]byte(body), "application/json")
			require.NoError(t, err)
			listed := len(fr.AllowedTools) == 1

			call := `{"id":1,"method":"tools/call","params":{"name":` +
				mcpFormalJSONQuote(name) + `}}`
			res, reason := p.checkSingle([]byte(call))
			require.Empty(t, reason, "policy %d, tool %q", pi, name)
			forwarded := !res.Denied

			assert.Equal(t, listed, forwarded,
				"policy %d: tool %q listed=%v but forwarded=%v", pi, name, listed, forwarded)
			if !listed {
				assert.True(t, res.Denied, "a hidden tool must be denied when called")
				assert.Equal(t, name, res.ToolName)
			}
		}
	}
}

func mcpFormalJSONQuote(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// The listing request itself is never a tools/call, so it is forwarded
// in every mode; it is the response that is filtered.
func TestToolsListRequestIsAlwaysForwarded(t *testing.T) {
	for pi, p := range mcpFormalPolicies(t) {
		res, reason := p.checkSingle([]byte(`{"id":1,"method":"tools/list"}`))
		require.Empty(t, reason, "policy %d", pi)
		assert.False(t, res.Denied, "policy %d", pi)
		assert.Equal(t, "tools/list", res.Method, "policy %d", pi)
	}
}

// The response filter reads a tool name with encoding/json, which is
// case-insensitive and keeps the last duplicate, so a hostile upstream
// can make a LISTING misleading. It cannot make a CALL succeed: the
// request path reads the name strictly and independently. This is the
// gap docs/security.md records, pinned here so it cannot widen.
func TestListingNameAmbiguityCannotAuthorizeACall(t *testing.T) {
	p, err := NewMCPToolPolicy(&MCPToolPolicyConfig{AllowedTools: []string{"calendar_read"}})
	require.NoError(t, err)

	body := mcpFormalToolsListBody([]mcpFormalListEntry{
		{raw: `{"name":"admin_delete","Name":"calendar_read"}`, named: true, name: "calendar_read"},
	})
	fr, err := p.FilterToolsListResponse([]byte(body), "application/json")
	require.NoError(t, err)
	require.Equal(t, []string{"calendar_read"}, fr.AllowedTools)

	// The entry survived the listing, but neither reading of it can be
	// called: the strict request parser refuses the ambiguous name, and
	// the unambiguous hostile name is denied.
	res, reason := p.checkSingle([]byte(
		`{"method":"tools/call","params":{"name":"admin_delete","Name":"calendar_read"}}`))
	assert.NotEmpty(t, reason, "an ambiguous call must be refused outright")
	assert.Nil(t, res)

	res, reason = p.checkSingle([]byte(`{"method":"tools/call","params":{"name":"admin_delete"}}`))
	require.Empty(t, reason)
	assert.True(t, res.Denied)
}

// =====================================================================
// 7. The trusted parser, differentially.
//
// Ambiguity must be REJECTED, never decided. Each case below is an
// input where the shipped reading and a case-sensitive, duplicate-
// rejecting reading could differ.
// =====================================================================

func mcpFormalAmbiguousBodies() []string {
	return []string{
		// duplicate guarded keys, same case
		`{"method":"ping","method":"tools/call","params":{"name":"a"}}`,
		`{"method":"tools/call","params":{"name":"a"},"params":{"name":"b"}}`,
		`{"method":"tools/call","params":{"name":"a","name":"b"}}`,
		// case variants
		`{"Method":"tools/call","params":{"name":"a"}}`,
		`{"METHOD":"tools/call","params":{"name":"a"}}`,
		`{"method":"tools/call","Params":{"name":"a"}}`,
		`{"method":"tools/call","params":{"Name":"a"}}`,
		`{"method":"tools/call","params":{"NAME":"a"}}`,
		`{"method":"tools/call","params":{"nAmE":"a"}}`,
		// case variant alongside the real key
		`{"method":"tools/call","Method":"ping","params":{"name":"a"}}`,
		`{"method":"tools/call","params":{"name":"delete_all","Name":"read"}}`,
		`{"method":"tools/call","params":{"Name":"read","name":"delete_all"}}`,
		// unicode escapes that decode to a guarded key or a variant
		`{"method":"tools/call","params":{"name":"a"},"method":"ping"}`,
		`{"method":"tools/call","params":{"name":"a","name":"b"}}`,
		`{"Method":"tools/call","params":{"name":"a"}}`,
		`{"method":"tools/call","params":{"name":"a"},"params":{"name":"b"}}`,
		// Unicode simple folding: U+017F folds to 's'
		`{"method":"tools/call","param\u017f":{"name":"a"}}`,
		"{\"method\":\"tools/call\",\"paramſ\":{\"name\":\"a\"}}",
		`{"method":"tools/call","params":{"nam\u0065":"a","name":"b"}}`,
		"{\"method\":\"tools/call\",\"params\":{\"name\":\"a\",\"name\":\"b\"}}",
		// structurally undecidable
		`{"method":"tools/call","params":{"name":{"name":"a"}}}`,
		`{"method":"tools/call","params":[{"name":"a"}]}`,
		`{"method":"tools/call","params":"name=a"}`,
		`{"method":"tools/call","params":null}`,
		`{"method":"tools/call","params":{}}`,
		`{"method":"tools/call","params":{"name":null}}`,
		`{"method":"tools/call","params":{"name":true}}`,
		`{"method":"tools/call","params":{"name":0}}`,
		`{"method":"tools/call","params":{"name":[]}}`,
		`{"method":["tools/call"],"params":{"name":"a"}}`,
		`{"method":{"x":"tools/call"},"params":{"name":"a"}}`,
		// not an object, or not JSON at all
		`"tools/call"`,
		`123`,
		`true`,
		`null`,
		``,
		`   `,
		`{`,
		`{"method":"tools/call"} {"method":"ping"}`,
		`{"method":"tools/call"},`,
		`{"method":"tools/call",}`,
		`{,"method":"tools/call"}`,
		`{"method":01}`,
		`{"method":"tools/call","params":{"name":"a"}}extra`,
		"\ufeff" + `{"method":"tools/call","params":{"name":"a"}}`,
	}
}

// The inputs that are NOT ambiguous and must still be read correctly.
func mcpFormalUnambiguousBodies() []string {
	return []string{
		`{"method":"tools/call","params":{"name":"a"}}`,
		`  {"method":"tools/call","params":{"name":"a"}}  `,
		"{\n\t\"method\" : \"tools/call\" ,\n\t\"params\" : { \"name\" : \"a\" }\n}",
		`{"method":"tools\/call","params":{"name":"a"}}`,
		`{"method":"tools/call","params":{"name":"a"}}`,
		`{"method":"tools/call","params":{"name":"a"}}`,
		`{"method":"tools/call","params":{"name":"admin"}}`,
		`{"id":1,"jsonrpc":"2.0","method":"tools/call","params":{"name":"a","arguments":{"name":"inner"}}}`,
		`{"id":{"a":[1,2,{"b":null}]},"method":"tools/call","params":{"name":"a"}}`,
		`{"id":1,"ID":2,"method":"ping"}`,
		`{"jsonrpc":"2.0","JSONRPC":"2.0","method":"tools/list"}`,
		`{"method":"tools/list"}`,
		`{"method":null}`,
		`{"id":1,"method":null,"params":{"name":"a"}}`,
		`{"method":"initialize","params":{"name":"irrelevant","Name":"also"}}`,
		`{"id":1,"result":{"tools":[]}}`,
		`{}`,
		`{"params":{"name":"a"}}`,
	}
}

func TestParseRPCMessageRejectsPolicyRelevantAmbiguity(t *testing.T) {
	for _, body := range mcpFormalAmbiguousBodies() {
		msg, reason := parseRPCMessage([]byte(body))
		assert.NotEmpty(t, reason, "ambiguous body was decided instead of rejected: %q", body)
		assert.Nil(t, msg, "body %q", body)

		// And the independent reader agrees it is not decidable.
		assert.True(t, refParseRPCMessage([]byte(body)).malformed,
			"reference parser accepted %q", body)
	}
}

func TestParseRPCMessageMatchesIndependentReader(t *testing.T) {
	bodies := append(mcpFormalAmbiguousBodies(), mcpFormalUnambiguousBodies()...)
	bodies = append(bodies, mcpFormalSingleBodies()...)
	for _, body := range bodies {
		mcpFormalCompareParsers(t, []byte(body))
	}
}

func mcpFormalCompareParsers(t *testing.T, raw []byte) {
	t.Helper()
	msg, reason := parseRPCMessage(raw)
	ref := refParseRPCMessage(raw)

	if reason != "" {
		assert.True(t, ref.malformed,
			"shipped parser rejected but reference accepted: %q", raw)
		assert.Nil(t, msg)
		return
	}
	require.NotNil(t, msg)
	assert.False(t, ref.malformed,
		"shipped parser accepted but reference rejected: %q", raw)
	if ref.malformed {
		return
	}
	assert.Equal(t, ref.method, msg.method, "method for %q", raw)
	assert.Equal(t, ref.toolName, msg.toolName, "tool name for %q", raw)
	assert.Equal(t, string(ref.id), string(msg.id), "id for %q", raw)
}

func TestDecodeStrictObjectMatchesIndependentScanner(t *testing.T) {
	bodies := append(mcpFormalAmbiguousBodies(), mcpFormalUnambiguousBodies()...)
	for _, body := range bodies {
		raw := []byte(body)
		got, gotReason := decodeStrictObject(raw, "method", "params")
		ref, refReason := refDecodeStrictObject(raw, "method", "params")
		assert.Equal(t, refReason == "", gotReason == "",
			"accept/reject disagreement on %q (shipped %q, reference %q)", body, gotReason, refReason)
		if gotReason != "" || refReason != "" {
			continue
		}
		for _, k := range []string{"method", "params", "id"} {
			assert.Equal(t, string(ref[k]), string(got[k]), "field %q of %q", k, body)
		}
		assert.Equal(t, len(ref), len(got), "field count of %q", body)
	}
	// json.Valid and the independent scanner agree on the whole corpus.
	for _, body := range bodies {
		assert.Equal(t, json.Valid([]byte(body)), refValidJSON([]byte(body)),
			"validity disagreement on %q", body)
	}
}

// A null method is read as no method at all. Nothing is executed by
// either reading, and a null params.name is still refused because the
// non-empty check catches it.
func TestNullMethodIsReadAsNoMethod(t *testing.T) {
	msg, reason := parseRPCMessage([]byte(`{"id":1,"method":null}`))
	require.Empty(t, reason)
	require.NotNil(t, msg)
	assert.Empty(t, msg.method)
	assert.Empty(t, msg.toolName)
	assert.Empty(t, mcpFormalCallNamesIn(`{"id":1,"method":null}`),
		"a null method must carry no tool call")

	// params.name null is refused: the parser requires a non-empty name.
	_, reason = parseRPCMessage([]byte(`{"method":"tools/call","params":{"name":null}}`))
	assert.NotEmpty(t, reason)

	// And with tool rules set, neither body is ever a forwarded call.
	p, err := NewMCPToolPolicy(&MCPToolPolicyConfig{AllowedTools: []string{"calendar_*"}})
	require.NoError(t, err)
	res, reason := p.checkSingle([]byte(`{"id":1,"method":null}`))
	require.Empty(t, reason)
	assert.False(t, res.Denied)
	assert.Empty(t, res.Method)
}

// =====================================================================
// 8. Bounded randomized parser differential.
//
// 2000 cases, generated and compared one at a time, nothing collected.
// =====================================================================

var mcpFormalRandKeys = []string{
	`"method"`, `"Method"`, `"METHOD"`, `"method"`, `"Method"`,
	`"params"`, `"Params"`, `"param\u017f"`, `"para\u006ds"`,
	`"name"`, `"Name"`, `"NAME"`, `"\u006eame"`, `"nam\u0065"`,
	`"id"`, `"ID"`, `"jsonrpc"`, `""`, `"x"`, `"\ud83d\ude00"`, `"\ud800"`,
}

var mcpFormalRandValues = []string{
	`"tools/call"`, `"tools\/call"`, `"tools/call"`, `"tools/list"`,
	`"ping"`, `""`, `"admin_delete"`, `"calendar_read"`, `"admin_delete"`,
	`123`, `-0.5e2`, `0`, `true`, `false`, `null`,
	`{"name":"inner"}`, `{"name":"a","Name":"b"}`, `{}`,
	`[1,"two",{"name":"deep"}]`, `[]`,
}

var mcpFormalWS = []string{"", " ", "\n", "\t", "  \n ", "\r"}

func mcpFormalRandomObject(rng *rand.Rand) string {
	var sb strings.Builder
	sb.WriteString("{")
	n := rng.Intn(5)
	for i := 0; i < n; i++ {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(mcpFormalWS[rng.Intn(len(mcpFormalWS))])
		sb.WriteString(mcpFormalRandKeys[rng.Intn(len(mcpFormalRandKeys))])
		sb.WriteString(mcpFormalWS[rng.Intn(len(mcpFormalWS))])
		sb.WriteString(":")
		sb.WriteString(mcpFormalWS[rng.Intn(len(mcpFormalWS))])
		sb.WriteString(mcpFormalRandValues[rng.Intn(len(mcpFormalRandValues))])
	}
	sb.WriteString(mcpFormalWS[rng.Intn(len(mcpFormalWS))])
	sb.WriteString("}")
	return sb.String()
}

func mcpFormalCorrupt(rng *rand.Rand, s string) string {
	if len(s) == 0 {
		return s
	}
	switch rng.Intn(6) {
	case 0:
		return s[:rng.Intn(len(s))]
	case 1:
		return s + "garbage"
	case 2:
		i := rng.Intn(len(s))
		return s[:i] + s[i:i+1] + s[i:]
	case 3:
		return "\ufeff" + s
	case 4:
		i := rng.Intn(len(s))
		return s[:i] + s[i+1:]
	default:
		return s + ","
	}
}

func TestParseRPCMessageRandomizedDifferential(t *testing.T) {
	const iterations = 2000 // bounded: fixed count, one case at a time
	rng := rand.New(rand.NewSource(0x6d637001))
	for i := 0; i < iterations; i++ {
		body := mcpFormalRandomObject(rng)
		if rng.Intn(4) == 0 {
			// A batch of 0..3 of these.
			parts := make([]string, 0, 3)
			for k := rng.Intn(4); k > 0; k-- {
				parts = append(parts, mcpFormalRandomObject(rng))
			}
			body = "[" + strings.Join(parts, ",") + "]"
		}
		if rng.Intn(5) == 0 {
			body = mcpFormalCorrupt(rng, body)
		}
		raw := []byte(body)
		if !utf8.Valid(raw) {
			// enforceRequest rejects a non-UTF-8 body before parsing,
			// so the parser is never offered one.
			continue
		}
		require.Equal(t, json.Valid(raw), refValidJSON(raw),
			"validity disagreement on %q", body)
		if len(raw) > 0 && bytes.TrimSpace(raw)[0] == '[' {
			mcpFormalCompareBatches(t, bytes.TrimSpace(raw))
			continue
		}
		mcpFormalCompareParsers(t, raw)
	}
}

func mcpFormalCompareBatches(t *testing.T, raw []byte) {
	t.Helper()
	p, err := NewMCPToolPolicy(&MCPToolPolicyConfig{AllowedTools: []string{"calendar_*"}})
	require.NoError(t, err)
	ref := refMCPPolicyFrom(p)
	got := mcpDecisionOf(p.checkBatch(raw))
	want := refMCPBatchDecision(ref, raw)
	assert.Equal(t, want.kind, got.kind, "batch %q", raw)
	if want.kind == "deny" {
		assert.Equal(t, want.toolName, got.toolName, "batch %q", raw)
	}
}

// Bounded sweep over the whole request path: every corpus body against
// every corpus policy, checked against the model's decision.
func TestCheckRequestMatchesDafnyDecision(t *testing.T) {
	bodies := append(mcpFormalSingleBodies(), mcpFormalBatchBodies()...)
	bodies = append(bodies, mcpFormalUnambiguousBodies()...)
	bodies = append(bodies, mcpFormalAmbiguousBodies()...)

	for pi, p := range mcpFormalPolicies(t) {
		ref := refMCPPolicyFrom(p)
		for _, body := range bodies {
			raw := []byte(strings.TrimSpace(body))
			res, err := p.CheckRequest(mcpFormalPostJSON(body))

			var want refMCPDecision
			switch {
			case !p.hasToolRules():
				want = refMCPForward("")
			case len(raw) == 0:
				want = refMCPForward("")
			case !utf8.Valid(raw):
				want = refMCPDecision{kind: "reject"}
			case raw[0] == '[':
				want = refMCPBatchDecision(ref, raw)
			default:
				want = refMCPCheckSingle(ref, refParseRPCMessage(raw))
			}

			var got refMCPDecision
			switch {
			case err != nil:
				var mcpErr *MCPRequestError
				require.ErrorAs(t, err, &mcpErr, "body %q", body)
				got = refMCPDecision{kind: "reject"}
			case res.Denied:
				got = refMCPDecision{kind: "deny", toolName: res.ToolName}
			default:
				got = refMCPForward(res.Method)
			}

			assert.Equal(t, want.kind, got.kind, "policy %d, body %q", pi, body)
			if want.kind == "deny" {
				assert.Equal(t, want.toolName, got.toolName, "policy %d, body %q", pi, body)
			}
		}
	}
}
