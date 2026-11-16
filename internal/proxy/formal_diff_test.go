package proxy

// Differential tests tying the shipped code to the Dafny models in formal/.
//
// Each reference implementation below mirrors one Dafny definition line
// for line and is named after it. The Dafny proofs are statements ABOUT
// these definitions; these tests are what makes them statements about
// the shipped functions too. If someone changes splitPath, the glob
// matcher or either redactor without updating formal/, one of these
// tests fails.
//
// Two deliberate modelling notes:
//
//   - The Dafny models use `string`, a sequence of characters. The
//     redaction proofs never inspect an element except to compare it
//     with '[' or ']', so they hold over sequences of any element type
//     with those two values distinguished. Both brackets are single-byte
//     ASCII, so the results transfer to Go's []byte, which is what the
//     redactors operate on. The reference implementations below are
//     therefore written on []byte for redaction and on string (indexed
//     by byte) for path splitting, where '/' is likewise ASCII.
//
//   - prepareRedactTokens' ordering (longest first, lexicographic
//     tiebreak) is NOT part of the Dafny model. Neither theorem needs
//     it: both hold for any token order, and the streaming and one-shot
//     sides are always given the same order. These tests pass the real
//     prepareRedactTokens output to both sides.

import (
	"bytes"
	"math/rand"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =====================================================================
// Reference implementations of the path / glob model (formal/path.dfy,
// formal/glob.dfy).
// =====================================================================

// refIndexOfSlash mirrors Dafny IndexOfSlash (formal/path.dfy).
func refIndexOfSlash(p string) int {
	if len(p) == 0 {
		return 0
	}
	if p[0] == '/' {
		return 0
	}
	return 1 + refIndexOfSlash(p[1:])
}

// refSplitPath mirrors Dafny SplitPath (formal/path.dfy).
func refSplitPath(p string) []string {
	if len(p) == 0 {
		return nil
	}
	i := refIndexOfSlash(p)
	if i == len(p) {
		return []string{p}
	}
	head := p[:i]
	tail := refSplitPath(p[i+1:])
	if len(head) == 0 {
		return tail
	}
	return append([]string{head}, tail...)
}

// refMatchSeg mirrors Dafny MatchSeg (formal/path.dfy).
func refMatchSeg(pat, seg string) bool {
	if pat == "*" {
		return seg != ""
	}
	return pat == seg
}

// refMatches mirrors Dafny Matches (formal/glob.dfy), the DECLARATIVE
// glob semantics the shipped DP is proved equal to.
func refMatches(pat, path []string) bool {
	if len(pat) == 0 {
		return len(path) == 0
	}
	if pat[0] == "**" {
		if refMatches(pat[1:], path) {
			return true
		}
		return len(path) > 0 && refMatches(pat, path[1:])
	}
	return len(path) > 0 && refMatchSeg(pat[0], path[0]) && refMatches(pat[1:], path[1:])
}

// refCollapseAcc mirrors Dafny CollapseAcc (formal/glob.dfy).
func refCollapseAcc(out, parts []string) []string {
	if len(parts) == 0 {
		return out
	}
	if parts[0] == "**" && len(out) > 0 && out[len(out)-1] == "**" {
		return refCollapseAcc(out, parts[1:])
	}
	return refCollapseAcc(append(append([]string{}, out...), parts[0]), parts[1:])
}

// refCollapseDoublestar mirrors Dafny CollapseDoublestar (formal/glob.dfy).
func refCollapseDoublestar(parts []string) []string {
	return refCollapseAcc(nil, parts)
}

// refMatchSegmentsSpec is Dafny MatchSegmentsDP's POSTCONDITION
// (formal/glob.dfy): deny above either cap, otherwise agree with the
// declarative semantics.
func refMatchSegmentsSpec(pattern, path []string) bool {
	if len(pattern) > maxPatternSegments || len(path) > maxPathSegments {
		return false
	}
	return refMatches(pattern, path)
}

// refMatchPattern mirrors Dafny MatchPattern (formal/glob.dfy).
func refMatchPattern(pattern, path string) bool {
	patParts := refCollapseDoublestar(refSplitPath(pattern))
	pathParts := refSplitPath(path)
	return refMatchSegmentsSpec(patParts, pathParts)
}

// =====================================================================
// Reference implementations of the redaction model (formal/redact.dfy,
// formal/stream.dfy).
// =====================================================================

var refPH = []byte("[REDACTED]")

// refBracketFree mirrors Dafny BracketFree (formal/redact.dfy).
func refBracketFree(t []byte) bool {
	for _, c := range t {
		if c == '[' || c == ']' {
			return false
		}
	}
	return true
}

// refContainsAnyMeta mirrors Dafny ContainsAnyMeta (formal/redact.dfy).
func refContainsAnyMeta(t []byte) bool {
	for _, c := range t {
		if c == '[' || c == ']' {
			return true
		}
	}
	return false
}

// refOccursAt mirrors Dafny OccursAt (formal/redact.dfy).
func refOccursAt(hay, needle []byte, i int) bool {
	return i+len(needle) <= len(hay) && bytes.Equal(hay[i:i+len(needle)], needle)
}

// refOccurs mirrors Dafny Occurs (formal/redact.dfy). The existential is
// bounded by |hay|, so it is decided by a scan.
func refOccurs(hay, needle []byte) bool {
	for i := 0; i <= len(hay); i++ {
		if refOccursAt(hay, needle, i) {
			return true
		}
	}
	return false
}

// refSubstringOfPlaceholder mirrors Dafny SubstringOfPlaceholder
// (formal/redact.dfy): Occurs(PH, t).
func refSubstringOfPlaceholder(t []byte) bool {
	return refOccurs(refPH, t)
}

// refRedactionSafe mirrors Dafny RedactionSafe (formal/redact.dfy), the
// model of the shipped redactionSafe.
func refRedactionSafe(secrets []string) bool {
	for _, s := range secrets {
		if refContainsAnyMeta([]byte(s)) || refSubstringOfPlaceholder([]byte(s)) {
			return false
		}
	}
	return true
}

// refRedactableTok mirrors Dafny RedactableTok (formal/redact.dfy), the
// precondition of the redaction theorems.
func refRedactableTok(t []byte) bool {
	return len(t) > 0 && refBracketFree(t) && !refOccurs(refPH, t)
}

// refReplaceAll mirrors Dafny ReplaceAll (formal/redact.dfy): leftmost
// first, non-overlapping, one character at a time.
func refReplaceAll(s, pat, nw []byte) []byte {
	if len(s) < len(pat) {
		return s
	}
	if bytes.Equal(s[:len(pat)], pat) {
		return append(append([]byte{}, nw...), refReplaceAll(s[len(pat):], pat, nw)...)
	}
	return append([]byte{s[0]}, refReplaceAll(s[1:], pat, nw)...)
}

// refOneShot mirrors Dafny OneShot (formal/redact.dfy), the model of
// redactAll.
func refOneShot(s []byte, toks [][]byte) []byte {
	if len(toks) == 0 {
		return s
	}
	return refOneShot(refReplaceAll(s, toks[0], refPH), toks[1:])
}

// refIndexOf mirrors Dafny IndexOf (formal/stream.dfy).
func refIndexOf(hay, needle []byte) int {
	if len(hay) < len(needle) {
		return -1
	}
	if bytes.Equal(hay[:len(needle)], needle) {
		return 0
	}
	r := refIndexOf(hay[1:], needle)
	if r < 0 {
		return -1
	}
	return r + 1
}

// refTPSLFrom mirrors Dafny TPSLFrom (formal/stream.dfy).
func refTPSLFrom(b, tok []byte, k int) int {
	if k == 0 {
		return 0
	}
	if bytes.HasPrefix(tok, b[len(b)-k:]) {
		return k
	}
	return refTPSLFrom(b, tok, k-1)
}

// refTPSL mirrors Dafny TPSL (formal/stream.dfy), the model of
// tokenPrefixSuffixLen.
func refTPSL(b, tok []byte) int {
	top := len(b)
	if len(tok)-1 < top {
		top = len(tok) - 1
	}
	return refTPSLFrom(b, tok, top)
}

// refScanReplace mirrors Dafny ScanReplace (formal/stream.dfy), the loop
// inside tokenReplacer.push. Returns (emitted, unscanned remainder).
func refScanReplace(buf, tok []byte) ([]byte, []byte) {
	idx := refIndexOf(buf, tok)
	if idx < 0 {
		return nil, buf
	}
	out, rest := refScanReplace(buf[idx+len(tok):], tok)
	emitted := append([]byte{}, buf[:idx]...)
	emitted = append(emitted, refPH...)
	emitted = append(emitted, out...)
	return emitted, rest
}

// refRepl mirrors Dafny Repl (formal/stream.dfy), the model of
// tokenReplacer.
type refRepl struct {
	tok  []byte
	held []byte
}

// refPushRepl mirrors Dafny PushRepl (formal/stream.dfy).
func refPushRepl(r refRepl, data []byte) (refRepl, []byte) {
	buf := append(append([]byte{}, r.held...), data...)
	scanned, rest := refScanReplace(buf, r.tok)
	k := refTPSL(rest, r.tok)
	m := len(rest) - k
	out := append(append([]byte{}, scanned...), rest[:m]...)
	return refRepl{tok: r.tok, held: append([]byte{}, rest[m:]...)}, out
}

// refFlushRepl mirrors Dafny FlushRepl (formal/stream.dfy).
func refFlushRepl(r refRepl) (refRepl, []byte) {
	return refRepl{tok: r.tok}, r.held
}

// refPushCascade mirrors Dafny PushCascade (formal/stream.dfy), the
// model of streamRedactor.push.
func refPushCascade(st []refRepl, data []byte) ([]refRepl, []byte) {
	if len(st) == 0 {
		return st, data
	}
	r0, out := refPushRepl(st[0], data)
	rest, out2 := refPushCascade(st[1:], out)
	return append([]refRepl{r0}, rest...), out2
}

// refFlushCascade mirrors Dafny FlushCascade (formal/stream.dfy), the
// model of streamRedactor.flush.
func refFlushCascade(st []refRepl) ([]refRepl, []byte) {
	if len(st) == 0 {
		return st, nil
	}
	f, held := refFlushRepl(st[0])
	pushed, out := refPushCascade(st[1:], held)
	drained, out2 := refFlushCascade(pushed)
	return append([]refRepl{f}, drained...), append(append([]byte{}, out...), out2...)
}

// refRunCascade mirrors Dafny RunCascade (formal/stream.dfy).
func refRunCascade(st []refRepl, chunks [][]byte) ([]refRepl, []byte) {
	if len(chunks) == 0 {
		return st, nil
	}
	st1, o1 := refPushCascade(st, chunks[0])
	st2, o2 := refRunCascade(st1, chunks[1:])
	return st2, append(append([]byte{}, o1...), o2...)
}

// refInitCascade mirrors Dafny InitCascade (formal/stream.dfy).
func refInitCascade(toks [][]byte) []refRepl {
	st := make([]refRepl, 0, len(toks))
	for _, t := range toks {
		st = append(st, refRepl{tok: t})
	}
	return st
}

// refStreamOut mirrors Dafny StreamOut (formal/stream.dfy): push every
// chunk, then flush once.
func refStreamOut(toks [][]byte, chunks [][]byte) []byte {
	st, out := refRunCascade(refInitCascade(toks), chunks)
	_, f := refFlushCascade(st)
	return append(append([]byte{}, out...), f...)
}

// =====================================================================
// Corpora
// =====================================================================

func formalPathCorpus() []string {
	paths := []string{
		"", "/", "//", "///", "a", "/a", "a/", "/a/", "/a//b", "a//b//c",
		"/v1/chat/completions", "/v1//chat/completions", "v1/chat/completions/",
		"/users/123/detail", "/repos/o/r/git/refs/heads/main",
		"/*", "/**", "/a/*/b", "/a/**/b", "/**/**", "/**/**/**",
		"/a/**/**/b", "**", "*", "/a/*", "/a/**", "/*/*/*",
		"/x/**/**/**/y", "/**/a/**", "/a/b/**/**",
		"/trailing/slash/", "//leading//double//", "/mixed//*//**//x",
	}
	// Deep paths around the 256-segment cap.
	for _, n := range []int{1, 2, 63, 64, 65, 255, 256, 257, 300} {
		paths = append(paths, "/"+strings.TrimSuffix(strings.Repeat("s/", n), "/"))
	}
	// Deep ** patterns around the 64-segment pattern cap.
	for _, n := range []int{63, 64, 65} {
		paths = append(paths, "/"+strings.TrimSuffix(strings.Repeat("**/", n), "/"))
	}
	return paths
}

func formalRandomPath(rng *rand.Rand) string {
	alphabet := []string{"a", "b", "v1", "*", "**", "", "x"}
	n := rng.Intn(7)
	var sb strings.Builder
	for i := 0; i < n; i++ {
		sb.WriteString("/")
		sb.WriteString(alphabet[rng.Intn(len(alphabet))])
	}
	if sb.Len() == 0 {
		return "/"
	}
	if rng.Intn(4) == 0 {
		sb.WriteString("/")
	}
	return sb.String()
}

// randomChunking splits body into a random sequence of pieces, including
// empty ones. The Dafny theorem is quantified over all chunkings, so any
// of these must give the same answer.
func randomChunking(rng *rand.Rand, body []byte) [][]byte {
	var chunks [][]byte
	i := 0
	for i < len(body) {
		n := rng.Intn(4)
		if i+n > len(body) {
			n = len(body) - i
		}
		chunks = append(chunks, body[i:i+n])
		i += n
	}
	if len(body) == 0 {
		chunks = append(chunks, nil)
	}
	return chunks
}

// =====================================================================
// splitPath  <->  Dafny SplitPath
//
// This test also discharges the one step formal/path.dfy cannot prove
// for itself: that Go's strings.Trim + strings.Split + drop-empty
// pipeline is the same sequence as splitting on every '/' and dropping
// the empty pieces.
// =====================================================================

func TestSplitPathMatchesDafnySplitPath(t *testing.T) {
	check := func(p string) {
		got := splitPath(p)
		want := refSplitPath(p)
		assert.Equal(t, len(want), len(got), "segment count for %q", p)
		if len(want) == len(got) {
			for i := range want {
				assert.Equal(t, want[i], got[i], "segment %d of %q", i, p)
			}
		}
	}
	for _, p := range formalPathCorpus() {
		check(p)
	}
	rng := rand.New(rand.NewSource(1001))
	for i := 0; i < 4000; i++ {
		check(formalRandomPath(rng))
	}
}

// SplitPathNoEmpty / StarNeverMatchesEmptySegment, on real data.
func TestSplitPathNeverYieldsEmptySegment(t *testing.T) {
	rng := rand.New(rand.NewSource(0xe3917))
	paths := formalPathCorpus()
	for i := 0; i < 2000; i++ {
		paths = append(paths, formalRandomPath(rng))
	}
	for _, p := range paths {
		for i, seg := range splitPath(p) {
			require.NotEmpty(t, seg, "splitPath(%q)[%d] is empty", p, i)
			// MatchSeg("*", seg) therefore always holds.
			assert.True(t, matchSegment("*", seg), "'*' must match %q", seg)
		}
	}
	// And the local form of the property.
	assert.False(t, matchSegment("*", ""), "'*' must never match an empty segment")
}

// =====================================================================
// collapseDoublestar  <->  Dafny CollapseAcc
// =====================================================================

func TestCollapseDoublestarMatchesDafnyCollapseAcc(t *testing.T) {
	rng := rand.New(rand.NewSource(0xc0115))
	var corpus [][]string
	for _, p := range formalPathCorpus() {
		corpus = append(corpus, splitPath(p))
	}
	for i := 0; i < 3000; i++ {
		n := rng.Intn(8)
		parts := make([]string, 0, n)
		for j := 0; j < n; j++ {
			parts = append(parts, []string{"a", "*", "**", "**", "b"}[rng.Intn(5)])
		}
		corpus = append(corpus, parts)
	}
	for _, parts := range corpus {
		got := collapseDoublestar(parts)
		want := refCollapseDoublestar(parts)
		assert.Equal(t, len(want), len(got), "collapse length for %v", parts)
		if len(want) == len(got) {
			for i := range want {
				assert.Equal(t, want[i], got[i], "collapse elem %d of %v", i, parts)
			}
		}
	}
}

func TestMatchSegmentMatchesDafnyMatchSeg(t *testing.T) {
	segs := []string{"", "*", "**", "a", "ab", "/"}
	for _, pat := range segs {
		for _, seg := range segs {
			assert.Equal(t, refMatchSeg(pat, seg), matchSegment(pat, seg),
				"matchSegment(%q, %q)", pat, seg)
		}
	}
}

// =====================================================================
// matchPattern  <->  Dafny MatchPattern
//
// Covers the whole shipped composition: splitPath, then
// collapseDoublestar, then the bottom-up DP, against the declarative
// glob semantics with the caps applied.
// =====================================================================

func TestMatchPatternMatchesDafnyGlobSemantics(t *testing.T) {
	corpus := formalPathCorpus()
	rng := rand.New(rand.NewSource(0x9106))
	for i := 0; i < 600; i++ {
		corpus = append(corpus, formalRandomPath(rng))
	}
	for _, pattern := range corpus {
		for _, path := range corpus {
			assert.Equal(t, refMatchPattern(pattern, path), matchPattern(pattern, path),
				"matchPattern(%q, %q)", pattern, path)
		}
	}
}

// The G3 claim on real data: collapsing consecutive '**' does not change
// the accepted language, so matchPattern agrees with the declarative
// semantics of the UNCOLLAPSED pattern whenever the caps allow.
func TestCollapsingDoubleStarPreservesGlobSemantics(t *testing.T) {
	corpus := formalPathCorpus()
	rng := rand.New(rand.NewSource(1002))
	for i := 0; i < 600; i++ {
		corpus = append(corpus, formalRandomPath(rng))
	}
	for _, pattern := range corpus {
		patParts := refSplitPath(pattern)
		collapsed := refCollapseDoublestar(patParts)
		if len(collapsed) > maxPatternSegments {
			continue
		}
		for _, path := range corpus {
			pathParts := refSplitPath(path)
			if len(pathParts) > maxPathSegments {
				continue
			}
			assert.Equal(t, refMatches(patParts, pathParts), matchPattern(pattern, path),
				"matchPattern(%q, %q) vs declarative semantics of the uncollapsed pattern",
				pattern, path)
		}
	}
}

// =====================================================================
// AccessPolicy.Allowed  <->  formal/policy.dfy
// =====================================================================

func TestAllowedMatchesDafnyPolicyContract(t *testing.T) {
	rules := []AccessRuleInput{
		{Action: "ALLOW", Method: "GET", Path: "/v1/*/read"},
		{Action: "DENY", Method: "POST", Path: "/v1/**"},
		{Action: "ALLOW", Method: "ALL", Path: "/v1/**"},
		{Action: "DENY", Method: "ALL", Path: "/**"},
	}
	p, err := NewAccessPolicy(rules, false)
	require.NoError(t, err)

	methods := []string{"GET", "POST", "PUT"}
	paths := append(formalPathCorpus(),
		"/v1/a/read", "/v1/a/write", "/v1/x/y/z", "/other/thing")

	for _, method := range methods {
		for _, path := range paths {
			got := p.Allowed(method, path)

			// P4: the cap denies before any rule is consulted.
			if len(refSplitPath(path)) > maxPathSegments {
				assert.False(t, got, "over-cap path %q must be denied", path)
				continue
			}

			// P1 / P2: find the first applicable rule in the model and
			// require the decision to be exactly its action.
			firstMatch := -1
			for i, r := range rules {
				if r.Method != "ALL" && r.Method != method {
					continue
				}
				if refMatchPattern(r.Path, path) {
					firstMatch = i
					break
				}
			}
			if firstMatch < 0 {
				assert.False(t, got, "implicit deny expected for %s %q", method, path)
			} else {
				assert.Equal(t, rules[firstMatch].Action == "ALLOW", got,
					"first-match-wins: %s %q should follow rule %d", method, path, firstMatch)
			}
		}
	}
}

// P2b: explicit deny-all denies everything. P2c: no rules allows
// everything (reachable only with strict: false, see policy.dfy).
func TestAllowedDenyAllAndNoRules(t *testing.T) {
	denyAll, err := NewAccessPolicy(nil, true)
	require.NoError(t, err)
	noRules, err := NewAccessPolicy(nil, false)
	require.NoError(t, err)
	for _, path := range formalPathCorpus() {
		assert.False(t, denyAll.Allowed("GET", path), "denyAll must deny %q", path)
		assert.True(t, noRules.Allowed("GET", path), "no rules must allow %q", path)
	}
}

// P4 in the form the model states it: even a rule list that would allow
// everything cannot rescue an over-cap path.
func TestAllowedCapDeniesBeforeAnyRule(t *testing.T) {
	p, err := NewAccessPolicy([]AccessRuleInput{
		{Action: "ALLOW", Method: "ALL", Path: "/**"},
		{Action: "ALLOW", Method: "ALL", PathRegex: ".*"},
	}, false)
	require.NoError(t, err)

	under := "/" + strings.TrimSuffix(strings.Repeat("s/", maxPathSegments), "/")
	over := "/" + strings.TrimSuffix(strings.Repeat("s/", maxPathSegments+1), "/")
	require.Equal(t, maxPathSegments, len(splitPath(under)))
	require.Equal(t, maxPathSegments+1, len(splitPath(over)))

	assert.True(t, p.Allowed("GET", under), "at the cap the allow rules still apply")
	assert.False(t, p.Allowed("GET", over), "over the cap must be denied")
}

// =====================================================================
// redactAll  <->  Dafny OneShot
// =====================================================================

func formalSecretCorpus() [][]string {
	return [][]string{
		{"sk-abc"},
		{"aa"},
		{"a"},
		{"ab", "b"},
		{"abc", "bc", "c"},
		{"Bearer sk-abc", "sk-abc"},
		{"RED"},
		{"REDACTED"},
		{"EDA"},
		{"xy", "yx"},
		{"aba"},
		{"abab"},
		{"secret", "cret", "et"},
	}
}

func formalBodyCorpus() []string {
	return []string{
		"", "a", "aa", "aaa", "aaaa", "ab", "abab", "ababab",
		"sk-abc", "xsk-abcx", "sk-absk-abc", "Bearer sk-abc here",
		"REDACTED", "[REDACTED]", "a[REDACTED]b", "REDREDRED",
		"abcabcabc", "aabbaabb", "abababa", "secretcretet",
		"xyyxxy", "data: sk-abc\n\ndata: sk-abc\n\n",
		"\x00sk-abc\xff", "aba aba aba", "ababa",
	}
}

func TestRedactAllMatchesDafnyOneShot(t *testing.T) {
	for _, secrets := range formalSecretCorpus() {
		toks := prepareRedactTokens(secrets)
		require.NotNil(t, toks)
		for _, body := range formalBodyCorpus() {
			got := redactAll(toks, []byte(body))
			want := refOneShot([]byte(body), toks)
			assert.Equal(t, string(want), string(got),
				"redactAll(%v, %q)", secrets, body)
		}
	}
}

func TestTokenPrefixSuffixLenMatchesDafnyTPSL(t *testing.T) {
	toks := []string{"a", "ab", "abc", "aba", "abab", "sk-abc", "REDACTED"}
	bufs := []string{
		"", "a", "ab", "aba", "abab", "x", "xa", "xab", "xaba",
		"sk-ab", "sk-abc", "REDACT", "aaa", "ababa",
	}
	for _, tok := range toks {
		for _, b := range bufs {
			got := tokenPrefixSuffixLen([]byte(b), []byte(tok))
			want := refTPSL([]byte(b), []byte(tok))
			assert.Equal(t, want, got, "tokenPrefixSuffixLen(%q, %q)", b, tok)
		}
	}
}

// =====================================================================
// streamRedactor  <->  Dafny StreamOut
// =====================================================================

func TestStreamRedactorMatchesDafnyStreamOut(t *testing.T) {
	rng := rand.New(rand.NewSource(1003))
	for _, secrets := range formalSecretCorpus() {
		toks := prepareRedactTokens(secrets)
		require.NotNil(t, toks)
		for _, body := range formalBodyCorpus() {
			for trial := 0; trial < 12; trial++ {
				chunks := randomChunking(rng, []byte(body))

				sr := newStreamRedactor(toks)
				var got []byte
				for _, c := range chunks {
					got = append(got, sr.push(c)...)
				}
				got = append(got, sr.flush()...)

				want := refStreamOut(toks, chunks)
				assert.Equal(t, string(want), string(got),
					"streamRedactor over %v, body %q, chunks %q", secrets, body, chunks)
			}
		}
	}
}

// S1 on real data: streamed output equals one-shot output, for every
// chunking tried. This is the shipped-code form of StreamEqualsOneShot.
func TestStreamedRedactionEqualsOneShot(t *testing.T) {
	rng := rand.New(rand.NewSource(1004))
	for _, secrets := range formalSecretCorpus() {
		toks := prepareRedactTokens(secrets)
		require.NotNil(t, toks)
		for _, body := range formalBodyCorpus() {
			oneShot := redactAll(toks, []byte(body))
			for trial := 0; trial < 20; trial++ {
				chunks := randomChunking(rng, []byte(body))
				sr := newStreamRedactor(toks)
				var got []byte
				for _, c := range chunks {
					got = append(got, sr.push(c)...)
				}
				got = append(got, sr.flush()...)
				assert.Equal(t, string(oneShot), string(got),
					"chunking must not change the output: %v over %q, chunks %q",
					secrets, body, chunks)
			}
		}
	}
}

// S2 / R3 on real data: no secret survives. redactionSafe is the only
// filter, because it now enforces the whole credential constraint --
// bracket-free AND not a substring of "[REDACTED]" -- so there is no
// second skip condition to apply here.
func TestNoSecretSurvivesRedaction(t *testing.T) {
	rng := rand.New(rand.NewSource(1005))
	for _, secrets := range formalSecretCorpus() {
		// The credential constraint, enforced exactly by the shipped check.
		if !redactionSafe(secrets) {
			continue
		}
		for _, s := range secrets {
			require.True(t, refRedactableTok([]byte(s)),
				"redactionSafe accepted %q, so RedactableTok must hold", s)
		}
		toks := prepareRedactTokens(secrets)
		require.NotNil(t, toks)
		for _, body := range formalBodyCorpus() {
			oneShot := redactAll(toks, []byte(body))
			for _, s := range secrets {
				assert.NotContains(t, string(oneShot), s,
					"one-shot output must not contain %q (body %q)", s, body)
			}
			for trial := 0; trial < 10; trial++ {
				chunks := randomChunking(rng, []byte(body))
				sr := newStreamRedactor(toks)
				var got []byte
				for _, c := range chunks {
					got = append(got, sr.push(c)...)
				}
				got = append(got, sr.flush()...)
				for _, s := range secrets {
					assert.NotContains(t, string(got), s,
						"streamed output must not contain %q (body %q, chunks %q)",
						s, body, chunks)
				}
			}
		}
	}
}

// redactionSafe is exactly Dafny RedactionSafe over the secret list:
// no '[' or ']' (ContainsAnyMeta) and not a substring of the placeholder
// text (SubstringOfPlaceholder).
func TestRedactionSafeMatchesDafnyRedactionSafe(t *testing.T) {
	cands := []string{
		"", "a", "sk-abc", "[", "]", "[]", "a[b", "a]b", "[REDACTED]",
		"REDACTED", "\x00", "a\x00b",
		// Substrings of the placeholder text, which the second condition
		// is what rejects.
		"R", "RE", "DACT", "ED", "ACTED", "EDACTED", "[RED", "TED]",
		// Near misses that are not substrings of it.
		"REDACTEDX", "REDCTED", "ED ", "RD", "DE", "redacted",
	}
	for _, s := range cands {
		assert.Equal(t, refRedactionSafe([]string{s}), redactionSafe([]string{s}),
			"redactionSafe(%q)", s)
	}

	// Over a secret list, both sides reject if any single element is
	// rejected.
	lists := [][]string{
		nil,
		{},
		{"sk-abc", "Bearer sk-abc"},
		{"sk-abc", "ED"},
		{"ED", "sk-abc"},
		{"sk-abc", ""},
		{"sk-abc", "a]b"},
	}
	for _, l := range lists {
		assert.Equal(t, refRedactionSafe(l), redactionSafe(l),
			"redactionSafe(%q)", l)
	}
}

// Every contiguous substring of the placeholder text is refused, and the
// empty string with it. The placeholder is 10 bytes, so this is the 66
// (i, j) spans with i <= j: an explicit, closed bound.
func TestRedactionSafeRefusesEveryPlaceholderSubstring(t *testing.T) {
	ph := string(redactedPlaceholder)
	require.Len(t, ph, 10)
	checked := 0
	for i := 0; i <= len(ph); i++ {
		for j := i; j <= len(ph); j++ {
			sub := ph[i:j]
			checked++
			assert.False(t, redactionSafe([]string{sub}),
				"a secret of %q is a substring of %q and must be refused", sub, ph)
			assert.False(t, refRedactableTok([]byte(sub)),
				"RedactableTok(%q) must be false", sub)
			// And refused in company, whichever side it sits on.
			assert.False(t, redactionSafe([]string{"sk-ordinary", sub}))
			assert.False(t, redactionSafe([]string{sub, "sk-ordinary"}))
		}
	}
	assert.Equal(t, 66, checked, "all i <= j pairs over a 10-byte placeholder")
}

// R4 on real data: everything redactionSafe accepts satisfies
// RedactableTok, the precondition of the redaction theorems. This is the
// Go-side witness of RedactionSafeImpliesRedactable in formal/redact.dfy.
//
// The sweep is bounded and streamed: a 5-character alphabet chosen to hit
// both conditions, lengths 0 to 3, generated one candidate at a time and
// never collected. 5^0+5^1+5^2+5^3 = 156 candidates.
func TestRedactionSafeDischargesRedactableTok(t *testing.T) {
	const alphabet = "R[D]E"
	const maxLen = 3

	accepted, rejected := 0, 0
	check := func(s string) {
		safe := redactionSafe([]string{s})
		// The shipped check and the Dafny model agree.
		require.Equal(t, refRedactionSafe([]string{s}), safe,
			"redactionSafe(%q) must match the model", s)
		if safe {
			accepted++
			// R4: acceptance implies the theorems' precondition.
			require.True(t, refRedactableTok([]byte(s)),
				"redactionSafe accepted %q but RedactableTok(%q) is false", s, s)
		} else {
			rejected++
			require.False(t, refRedactableTok([]byte(s)),
				"redactionSafe rejected %q but RedactableTok(%q) is true", s, s)
		}
	}

	// Stream the candidates: an odometer over the alphabet, one string in
	// flight at a time, no collection of the whole space.
	buf := make([]byte, 0, maxLen)
	var walk func(depth int)
	walk = func(depth int) {
		check(string(buf))
		if depth == maxLen {
			return
		}
		for i := 0; i < len(alphabet); i++ {
			buf = append(buf, alphabet[i])
			walk(depth + 1)
			buf = buf[:len(buf)-1]
		}
	}
	walk(0)

	assert.Equal(t, 156, accepted+rejected, "bounded sweep size")
	assert.Positive(t, accepted, "the sweep must exercise the accepting side")
	assert.Positive(t, rejected, "the sweep must exercise the rejecting side")
}
