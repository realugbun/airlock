include "path.dfy"

// =====================================================================
// formal/glob.dfy
//
// Model of the glob access-rule matcher in internal/proxy/allowlist.go.
//
// Modelled Go functions:
//   matchPattern        -> MatchPattern
//   collapseDoublestar  -> CollapseDoublestar / CollapseAcc
//   matchSegments       -> MatchSegmentsDP
//   matchSegment        -> MatchSeg      (path.dfy)
//   splitPath           -> SplitPath     (path.dfy)
//
// What is proved here:
//
//   G1  MatchSegmentsDP, the transliteration of the bottom-up DP in
//       matchSegments, equals the declarative glob semantics Matches
//       under the 64/256 caps, and is false above them.
//
//   G2  Collapsing consecutive '**' does not change what matches:
//       Matches(CollapseDoublestar(pat), path) == Matches(pat, path).
//
//   G3  The WHOLE matchPattern composition
//         matchSegments(collapseDoublestar(splitPath(pattern)), splitPath(path))
//       equals Matches(SplitPath(pattern), SplitPath(path)) under the
//       caps. This is the property the proxy actually relies on; G1 and
//       G2 are the two halves of it.
//
//   G4  '*' never matches an empty segment, at the level of a whole
//       pattern and path (see also path.dfy).
// =====================================================================

// ---------------------------------------------------------------------
// Declarative glob semantics. This is the SPEC; the shipped DP must
// equal it. '**' matches zero or more segments, '*' exactly one
// non-empty segment, anything else matches itself.
// ---------------------------------------------------------------------
predicate Matches(pat: seq<string>, path: seq<string>)
  decreases |pat| + |path|
{
  if |pat| == 0 then |path| == 0
  else if pat[0] == "**" then
    Matches(pat[1..], path) || (|path| > 0 && Matches(pat, path[1..]))
  else
    |path| > 0 && MatchSeg(pat[0], path[0]) && Matches(pat[1..], path[1..])
}

// A lone "**" matches anything, including the empty path.
lemma StarStarMatchesAnything(path: seq<string>)
  ensures Matches(["**"], path)
  decreases |path|
{
  if |path| == 0 {
  } else {
    StarStarMatchesAnything(path[1..]);
    assert Matches(["**"], path[1..]);
  }
}

// =====================================================================
// G2: collapsing consecutive '**'
//
// Go (collapseDoublestar):
//
//   out := make([]string, 0, len(parts))
//   for _, p := range parts {
//       if p == "**" && len(out) > 0 && out[len(out)-1] == "**" { continue }
//       out = append(out, p)
//   }
//   return out
//
// CollapseAcc below is that loop with `out` as an explicit accumulator,
// so the model has the same left-to-right, keep-the-first-of-each-run
// behaviour as the Go code rather than a convenient reformulation of it.
// =====================================================================
function CollapseAcc(out: seq<string>, parts: seq<string>): seq<string>
  decreases |parts|
{
  if |parts| == 0 then out
  else if parts[0] == "**" && |out| > 0 && out[|out| - 1] == "**" then
    CollapseAcc(out, parts[1..])
  else
    CollapseAcc(out + [parts[0]], parts[1..])
}

function CollapseDoublestar(parts: seq<string>): seq<string>
{
  CollapseAcc([], parts)
}

// Collapsing never lengthens the pattern, so a pattern inside the
// 64-segment cap stays inside it after collapsing.
lemma CollapseAccLen(out: seq<string>, parts: seq<string>)
  ensures |CollapseAcc(out, parts)| <= |out| + |parts|
  ensures |out| <= |CollapseAcc(out, parts)|
  decreases |parts|
{
  if |parts| == 0 {
  } else if parts[0] == "**" && |out| > 0 && out[|out| - 1] == "**" {
    CollapseAccLen(out, parts[1..]);
  } else {
    CollapseAccLen(out + [parts[0]], parts[1..]);
  }
}

lemma CollapseDoublestarLen(parts: seq<string>)
  ensures |CollapseDoublestar(parts)| <= |parts|
{
  CollapseAccLen([], parts);
}

// ---------------------------------------------------------------------
// The heart of G2: inserting a redundant '**' immediately after a '**'
// does not change what Matches accepts, in ANY left context.
//
// The induction is on |out| + |path|: walking down `out` one segment at
// a time, with the '**' case also consuming path segments. No general
// concatenation-splitting lemma is needed.
// ---------------------------------------------------------------------
lemma AbsorbInContext(out: seq<string>, rest: seq<string>, path: seq<string>)
  requires |out| > 0 && out[|out| - 1] == "**"
  ensures Matches(out + ["**"] + rest, path) == Matches(out + rest, path)
  decreases |out| + |path|
{
  if |out| == 1 {
    // out == ["**"], so the claim is Matches(["**","**"]+rest) == Matches(["**"]+rest).
    assert out == ["**"];
    StarStarAbsorb(rest, path);
    assert out + ["**"] + rest == ["**"] + (["**"] + rest);
    assert out + rest == ["**"] + rest;
  } else {
    var head := out[0];
    assert out == [head] + out[1..];
    assert |out[1..]| > 0 && out[1..][|out[1..]| - 1] == "**";
    assert out + ["**"] + rest == [head] + (out[1..] + ["**"] + rest);
    assert out + rest == [head] + (out[1..] + rest);

    if head == "**" {
      // Both sides unfold the same way; recurse on the shorter context
      // for the "skip" branch and on the shorter path for the "consume"
      // branch.
      AbsorbInContext(out[1..], rest, path);
      if |path| > 0 {
        AbsorbInContext(out, rest, path[1..]);
      }
      assert ([head] + (out[1..] + ["**"] + rest))[1..] == out[1..] + ["**"] + rest;
      assert ([head] + (out[1..] + rest))[1..] == out[1..] + rest;
    } else {
      // A literal or '*' head must consume exactly one segment on both
      // sides, after which the contexts are one shorter.
      AbsorbInContext(out[1..], rest, if |path| > 0 then path[1..] else path);
      assert ([head] + (out[1..] + ["**"] + rest))[1..] == out[1..] + ["**"] + rest;
      assert ([head] + (out[1..] + rest))[1..] == out[1..] + rest;
    }
  }
}

// Base case of AbsorbInContext: "**","**" accepts exactly what "**" does.
lemma StarStarAbsorb(rest: seq<string>, path: seq<string>)
  ensures Matches(["**"] + (["**"] + rest), path) == Matches(["**"] + rest, path)
  decreases |path|
{
  var a := ["**"] + rest;
  var b := ["**"] + a;
  assert b[0] == "**" && b[1..] == a;
  assert a[0] == "**" && a[1..] == rest;
  if |path| == 0 {
    // Both reduce to Matches(rest, []) via the zero-segment branch.
  } else {
    StarStarAbsorb(rest, path[1..]);
    assert Matches(b, path) == (Matches(a, path) || Matches(b, path[1..]));
    assert Matches(a, path) == (Matches(rest, path) || Matches(a, path[1..]));
    // Matches(b, path[1..]) == Matches(a, path[1..]) by the recursive call,
    // and Matches(a, path[1..]) implies Matches(a, path), so the extra
    // disjunct on the left adds nothing.
  }
}

lemma CollapseAccPreservesMatches(out: seq<string>, parts: seq<string>, path: seq<string>)
  ensures Matches(CollapseAcc(out, parts), path) == Matches(out + parts, path)
  decreases |parts|
{
  if |parts| == 0 {
    assert out + parts == out;
  } else if parts[0] == "**" && |out| > 0 && out[|out| - 1] == "**" {
    CollapseAccPreservesMatches(out, parts[1..], path);
    assert parts == ["**"] + parts[1..];
    assert out + parts == out + ["**"] + parts[1..];
    AbsorbInContext(out, parts[1..], path);
  } else {
    CollapseAccPreservesMatches(out + [parts[0]], parts[1..], path);
    assert (out + [parts[0]]) + parts[1..] == out + parts;
  }
}

// G2, as stated.
lemma CollapseDoublestarPreservesMatches(parts: seq<string>, path: seq<string>)
  ensures Matches(CollapseDoublestar(parts), path) == Matches(parts, path)
{
  CollapseAccPreservesMatches([], parts, path);
  assert [] + parts == parts;
}

// =====================================================================
// G1: Go's matchSegments, transliterated as a bottom-up DP over a
// (P+1)x(S+1) table. No recursion, no backtracking.
//
//   dp[P][S] = true
//   for p := P-1; p >= 0; p-- {
//       if pattern[p] == "**" {
//           for s := S; s >= 0; s-- {
//               dp[p][s] = dp[p+1][s] || (s < S && dp[p][s+1])
//           }
//       } else {
//           for s := S-1; s >= 0; s-- {
//               if matchSegment(pattern[p], path[s]) { dp[p][s] = dp[p+1][s+1] }
//           }
//       }
//   }
//   return dp[0][0]
// =====================================================================
method MatchSegmentsDP(pattern: seq<string>, path: seq<string>) returns (res: bool)
  ensures |pattern| > MaxPatternSegments || |path| > MaxPathSegments ==> res == false
  ensures |pattern| <= MaxPatternSegments && |path| <= MaxPathSegments
          ==> res == Matches(pattern, path)
{
  var P := |pattern|;
  var S := |path|;
  if P > MaxPatternSegments || S > MaxPathSegments {
    return false;           // Go: deny if either cap is exceeded
  }

  var dp := new bool[P + 1, S + 1]((_, _) => false);
  dp[P, S] := true;         // empty pattern matches empty path

  assert forall s :: 0 <= s <= S ==> dp[P, s] == (s == S);
  assert forall s :: 0 <= s <= S ==> Matches(pattern[P..], path[s..]) == (s == S);

  var p := P - 1;
  while p >= 0
    invariant -1 <= p <= P - 1 || P == 0
    invariant -1 <= p < P + 1
    invariant forall pp, ss :: (p < pp <= P && 0 <= ss <= S
              ==> dp[pp, ss] == Matches(pattern[pp..], path[ss..]))
    // rows not yet computed are still at their false initialisation
    invariant forall pp, ss :: 0 <= pp <= p && 0 <= ss <= S ==> dp[pp, ss] == false
    decreases p + 1
  {
    var seg := pattern[p];
    assert pattern[p..][0] == seg;
    assert pattern[p..][1..] == pattern[p + 1..];

    if seg == "**" {
      var s := S;
      while s >= 0
        invariant -1 <= s <= S
        invariant forall ss :: (s < ss <= S
                  ==> dp[p, ss] == Matches(pattern[p..], path[ss..]))
        invariant forall pp, ss :: (p < pp <= P && 0 <= ss <= S
                  ==> dp[pp, ss] == Matches(pattern[pp..], path[ss..]))
        invariant forall pp, ss :: 0 <= pp < p && 0 <= ss <= S ==> dp[pp, ss] == false
        invariant forall ss :: 0 <= ss <= s ==> dp[p, ss] == false
        decreases s + 1
      {
        var v := dp[p + 1, s];
        if s < S {
          assert path[s..][1..] == path[s + 1..];
          v := v || dp[p, s + 1];
        } else {
          assert |path[s..]| == 0;
        }
        dp[p, s] := v;
        assert dp[p, s] == Matches(pattern[p..], path[s..]);
        s := s - 1;
      }
    } else {
      // Literal or '*': must consume exactly one segment. dp[p, S] is
      // never written and stays false, which is correct because
      // Matches(pattern[p..], []) is false for a non-'**' head.
      assert dp[p, S] == false;
      assert Matches(pattern[p..], path[S..]) == false;
      var s := S - 1;
      while s >= 0
        invariant -1 <= s <= S - 1 || S == 0
        invariant -1 <= s < S + 1
        invariant dp[p, S] == false
        invariant forall ss :: (s < ss <= S
                  ==> dp[p, ss] == Matches(pattern[p..], path[ss..]))
        invariant forall pp, ss :: (p < pp <= P && 0 <= ss <= S
                  ==> dp[pp, ss] == Matches(pattern[pp..], path[ss..]))
        invariant forall pp, ss :: 0 <= pp < p && 0 <= ss <= S ==> dp[pp, ss] == false
        invariant forall ss :: 0 <= ss <= s ==> dp[p, ss] == false
        decreases s + 1
      {
        assert path[s..][0] == path[s];
        assert path[s..][1..] == path[s + 1..];
        if MatchSeg(seg, path[s]) {
          dp[p, s] := dp[p + 1, s + 1];
        }
        assert dp[p, s] == Matches(pattern[p..], path[s..]);
        s := s - 1;
      }
    }
    p := p - 1;
  }

  assert pattern[0..] == pattern;
  assert path[0..] == path;
  res := dp[0, 0];
}

// =====================================================================
// G3: the whole matchPattern composition.
//
//   func matchPattern(pattern, path string) bool {
//       patParts := splitPath(pattern)
//       patParts = collapseDoublestar(patParts)
//       pathParts := splitPath(path)
//       return matchSegments(patParts, pathParts)
//   }
//
// The postcondition is stated against SplitPath(pattern) -- the
// UNCOLLAPSED pattern -- so collapseDoublestar is proved to be an
// optimisation with no effect on the accepted language, not merely
// modelled.
// =====================================================================
method MatchPattern(pattern: string, path: string) returns (res: bool)
  ensures var pat := SplitPath(pattern);
          var pth := SplitPath(path);
          (|pat| <= MaxPatternSegments && |pth| <= MaxPathSegments
           ==> res == Matches(pat, pth))
  ensures var pth := SplitPath(path);
          |pth| > MaxPathSegments ==> res == false
{
  var patParts := SplitPath(pattern);
  var collapsed := CollapseDoublestar(patParts);
  var pathParts := SplitPath(path);

  CollapseDoublestarLen(patParts);
  assert |collapsed| <= |patParts|;

  res := MatchSegmentsDP(collapsed, pathParts);

  if |collapsed| <= MaxPatternSegments && |pathParts| <= MaxPathSegments {
    CollapseDoublestarPreservesMatches(patParts, pathParts);
    assert res == Matches(collapsed, pathParts) == Matches(patParts, pathParts);
  }
}

// =====================================================================
// G4: '*' never matches an empty segment, at whole-pattern level.
//
// Every segment MatchSeg is ever applied to comes from SplitPath, and
// SplitPath yields no empty segment, so the '*' case of MatchSeg is
// never reached with "". Stated here over an arbitrary request path.
// =====================================================================
lemma StarNeverMatchesEmptyInMatchPattern(pattern: string, path: string)
  ensures !MatchSeg("*", "")
  ensures forall s :: s in SplitPath(path) ==> MatchSeg("*", s)
  // A '*' pattern segment cannot be the reason an over-short path matches:
  // Matches(["*"], []) is false, because '*' demands a segment to consume.
  ensures !Matches(["*"], [])
{
  StarNeverMatchesEmptySegment(path);
}

// An empty path (no segments) is matched only by patterns made of '**'.
// In particular "/users/*" does not match "/" or "".
lemma StarDoesNotMatchEmptyPath(rest: seq<string>)
  ensures !Matches(["*"] + rest, [])
{
  assert (["*"] + rest)[0] == "*";
}
