// =====================================================================
// formal/path.dfy
//
// Shared model of path splitting and segment matching, as shipped in
// internal/proxy/allowlist.go.
//
// Modelled Go functions:
//   splitPath      -> SplitPath
//   matchSegment   -> MatchSeg
//   maxPathSegments / maxPatternSegments -> MaxPathSegments / MaxPatternSegments
//
// Verified alone and included by glob.dfy and policy.dfy, so the two
// files reason about one definition of splitting rather than two.
// =====================================================================

// Safety caps (Go: maxPatternSegments / maxPathSegments in allowlist.go).
//
// THE 256-SEGMENT CAP IS INTENDED BEHAVIOUR, NOT A LIMITATION OF THE MODEL.
// A request whose path has more than MaxPathSegments segments is denied by
// AccessPolicy.Allowed before any rule is consulted (see policy.dfy,
// AllowedDeniesOverlongPathBeforeAnyRule). The cap exists because the glob
// matcher denies over-cap paths while a path_regex rule has no such cap: a
// path long enough to fail a trailing `DENY /**` could otherwise be picked
// up by a later `ALLOW path_regex` and fail open. Denying centrally, once,
// for the whole request removes that asymmetry. The limit is not
// configurable.
const MaxPatternSegments: int := 64
const MaxPathSegments: int := 256

// ---------------------------------------------------------------------
// Segment-level matcher  (Go: matchSegment)
//
//   func matchSegment(pattern, segment string) bool {
//       if pattern == "*" { return segment != "" }
//       return pattern == segment
//   }
// ---------------------------------------------------------------------
predicate MatchSeg(pat: string, seg: string)
{
  if pat == "*" then seg != "" else pat == seg
}

// P3, local form: '*' never matches an empty segment.
lemma StarNeverMatchesEmpty()
  ensures !MatchSeg("*", "")
{}

// ---------------------------------------------------------------------
// Index of the first '/' in p, or |p| when there is none.
// ---------------------------------------------------------------------
function IndexOfSlash(p: string): int
  ensures 0 <= IndexOfSlash(p) <= |p|
  ensures IndexOfSlash(p) < |p| ==> p[IndexOfSlash(p)] == '/'
  ensures forall j :: 0 <= j < IndexOfSlash(p) ==> p[j] != '/'
  decreases |p|
{
  if |p| == 0 then 0
  else if p[0] == '/' then 0
  else 1 + IndexOfSlash(p[1..])
}

// ---------------------------------------------------------------------
// SplitPath models Go's splitPath:
//
//   p = strings.Trim(p, "/")
//   if p == "" { return nil }
//   raw := strings.Split(p, "/")
//   out := raw[:0]
//   for _, s := range raw { if s != "" { out = append(out, s) } }
//
// Trimming is subsumed by dropping empty pieces: Trim only ever removes
// leading and trailing '/', and each such '/' contributes exactly one
// empty piece to Split, which the filter drops. So splitting on every
// '/' and dropping empty pieces is the same sequence. The Go
// differential test TestSplitPathMatchesDafnySplitPath discharges that
// step, which is an argument about the standard library rather than
// something this file can prove.
// ---------------------------------------------------------------------
function SplitPath(p: string): seq<string>
  decreases |p|
{
  if |p| == 0 then []
  else
    var i := IndexOfSlash(p);
    if i == |p| then [p]
    else
      var head := p[..i];
      var tail := SplitPath(p[i + 1..]);
      if |head| == 0 then tail else [head] + tail
}

// SplitPath never produces an empty segment.
lemma SplitPathNoEmpty(p: string)
  ensures forall s :: s in SplitPath(p) ==> |s| > 0
  decreases |p|
{
  if |p| == 0 {
  } else {
    var i := IndexOfSlash(p);
    if i == |p| {
      assert |p| > 0;
    } else {
      SplitPathNoEmpty(p[i + 1..]);
    }
  }
}

// SplitPath never produces a segment containing '/'.
lemma SplitPathNoSlash(p: string)
  ensures forall s :: s in SplitPath(p) ==> forall j :: 0 <= j < |s| ==> s[j] != '/'
  decreases |p|
{
  if |p| == 0 {
  } else {
    var i := IndexOfSlash(p);
    if i == |p| {
      assert forall j :: 0 <= j < |p| ==> p[j] != '/';
    } else {
      SplitPathNoSlash(p[i + 1..]);
      assert forall j :: 0 <= j < |p[..i]| ==> p[..i][j] != '/';
    }
  }
}

// =====================================================================
// P3 AT THE SYSTEM LEVEL: '*' never matches an empty segment.
//
// Two halves, together closing the property as the acceptance criteria
// state it. MatchSeg("*", "") is false, AND the matcher is never offered
// an empty segment in the first place, because every segment the policy
// compares comes out of SplitPath.
// =====================================================================
lemma StarNeverMatchesEmptySegment(p: string)
  ensures !MatchSeg("*", "")
  ensures forall s :: s in SplitPath(p) ==> MatchSeg("*", s)
  ensures forall i :: 0 <= i < |SplitPath(p)| ==> MatchSeg("*", SplitPath(p)[i])
{
  SplitPathNoEmpty(p);
}
