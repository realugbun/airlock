include "path.dfy"

// =====================================================================
// formal/policy.dfy
//
// Model of (*AccessPolicy).Allowed in internal/proxy/allowlist.go.
//
// Modelled Go functions:
//   (*AccessPolicy).Allowed -> Allowed
//   splitPath               -> SplitPath  (path.dfy)
//   matchSegment            -> MatchSeg   (path.dfy)
//
// What is proved here:
//
//   P1  FIRST MATCH WINS. If rule k is the first applicable rule, the
//       decision is exactly rules[k].action == Allow.
//   P2  IMPLICIT DENY. If rules are defined and none applies, deny.
//   P2b EXPLICIT DENY-ALL. denyAll denies unconditionally.
//   P2c NO RULES MEANS ALLOW -- faithful to the Go code; see the note on
//       strict mode below.
//   P4  THE 256-SEGMENT CAP denies before any rule is consulted, and is
//       stated over |SplitPath(path)|, the real splitter, not a free
//       parameter.
//   P3  '*' never matches an empty segment (path.dfy, restated here
//       against the segments this policy actually compares).
//
// The per-rule matcher is left UNINTERPRETED (the function field `hit`),
// so P1, P2 and P4 hold for ANY matcher -- glob or RE2 -- rather than
// only for the glob one. That keeps the regex engine out of the trusted
// surface for these properties. The glob matcher's own correctness is
// glob.dfy's subject.
// =====================================================================

datatype Action = Allow | Deny

datatype Rule = Rule(action: Action, httpMethod: string, hit: string -> bool)

// Go:
//   if r.method != "ALL" && r.method != method { continue }
//   ... if hit { return r.action == actionAllow }
predicate RuleApplies(r: Rule, httpMethod: string, path: string)
{
  (r.httpMethod == "ALL" || r.httpMethod == httpMethod) && r.hit(path)
}

ghost predicate NoneApply(rules: seq<Rule>, httpMethod: string, path: string)
{
  forall i :: 0 <= i < |rules| ==> !RuleApplies(rules[i], httpMethod, path)
}

ghost predicate IsFirstMatch(rules: seq<Rule>, httpMethod: string, path: string, k: int)
{
  && 0 <= k < |rules|
  && RuleApplies(rules[k], httpMethod, path)
  && (forall i :: 0 <= i < k ==> !RuleApplies(rules[i], httpMethod, path))
}

// ---------------------------------------------------------------------
// Transliteration of (*AccessPolicy).Allowed.
//
//   func (p *AccessPolicy) Allowed(method, path string) bool {
//       if p.denyAll { return false }
//       if len(p.rules) == 0 { return true }
//       if len(splitPath(path)) > maxPathSegments { return false }
//       normalized := normalizePath(path)
//       for _, r := range p.rules {
//           if r.method != "ALL" && r.method != method { continue }
//           var hit bool
//           if r.regex != nil { hit = r.regex.MatchString(normalized) }
//           else { hit = matchPattern(r.pattern, path) }
//           if hit { return r.action == actionAllow }
//       }
//       return false
//   }
//
// The segment count is computed here as |SplitPath(path)|, exactly as
// the Go code computes len(splitPath(path)), rather than being supplied
// as an unconstrained parameter.
// ---------------------------------------------------------------------
method Allowed(rules: seq<Rule>, denyAll: bool, httpMethod: string, path: string)
  returns (ok: bool)

  // --- P2b EXPLICIT DENY-ALL (config `access_rules: []`) --------------
  ensures denyAll ==> !ok

  // --- P2c NO RULES AT ALL MEANS NO RESTRICTIONS ----------------------
  //
  // This is FAITHFUL TO THE SHIPPED CODE, not a modelling convenience:
  // `if len(p.rules) == 0 { return true }`. It is not a fail-open path,
  // because a route can only reach this state deliberately. Strict mode
  // is the default and rejects a route with no access_rules at config
  // load (internal/config/config.go: "access_rules required when strict
  // mode is enabled (default); set strict: false to allow routes without
  // access rules"), so an unconfigured route fails to start rather than
  // serving traffic unrestricted. Reaching this branch requires the
  // operator to have set `strict: false` and omitted access_rules.
  // See docs/security.md, "No rules means no restrictions".
  ensures !denyAll && |rules| == 0 ==> ok

  // --- P4 THE 256-SEGMENT CAP, EVALUATED BEFORE ANY RULE -------------
  //
  // Stated over the real splitter. This is INTENDED BEHAVIOUR: an
  // over-cap path is denied outright, whatever the rules say and
  // whatever matcher they use. See path.dfy for why the cap is central
  // rather than per-rule.
  ensures !denyAll && |rules| > 0 && |SplitPath(path)| > MaxPathSegments ==> !ok

  // --- P1 FIRST MATCH WINS -------------------------------------------
  ensures (!denyAll && |rules| > 0 && |SplitPath(path)| <= MaxPathSegments)
          ==> forall k :: IsFirstMatch(rules, httpMethod, path, k)
                          ==> (ok <==> rules[k].action == Allow)

  // --- P2 IMPLICIT DENY ----------------------------------------------
  ensures (!denyAll && |rules| > 0 && |SplitPath(path)| <= MaxPathSegments
           && NoneApply(rules, httpMethod, path)) ==> !ok

  // --- a decision is only ever an allow if some rule said so ---------
  ensures ok && |rules| > 0 && !denyAll
          ==> exists k :: IsFirstMatch(rules, httpMethod, path, k)
                          && rules[k].action == Allow
{
  if denyAll { return false; }
  if |rules| == 0 { return true; }

  // Go: if len(splitPath(path)) > maxPathSegments { return false }
  var segCount := |SplitPath(path)|;
  if segCount > MaxPathSegments { return false; }

  var i := 0;
  while i < |rules|
    invariant 0 <= i <= |rules|
    // everything skipped so far genuinely did not apply
    invariant forall j :: 0 <= j < i ==> !RuleApplies(rules[j], httpMethod, path)
    decreases |rules| - i
  {
    var r := rules[i];
    if r.httpMethod != "ALL" && r.httpMethod != httpMethod {
      i := i + 1;
      continue;
    }
    if r.hit(path) {
      assert IsFirstMatch(rules, httpMethod, path, i);
      // A first match is unique, so returning this rule's action is
      // exactly what first-match-wins demands.
      assert forall k :: IsFirstMatch(rules, httpMethod, path, k) ==> k == i;
      return r.action == Allow;
    }
    i := i + 1;
  }
  // No rule matched -- implicit deny.
  assert NoneApply(rules, httpMethod, path);
  assert forall k :: !IsFirstMatch(rules, httpMethod, path, k);
  return false;
}

// =====================================================================
// P4 restated on its own: the cap is consulted before any rule, so no
// rule's `hit` can be the reason an over-cap path is allowed. Proved by
// calling Allowed with an ARBITRARY rule list whose matchers all accept
// every path: the answer is still deny.
// =====================================================================
method AllowedDeniesOverlongPathBeforeAnyRule(
    rules: seq<Rule>, httpMethod: string, path: string)
  returns (ok: bool)
  requires |rules| > 0
  requires |SplitPath(path)| > MaxPathSegments
  // Even if every rule is an ALLOW whose matcher accepts everything,
  // the request is denied.
  requires forall i :: 0 <= i < |rules| ==> rules[i].action == Allow
  requires forall i :: 0 <= i < |rules| ==> rules[i].httpMethod == "ALL"
  requires forall i :: 0 <= i < |rules| ==> rules[i].hit(path)
  ensures !ok
{
  ok := Allowed(rules, false, httpMethod, path);
}

// =====================================================================
// P3 at the level this policy operates at: every segment the matcher is
// offered comes out of SplitPath, so '*' is never handed "".
// =====================================================================
lemma StarNeverMatchesEmptySegmentInPolicy(path: string)
  ensures !MatchSeg("*", "")
  ensures forall s :: s in SplitPath(path) ==> |s| > 0 && MatchSeg("*", s)
{
  StarNeverMatchesEmptySegment(path);
}

// =====================================================================
// The two headline properties stated together with the cap, as the
// acceptance criteria ask: for a route WITH rules and a path within the
// cap, the decision is the first applicable rule's action, and deny if
// there is none; for a path over the cap, deny regardless.
// =====================================================================
method AccessContract(rules: seq<Rule>, httpMethod: string, path: string)
  returns (ok: bool)
  requires |rules| > 0
  ensures |SplitPath(path)| > MaxPathSegments ==> !ok
  ensures |SplitPath(path)| <= MaxPathSegments ==>
          (forall k :: IsFirstMatch(rules, httpMethod, path, k)
                       ==> (ok <==> rules[k].action == Allow))
  ensures (|SplitPath(path)| <= MaxPathSegments
           && NoneApply(rules, httpMethod, path)) ==> !ok
{
  ok := Allowed(rules, false, httpMethod, path);
}
