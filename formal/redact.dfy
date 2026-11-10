// =====================================================================
// formal/redact.dfy
//
// Model of whole-buffer redaction in internal/proxy/redact.go.
//
// Modelled Go functions:
//   redactedPlaceholder   -> PH
//   bytes.ReplaceAll      -> ReplaceAll
//   redactAll             -> OneShot
//   redactionSafe         -> RedactionSafe
//
// What is proved here:
//
//   R0  A bracket-free secret cannot overlap the placeholder: it has no
//       suffix that is a placeholder prefix, no prefix that is a
//       placeholder suffix, and does not contain the placeholder.
//   R1  ONE pass of ReplaceAll over a whole buffer removes every
//       occurrence of that secret and creates none
//       (ReplaceAllRemovesAll).
//   R2  Replacing a DIFFERENT secret cannot bring an already-removed
//       secret back (ReplaceAllPreservesAbsence).
//   R3  NO SECRET IN OUTPUT, multi-secret: after redactAll over a whole
//       buffer, NONE of the secrets occurs in the output
//       (OneShotRemovesAll). R1+R2 compose to give this for any number
//       of secrets in any order.
//   R4  THE PRECONDITION IS DISCHARGED BY THE SHIPPED CHECK: the model
//       of redactionSafe implies RedactableTok for every secret it
//       accepts (RedactionSafeImpliesRedactable), so R1-R3 apply to
//       every redaction set the router lets through
//       (NoSecretSurvivesTheShippedCheck). Nothing about the credential
//       is left assumed.
//
// The credential constraint is RedactableTok below: nonempty, free of
// '[' and ']', and not itself a substring of the constant text
// "[REDACTED]". All three conjuncts are enforced by redactionSafe
// before the upstream is contacted, and R4 proves that they are. A
// credential failing any of them is refused with a 500.
//
// Nothing in this file is axiomatised and nothing is taken on trust by
// the verifier: every lemma below has a proof. The earlier axiomatised
// NoHeadSplice is discharged as ReplaceAllPrefixPreserved + NoHeadSplice.
// =====================================================================

const PH: string := "[REDACTED]"      // Go: redactedPlaceholder

ghost predicate OccursAt(hay: string, needle: string, i: nat)
{ i + |needle| <= |hay| && hay[i..i + |needle|] == needle }

ghost predicate Occurs(hay: string, needle: string)
{ exists i: nat :: OccursAt(hay, needle, i) }

predicate IsPrefix(w: string, s: string)
{ |w| <= |s| && s[..|w|] == w }

// The negation of the first thing redactionSafe rejects: a secret
// containing any byte of placeholderMeta == "[]".
predicate BracketFree(t: string)
{ forall i :: 0 <= i < |t| ==> t[i] != '[' && t[i] != ']' }

// The constraint on a redactable credential. Every conjunct is enforced
// by redactionSafe -- see RedactionSafe and R4 below.
ghost predicate RedactableTok(t: string)
{
  && |t| > 0
  && BracketFree(t)       // no '[' or ']'
  && !Occurs(PH, t)       // t is not a substring of "[REDACTED]"
}

ghost predicate RedactableTokens(toks: seq<string>)
{ forall i :: 0 <= i < |toks| ==> RedactableTok(toks[i]) }

// ---------------------------------------------------------------------
// MODEL OF THE SHIPPED CHECK (Go: redactionSafe, internal/proxy/redact.go)
//
//   for _, s := range secrets {
//       if strings.ContainsAny(s, placeholderMeta) { return false }
//       if strings.Contains(placeholderText, s)   { return false }
//   }
//   return true
//
// with placeholderMeta == "[]" and placeholderText == PH.
// ---------------------------------------------------------------------

// Go: strings.ContainsAny(t, "[]").
ghost predicate ContainsAnyMeta(t: string)
{ exists i :: 0 <= i < |t| && (t[i] == '[' || t[i] == ']') }

// Go: strings.Contains(placeholderText, t) -- t occurs somewhere in the
// placeholder text. Note strings.Contains(x, "") is true, so this is
// also what refuses the empty secret.
ghost predicate SubstringOfPlaceholder(t: string)
{ Occurs(PH, t) }

// Go: redactionSafe(secrets).
ghost predicate RedactionSafe(secrets: seq<string>)
{
  forall i :: 0 <= i < |secrets| ==>
    !ContainsAnyMeta(secrets[i]) && !SubstringOfPlaceholder(secrets[i])
}

// ---------------------------------------------------------------------
// Leftmost-first, non-overlapping replacement. This is bytes.ReplaceAll's
// semantics: scan left to right, replace a match, continue after it.
// ---------------------------------------------------------------------
function ReplaceAll(s: string, pat: string, nw: string): string
  requires |pat| > 0
  decreases |s|
{
  if |s| < |pat| then s
  else if s[..|pat|] == pat then nw + ReplaceAll(s[|pat|..], pat, nw)
  else [s[0]] + ReplaceAll(s[1..], pat, nw)
}

// Go: redactAll(tokens, body) -- one ReplaceAll pass per token, in order.
//
//   for _, tok := range tokens { body = bytes.ReplaceAll(body, tok, PH) }
function OneShot(s: string, toks: seq<string>): string
  requires forall i :: 0 <= i < |toks| ==> |toks[i]| > 0
  decreases |toks|
{
  if |toks| == 0 then s
  else OneShot(ReplaceAll(s, toks[0], PH), toks[1..])
}

// =====================================================================
// R0: a bracket-free secret cannot interact with the placeholder.
// =====================================================================
lemma PHShape()
  ensures |PH| == 10
  ensures PH[0] == '['
  ensures PH[|PH| - 1] == ']'
  ensures PH[1..|PH| - 1] == "REDACTED"
{}

lemma NoPlaceholderInsideSecret(t: string)
  requires BracketFree(t)
  ensures !Occurs(t, PH)
{
  PHShape();
  if Occurs(t, PH) {
    var i: nat :| OccursAt(t, PH, i);
    assert t[i..i + |PH|] == PH;
    assert t[i] == PH[0] == '[';
    assert false;
  }
}

// No nonempty suffix of a bracket-free secret is a prefix of PH, and no
// nonempty suffix of PH is a prefix of such a secret. These are the two
// ways a replacement could splice a secret across its own boundary.
lemma NoBoundarySplice(t: string)
  requires |t| > 0 && BracketFree(t)
  ensures forall k: nat :: 1 <= k <= |t| && k <= |PH| ==> t[|t| - k..] != PH[..k]
  ensures forall k: nat :: 1 <= k <= |PH| && k <= |t| ==> PH[|PH| - k..] != t[..k]
{
  PHShape();
  forall k: nat | 1 <= k <= |t| && k <= |PH|
    ensures t[|t| - k..] != PH[..k]
  {
    assert PH[..k][0] == '[';
    assert t[|t| - k..][0] == t[|t| - k] != '[';
  }
  forall k: nat | 1 <= k <= |PH| && k <= |t|
    ensures PH[|PH| - k..] != t[..k]
  {
    assert PH[|PH| - k..][k - 1] == PH[|PH| - 1] == ']';
    assert t[..k][k - 1] == t[k - 1] != ']';
  }
}

// =====================================================================
// The lemma the spike was missing: PREFIXES OF ReplaceAll's OUTPUT.
//
// If a bracket-free string w is not a prefix of v, then w is not a
// prefix of ReplaceAll(v, t, PH) either.
//
// This is what closes the previously axiomatised NoHeadSplice. It works
// is that ReplaceAll only ever emits either a verbatim leading character
// of v or a placeholder, and a placeholder starts with '[', which a
// bracket-free w cannot match. So the output's prefix either tracks v's
// prefix character by character or is cut short by a '['. Note that no
// relation between |w| and |t| is needed, which is why this is strong
// enough to carry the |t|-1 case the earlier induction got stuck on.
// =====================================================================
lemma ReplaceAllPrefixPreserved(v: string, t: string, w: string)
  requires |t| > 0
  requires BracketFree(w)
  requires !IsPrefix(w, v)
  ensures !IsPrefix(w, ReplaceAll(v, t, PH))
  decreases |v|
{
  // The empty string is a prefix of everything, so w is nonempty.
  assert |w| >= 1 by { if |w| == 0 { assert IsPrefix(w, v); } }

  if |v| < |t| {
    assert ReplaceAll(v, t, PH) == v;
  } else if v[..|t|] == t {
    var out := ReplaceAll(v, t, PH);
    assert out == PH + ReplaceAll(v[|t|..], t, PH);
    PHShape();
    assert out[0] == '[';
    if IsPrefix(w, out) {
      assert w[0] == out[..|w|][0] == out[0] == '[';
      assert false;
    }
  } else {
    var tail := ReplaceAll(v[1..], t, PH);
    assert ReplaceAll(v, t, PH) == [v[0]] + tail;
    if IsPrefix(w, [v[0]] + tail) {
      var c := [v[0]] + tail;
      assert w == c[..|w|];
      assert w[0] == v[0];
      assert IsPrefix(w[1..], tail) by {
        assert |w| - 1 <= |tail|;
        assert tail[..|w| - 1] == c[1..|w|] == w[1..];
      }
      // w is not a prefix of v and agrees with v at index 0, so w[1..]
      // is not a prefix of v[1..].
      assert !IsPrefix(w[1..], v[1..]) by {
        if IsPrefix(w[1..], v[1..]) {
          assert |w| <= |v|;
          assert v[..|w|] == [v[0]] + v[1..|w|] == [w[0]] + w[1..] == w;
          assert IsPrefix(w, v);
        }
      }
      assert BracketFree(w[1..]);
      ReplaceAllPrefixPreserved(v[1..], t, w[1..]);
      assert false;
    }
  }
}

// NoHeadSplice, PROVED (no longer axiomatised): ReplaceAll emits
// s[0] verbatim only when s does not start with t, and then an
// occurrence of t cannot begin at index 0 of the output.
lemma NoHeadSplice(s: string, t: string, tail: string)
  requires |t| > 0 && BracketFree(t)
  requires |s| >= |t| && s[..|t|] != t
  requires tail == ReplaceAll(s[1..], t, PH)
  ensures !OccursAt([s[0]] + tail, t, 0)
{
  var c := [s[0]] + tail;
  if OccursAt(c, t, 0) {
    assert IsPrefix(t, c);
    assert t[0] == s[0];
    if |t| == 1 {
      assert s[..1] == [s[0]] == [t[0]] == t;
      assert false;
    }
    assert IsPrefix(t[1..], tail) by {
      assert |t| - 1 <= |tail|;
      assert tail[..|t| - 1] == c[1..|t|] == t[1..];
    }
    assert !IsPrefix(t[1..], s[1..]) by {
      if IsPrefix(t[1..], s[1..]) {
        assert s[..|t|] == [s[0]] + s[1..|t|] == [t[0]] + t[1..] == t;
      }
    }
    assert BracketFree(t[1..]);
    ReplaceAllPrefixPreserved(s[1..], t, t[1..]);
    assert false;
  }
}

// ---------------------------------------------------------------------
// Occurrence bookkeeping helpers.
// ---------------------------------------------------------------------
lemma NoOccurrenceInSuffix(s: string, t: string, k: nat)
  requires k <= |s|
  requires !Occurs(s, t)
  ensures !Occurs(s[k..], t)
{
  if Occurs(s[k..], t) {
    var i: nat :| OccursAt(s[k..], t, i);
    assert OccursAt(s, t, i + k) by {
      assert s[i + k..i + k + |t|] == s[k..][i..i + |t|] == t;
    }
  }
}

// An occurrence in [h] + b at index >= 1 is an occurrence in b, so ruling
// out index 0 and all of b rules out everything.
lemma NoOccurrenceInCons(h: char, b: string, t: string)
  requires |t| > 0
  requires !Occurs(b, t)
  requires !OccursAt([h] + b, t, 0)
  ensures !Occurs([h] + b, t)
{
  var c := [h] + b;
  if Occurs(c, t) {
    var i: nat :| OccursAt(c, t, i);
    assert i >= 1;
    assert OccursAt(b, t, i - 1) by {
      assert b[i - 1..i - 1 + |t|] == c[i..i + |t|] == t;
    }
  }
}

// A secret cannot occur in PH + b if it occurs in neither PH nor b: a
// straddling occurrence would need a suffix of PH to be its prefix, and
// every nonempty suffix of PH ends in ']'.
lemma NoOccurrenceAfterPH(b: string, t: string)
  requires RedactableTok(t)
  requires !Occurs(b, t)
  ensures !Occurs(PH + b, t)
{
  PHShape();
  NoBoundarySplice(t);
  var c := PH + b;
  if Occurs(c, t) {
    var i: nat :| OccursAt(c, t, i);
    if i + |t| <= |PH| {
      assert OccursAt(PH, t, i) by { assert PH[i..i + |t|] == c[i..i + |t|] == t; }
      assert Occurs(PH, t);
      assert false;
    } else if i >= |PH| {
      assert OccursAt(b, t, i - |PH|) by {
        assert b[i - |PH|..i - |PH| + |t|] == c[i..i + |t|] == t;
      }
      assert false;
    } else {
      var k := |PH| - i;
      assert 1 <= k <= |PH| && k < |t|;
      assert PH[|PH| - k..] == c[i..|PH|] == c[i..i + |t|][..k] == t[..k];
      assert false;
    }
  }
}

// =====================================================================
// R1: one ReplaceAll pass over a whole buffer removes every occurrence
// of that secret, and creates none.
// =====================================================================
lemma ReplaceAllRemovesAll(s: string, t: string)
  requires RedactableTok(t)
  ensures !Occurs(ReplaceAll(s, t, PH), t)
  decreases |s|
{
  if |s| < |t| {
    assert ReplaceAll(s, t, PH) == s;
    if Occurs(s, t) { var i: nat :| OccursAt(s, t, i); assert false; }
  } else if s[..|t|] == t {
    var tail := ReplaceAll(s[|t|..], t, PH);
    ReplaceAllRemovesAll(s[|t|..], t);
    assert ReplaceAll(s, t, PH) == PH + tail;
    NoOccurrenceAfterPH(tail, t);
  } else {
    var tail := ReplaceAll(s[1..], t, PH);
    ReplaceAllRemovesAll(s[1..], t);
    assert ReplaceAll(s, t, PH) == [s[0]] + tail;
    NoHeadSplice(s, t, tail);
    NoOccurrenceInCons(s[0], tail, t);
  }
}

// =====================================================================
// R2: replacing a DIFFERENT secret cannot resurrect an absent one.
//
// This is what makes the multi-secret result follow from the
// single-secret one: later passes only delete occurrences of their own
// token and insert placeholders, and neither can spell a bracket-free
// secret that was not already there.
// =====================================================================
lemma ReplaceAllPreservesAbsence(x: string, u: string, t: string)
  requires |u| > 0
  requires RedactableTok(t)
  requires !Occurs(x, t)
  ensures !Occurs(ReplaceAll(x, u, PH), t)
  decreases |x|
{
  if |x| < |u| {
    assert ReplaceAll(x, u, PH) == x;
  } else if x[..|u|] == u {
    var tail := ReplaceAll(x[|u|..], u, PH);
    NoOccurrenceInSuffix(x, t, |u|);
    ReplaceAllPreservesAbsence(x[|u|..], u, t);
    assert ReplaceAll(x, u, PH) == PH + tail;
    NoOccurrenceAfterPH(tail, t);
  } else {
    var tail := ReplaceAll(x[1..], u, PH);
    NoOccurrenceInSuffix(x, t, 1);
    ReplaceAllPreservesAbsence(x[1..], u, t);
    assert ReplaceAll(x, u, PH) == [x[0]] + tail;
    // Index 0 of the output: t is not a prefix of x, and the output's
    // prefix tracks x's, so t is not a prefix of the output either.
    assert !OccursAt([x[0]] + tail, t, 0) by {
      var c := [x[0]] + tail;
      if OccursAt(c, t, 0) {
        assert IsPrefix(t, c);
        assert !IsPrefix(t, x) by {
          if IsPrefix(t, x) { assert OccursAt(x, t, 0); }
        }
        assert t[0] == x[0];
        if |t| == 1 { assert IsPrefix(t, x) by { assert x[..1] == [x[0]] == t; } }
        assert IsPrefix(t[1..], tail) by {
          assert tail[..|t| - 1] == c[1..|t|] == t[1..];
        }
        assert !IsPrefix(t[1..], x[1..]) by {
          if IsPrefix(t[1..], x[1..]) {
            assert x[..|t|] == [x[0]] + x[1..|t|] == [t[0]] + t[1..] == t;
            assert IsPrefix(t, x);
          }
        }
        assert BracketFree(t[1..]);
        ReplaceAllPrefixPreserved(x[1..], u, t[1..]);
        assert false;
      }
    }
    NoOccurrenceInCons(x[0], tail, t);
  }
}

// Absence survives a whole OneShot cascade of other secrets.
lemma OneShotPreservesAbsence(s: string, toks: seq<string>, t: string)
  requires forall i :: 0 <= i < |toks| ==> |toks[i]| > 0
  requires RedactableTok(t)
  requires !Occurs(s, t)
  ensures !Occurs(OneShot(s, toks), t)
  decreases |toks|
{
  if |toks| == 0 {
  } else {
    ReplaceAllPreservesAbsence(s, toks[0], t);
    OneShotPreservesAbsence(ReplaceAll(s, toks[0], PH), toks[1..], t);
  }
}

// =====================================================================
// R3: NO SECRET APPEARS IN THE OUTPUT (multi-secret, whole buffer).
//
// This is the property docs/security.md claims for redactAll and for
// header/trailer redaction, and the one the streaming theorem in
// stream.dfy is reduced to.
// =====================================================================
lemma OneShotRemovesAll(s: string, toks: seq<string>, i: int)
  requires 0 <= i < |toks|
  requires RedactableTokens(toks)
  ensures !Occurs(OneShot(s, toks), toks[i])
  decreases |toks|
{
  if i == 0 {
    var y := ReplaceAll(s, toks[0], PH);
    ReplaceAllRemovesAll(s, toks[0]);
    assert !Occurs(y, toks[0]);
    OneShotPreservesAbsence(y, toks[1..], toks[0]);
  } else {
    OneShotRemovesAll(ReplaceAll(s, toks[0], PH), toks[1..], i - 1);
    assert toks[1..][i - 1] == toks[i];
  }
}

// R3 stated over the whole token list at once.
lemma NoSecretInOneShotOutput(s: string, toks: seq<string>)
  requires RedactableTokens(toks)
  ensures forall i :: 0 <= i < |toks| ==> !Occurs(OneShot(s, toks), toks[i])
{
  forall i | 0 <= i < |toks|
    ensures !Occurs(OneShot(s, toks), toks[i])
  { OneShotRemovesAll(s, toks, i); }
}

// =====================================================================
// R4: THE PRECONDITION OF R1-R3 IS DISCHARGED BY THE SHIPPED CHECK.
//
// Everything above is stated under RedactableTok. This section proves
// that RedactableTok holds for every secret redactionSafe accepts, so
// the guarantee applies to every redaction set the router forwards and
// nothing about the credential is left assumed.
//
// The two Go conditions line up with the two interesting conjuncts:
// ContainsAnyMeta is the negation of BracketFree, and
// SubstringOfPlaceholder is Occurs(PH, t). Nonemptiness is not a third
// check: the empty string occurs in PH at index 0, so the substring
// condition already rejects it, which is exactly what
// strings.Contains(placeholderText, "") == true does in Go.
// =====================================================================

// ContainsAnyMeta is the negation of BracketFree. Two spellings of one
// condition: Go tests for the presence of a bracket, the proofs above
// require its absence.
lemma ContainsAnyMetaIsNotBracketFree(t: string)
  ensures ContainsAnyMeta(t) <==> !BracketFree(t)
{
  if ContainsAnyMeta(t) {
    var i :| 0 <= i < |t| && (t[i] == '[' || t[i] == ']');
  }
  if !BracketFree(t) {
    var i :| 0 <= i < |t| && !(t[i] != '[' && t[i] != ']');
    assert 0 <= i < |t| && (t[i] == '[' || t[i] == ']');
  }
}

// The empty string is a substring of the placeholder, so the substring
// condition rejects it. This is the conjunct that used to be carried by
// RedactableTok's |t| > 0 with no corresponding check in the Go: the
// rejection is stated here as well as the substring fact, so nothing is
// left to a comment.
lemma EmptyIsSubstringOfPlaceholder()
  ensures SubstringOfPlaceholder("")
  ensures !RedactionSafe([""])
{
  assert OccursAt(PH, "", 0) by { assert PH[0..0] == ""; }
  assert [""][0] == "";
}

// R4, the implication the spec asks for:
//
//     redactionSafe(secrets) ==> forall t in secrets :: RedactableTok(t)
lemma RedactionSafeImpliesRedactable(secrets: seq<string>)
  requires RedactionSafe(secrets)
  ensures RedactableTokens(secrets)
  ensures forall i :: 0 <= i < |secrets| ==> |secrets[i]| > 0
{
  forall i | 0 <= i < |secrets|
    ensures RedactableTok(secrets[i])
  {
    var t := secrets[i];
    ContainsAnyMetaIsNotBracketFree(t);
    assert BracketFree(t);
    assert !Occurs(PH, t);
    if |t| == 0 {
      EmptyIsSubstringOfPlaceholder();
      assert t == "";
      assert false;
    }
  }
}

// The converse direction, for completeness: the check is not stronger
// than the constraint either, so RedactionSafe and RedactableTokens are
// equivalent and the check rejects no credential that satisfies the
// theorems' precondition.
//
// This is a statement about RedactableTok, not about re-spellability in
// general. The bracket rule is deliberately conservative: it refuses
// some credentials, such as "X]]", that no body could actually re-form.
// Narrowing it is not worth the proof it would cost.
lemma RedactableImpliesRedactionSafe(secrets: seq<string>)
  requires RedactableTokens(secrets)
  ensures RedactionSafe(secrets)
{
  forall i | 0 <= i < |secrets|
    ensures !ContainsAnyMeta(secrets[i]) && !SubstringOfPlaceholder(secrets[i])
  { ContainsAnyMetaIsNotBracketFree(secrets[i]); }
}

// =====================================================================
// R3 restated over the shipped check: no secret the router accepted can
// appear in the output of redactAll. This is R4 composed with R3 and is
// the end-to-end whole-buffer guarantee with no remaining hypothesis
// about the credential beyond what the gateway itself enforces.
// =====================================================================
lemma NoSecretSurvivesTheShippedCheck(s: string, toks: seq<string>)
  requires RedactionSafe(toks)
  ensures RedactableTokens(toks)
  ensures forall i :: 0 <= i < |toks| ==> |toks[i]| > 0
  ensures forall i :: 0 <= i < |toks| ==> !Occurs(OneShot(s, toks), toks[i])
{
  RedactionSafeImpliesRedactable(toks);
  NoSecretInOneShotOutput(s, toks);
}
