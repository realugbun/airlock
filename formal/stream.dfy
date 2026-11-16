include "redact.dfy"

// =====================================================================
// formal/stream.dfy
//
// Model of the STREAMING redactors in internal/proxy/redact.go, as they
// stand after the redaction fix (both readers share one cascade of
// tokenReplacers).
//
// Modelled Go functions:
//   bytes.Index            -> IndexOf
//   tokenPrefixSuffixLen   -> TPSL
//   tokenReplacer          -> Repl
//   tokenReplacer.push     -> PushRepl   (loop body: ScanReplace)
//   tokenReplacer.flush    -> FlushRepl
//   streamRedactor         -> seq<Repl>
//   streamRedactor.push    -> PushCascade
//   streamRedactor.flush   -> FlushCascade
//   redactAll              -> OneShot    (redact.dfy)
//
// What is proved here:
//
//   S1  STREAMED == ONE-SHOT, FOR ANY CHUNKING. Pushing a body through
//       the cascade in an arbitrary sequence of pieces and then flushing
//       produces exactly redactAll of the concatenated body
//       (StreamEqualsOneShot). The chunk list is universally quantified,
//       so this covers every possible split, including a secret split
//       character by character across reads.
//
//   S2  NO SECRET IN THE STREAMED OUTPUT, for any chunking, obtained by
//       composing S1 with redact.dfy's R3 (NoSecretInStreamedOutput).
//
//   S3  S2 UNDER THE SHIPPED CHECK ONLY: the same statement with
//       redact.dfy's model of redactionSafe as its single hypothesis
//       (NoStreamedSecretSurvivesTheShippedCheck), via R4. The streaming
//       guarantee therefore holds for every redaction set the router
//       forwards, with no assumed credential constraint.
//
// Both shipped readers are instances of S1. redactingReader pushes
// r.buf[:n] per Read and calls flush exactly once when the upstream
// returns an error or EOF; newSSERedactingReader passes sr.push as the
// per-event-batch transform and sr.flush as the final hook, which
// sseEventReader calls once in drain(). Each therefore delivers SOME
// partition of its input to the cascade followed by one flush, and S1
// holds for every partition. See docs/security.md.
//
// Nothing in this file is axiomatised; every lemma below has a proof.
// =====================================================================

// ---------------------------------------------------------------------
// Leftmost occurrence index, or -1  (Go: bytes.Index)
// ---------------------------------------------------------------------
function IndexOf(hay: string, needle: string): int
  requires |needle| > 0
  ensures IndexOf(hay, needle) == -1
          || (0 <= IndexOf(hay, needle) && IndexOf(hay, needle) + |needle| <= |hay|)
  decreases |hay|
{
  if |hay| < |needle| then -1
  else if hay[..|needle|] == needle then 0
  else
    var r := IndexOf(hay[1..], needle);
    if r < 0 then -1 else r + 1
}

lemma IndexOfSpec(hay: string, needle: string)
  requires |needle| > 0
  ensures IndexOf(hay, needle) >= 0 ==> OccursAt(hay, needle, IndexOf(hay, needle))
  ensures IndexOf(hay, needle) >= 0
          ==> forall j: nat :: j < IndexOf(hay, needle) ==> !OccursAt(hay, needle, j)
  ensures IndexOf(hay, needle) < 0 ==> !Occurs(hay, needle)
  decreases |hay|
{
  if |hay| < |needle| {
    if Occurs(hay, needle) { var i: nat :| OccursAt(hay, needle, i); assert false; }
  } else if hay[..|needle|] == needle {
    assert OccursAt(hay, needle, 0);
  } else {
    IndexOfSpec(hay[1..], needle);
    var r := IndexOf(hay[1..], needle);
    assert !OccursAt(hay, needle, 0);
    if r < 0 {
      if Occurs(hay, needle) {
        var i: nat :| OccursAt(hay, needle, i);
        assert i >= 1;
        assert OccursAt(hay[1..], needle, i - 1) by {
          assert hay[1..][i - 1..i - 1 + |needle|] == hay[i..i + |needle|] == needle;
        }
        assert false;
      }
    } else {
      assert OccursAt(hay, needle, r + 1) by {
        assert hay[r + 1..r + 1 + |needle|] == hay[1..][r..r + |needle|] == needle;
      }
      forall j: nat | j < r + 1
        ensures !OccursAt(hay, needle, j)
      {
        if j >= 1 && OccursAt(hay, needle, j) {
          assert OccursAt(hay[1..], needle, j - 1) by {
            assert hay[1..][j - 1..j - 1 + |needle|] == hay[j..j + |needle|] == needle;
          }
        }
      }
    }
  }
}

lemma IndexOfUnique(hay: string, needle: string, idx: nat)
  requires |needle| > 0
  requires OccursAt(hay, needle, idx)
  requires forall j: nat :: j < idx ==> !OccursAt(hay, needle, j)
  ensures IndexOf(hay, needle) == idx
{
  IndexOfSpec(hay, needle);
  assert Occurs(hay, needle);
  var i := IndexOf(hay, needle);
  assert i >= 0;
  if i < idx { assert !OccursAt(hay, needle, i); assert false; }
  if i > idx { assert !OccursAt(hay, needle, idx); assert false; }
}

lemma IndexOfNegOnSuffix(s: string, tok: string, k: nat)
  requires |tok| > 0 && k <= |s|
  requires IndexOf(s, tok) < 0
  ensures IndexOf(s[k..], tok) < 0
{
  IndexOfSpec(s, tok);
  NoOccurrenceInSuffix(s, tok, k);
  IndexOfSpec(s[k..], tok);
}

// Appending to the right cannot move a match that is already complete.
lemma IndexOfPrefixStable(buf: string, b: string, tok: string)
  requires |tok| > 0
  requires IndexOf(buf, tok) >= 0
  ensures IndexOf(buf + b, tok) == IndexOf(buf, tok)
{
  IndexOfSpec(buf, tok);
  var idx := IndexOf(buf, tok);
  var c := buf + b;
  assert OccursAt(c, tok, idx) by {
    assert c[idx..idx + |tok|] == buf[idx..idx + |tok|] == tok;
  }
  forall j: nat | j < idx
    ensures !OccursAt(c, tok, j)
  {
    assert !OccursAt(buf, tok, j);
    assert j + |tok| <= |buf|;
    assert c[j..j + |tok|] == buf[j..j + |tok|];
  }
  IndexOfUnique(c, tok, idx);
}

// ---------------------------------------------------------------------
// ReplaceAll, reformulated around the leftmost match index. This is the
// bridge between the character-by-character definition in redact.dfy
// (which mirrors bytes.ReplaceAll's semantics) and the index-based loop
// the Go push method actually runs.
// ---------------------------------------------------------------------
lemma ReplaceAllShort(s: string, tok: string)
  requires |tok| > 0 && |s| < |tok|
  ensures ReplaceAll(s, tok, PH) == s
{}

lemma ReplaceAllNoMatch(buf: string, tok: string)
  requires |tok| > 0
  requires IndexOf(buf, tok) < 0
  ensures ReplaceAll(buf, tok, PH) == buf
  decreases |buf|
{
  if |buf| < |tok| {
  } else {
    assert buf[..|tok|] != tok;
    assert IndexOf(buf[1..], tok) < 0;
    ReplaceAllNoMatch(buf[1..], tok);
    assert ReplaceAll(buf, tok, PH) == [buf[0]] + buf[1..] == buf;
  }
}

lemma ReplaceAllAtIndex(buf: string, tok: string)
  requires |tok| > 0
  requires IndexOf(buf, tok) >= 0
  ensures var idx := IndexOf(buf, tok);
          ReplaceAll(buf, tok, PH)
            == buf[..idx] + PH + ReplaceAll(buf[idx + |tok|..], tok, PH)
  decreases |buf|
{
  var idx := IndexOf(buf, tok);
  if idx == 0 {
    assert buf[..|tok|] == tok;
    assert buf[..0] + PH + ReplaceAll(buf[|tok|..], tok, PH)
           == PH + ReplaceAll(buf[|tok|..], tok, PH);
  } else {
    assert |buf| >= |tok| && buf[..|tok|] != tok;
    assert IndexOf(buf[1..], tok) == idx - 1;
    ReplaceAllAtIndex(buf[1..], tok);
    assert ReplaceAll(buf, tok, PH) == [buf[0]] + ReplaceAll(buf[1..], tok, PH);
    assert buf[1..][..idx - 1] == buf[1..idx];
    assert buf[1..][idx - 1 + |tok|..] == buf[idx + |tok|..];
    assert [buf[0]] + buf[1..idx] == buf[..idx];
  }
}

// ---------------------------------------------------------------------
// ScanReplace models the loop inside tokenReplacer.push:
//
//   out := []; i := 0
//   for {
//       idx := bytes.Index(buf[i:], t.tok)
//       if idx < 0 { break }
//       out = append(out, buf[i:i+idx]...)
//       out = append(out, redactedPlaceholder...)
//       i += idx + len(t.tok)
//   }
//   rest := buf[i:]
//
// It returns (what the loop emitted, what is left unscanned).
// ---------------------------------------------------------------------
function ScanReplace(buf: string, tok: string): (string, string)
  requires |tok| > 0
  decreases |buf|
{
  var idx := IndexOf(buf, tok);
  if idx < 0 then ("", buf)
  else
    var r := ScanReplace(buf[idx + |tok|..], tok);
    (buf[..idx] + PH + r.0, r.1)
}

// The loop exits because no complete occurrence is left.
lemma ScanReplaceRestNoMatch(buf: string, tok: string)
  requires |tok| > 0
  ensures IndexOf(ScanReplace(buf, tok).1, tok) < 0
  decreases |buf|
{
  var idx := IndexOf(buf, tok);
  if idx < 0 {
  } else {
    ScanReplaceRestNoMatch(buf[idx + |tok|..], tok);
  }
}

// The emitted part is final: whatever follows buf, ReplaceAll over the
// whole thing begins with exactly what the loop already emitted.
lemma ScanSplit(buf: string, b: string, tok: string)
  requires |tok| > 0
  ensures var sc := ScanReplace(buf, tok);
          ReplaceAll(buf + b, tok, PH) == sc.0 + ReplaceAll(sc.1 + b, tok, PH)
  decreases |buf|
{
  var idx := IndexOf(buf, tok);
  if idx < 0 {
    assert ScanReplace(buf, tok) == ("", buf);
  } else {
    IndexOfPrefixStable(buf, b, tok);
    assert IndexOf(buf + b, tok) == idx;
    ReplaceAllAtIndex(buf + b, tok);
    assert (buf + b)[..idx] == buf[..idx];
    assert (buf + b)[idx + |tok|..] == buf[idx + |tok|..] + b;
    ScanSplit(buf[idx + |tok|..], b, tok);
    var r := ScanReplace(buf[idx + |tok|..], tok);
    assert ReplaceAll(buf + b, tok, PH)
           == buf[..idx] + PH + (r.0 + ReplaceAll(r.1 + b, tok, PH));
    assert buf[..idx] + PH + (r.0 + ReplaceAll(r.1 + b, tok, PH))
           == (buf[..idx] + PH + r.0) + ReplaceAll(r.1 + b, tok, PH);
  }
}

// ---------------------------------------------------------------------
// TPSL models tokenPrefixSuffixLen: the length of the longest suffix of
// b that is a PROPER prefix of tok.
//
//   k := min(len(tok)-1, len(b))
//   for ; k > 0; k-- { if bytes.HasPrefix(tok, b[len(b)-k:]) { return k } }
//   return 0
// ---------------------------------------------------------------------
function TPSLFrom(b: string, tok: string, k: nat): nat
  requires |tok| > 0
  requires k <= |b| && k < |tok|
  ensures TPSLFrom(b, tok, k) <= k
  decreases k
{
  if k == 0 then 0
  else if IsPrefix(b[|b| - k..], tok) then k
  else TPSLFrom(b, tok, k - 1)
}

function TPSL(b: string, tok: string): nat
  requires |tok| > 0
  ensures TPSL(b, tok) <= |b| && TPSL(b, tok) < |tok|
{
  TPSLFrom(b, tok, if |tok| - 1 < |b| then |tok| - 1 else |b|)
}

// The k-length suffix of rest and of rest[1..] are the same string
// whenever k leaves at least one character in front, so the scan for the
// longest token-prefix suffix gives the same answer on both.
lemma TPSLFromShift(rest: string, tok: string, k: nat)
  requires |tok| > 0 && |rest| > 0
  requires k <= |rest| - 1 && k < |tok|
  ensures TPSLFrom(rest, tok, k) == TPSLFrom(rest[1..], tok, k)
  decreases k
{
  if k == 0 {
  } else {
    assert rest[1..][|rest[1..]| - k..] == rest[|rest| - k..];
    TPSLFromShift(rest, tok, k - 1);
  }
}

// Dropping a leading character leaves the held tail unchanged, as long
// as the tail is not the whole string.
lemma TPSLShift(rest: string, tok: string)
  requires |tok| > 0 && |rest| > 0
  requires TPSL(rest, tok) < |rest|
  ensures TPSL(rest[1..], tok) == TPSL(rest, tok)
{
  var k := TPSL(rest, tok);
  var b := rest[1..];
  if |tok| - 1 <= |rest| - 1 {
    // Both scans start at the same cap, |tok| - 1.
    assert TPSL(rest, tok) == TPSLFrom(rest, tok, |tok| - 1);
    assert TPSL(b, tok) == TPSLFrom(b, tok, |tok| - 1);
    TPSLFromShift(rest, tok, |tok| - 1);
  } else {
    // |tok| > |rest|: rest's scan starts at |rest| and b's at |rest| - 1.
    assert TPSL(rest, tok) == TPSLFrom(rest, tok, |rest|);
    assert TPSL(b, tok) == TPSLFrom(b, tok, |rest| - 1);
    // The top candidate (the whole of rest) cannot have matched, because
    // it would have returned |rest|, and k < |rest|.
    assert rest[|rest| - |rest|..] == rest;
    assert !IsPrefix(rest, tok);
    assert TPSLFrom(rest, tok, |rest|) == TPSLFrom(rest, tok, |rest| - 1);
    TPSLFromShift(rest, tok, |rest| - 1);
  }
}

// A string with no complete occurrence of tok, whose longest
// token-prefix suffix is shorter than itself, is not a prefix of tok.
lemma HoldNotWholePrefix(rest: string, tok: string)
  requires |tok| > 0
  requires IndexOf(rest, tok) < 0
  requires TPSL(rest, tok) < |rest|
  ensures !IsPrefix(rest, tok)
{
  if IsPrefix(rest, tok) {
    if |rest| == |tok| {
      assert rest == tok;
      IndexOfSpec(rest, tok);
      assert OccursAt(rest, tok, 0) by { assert rest[0..|tok|] == rest == tok; }
      assert false;
    }
    assert |rest| < |tok|;
    // So the scan starts at the whole of rest, which IS a prefix of tok,
    // and therefore returns |rest| -- contradicting TPSL(rest,tok) < |rest|.
    assert TPSL(rest, tok) == TPSLFrom(rest, tok, |rest|);
    assert |rest| > 0;
    assert rest[|rest| - |rest|..] == rest;
    assert TPSLFrom(rest, tok, |rest|) == |rest|;
    assert false;
  }
}

// The held tail is exactly the part that is NOT final: no occurrence of
// tok in rest+b can begin before |rest|-k, because a straddling match
// would make a longer suffix of rest a proper prefix of tok.
lemma {:vcs_split_on_every_assert} ReplaceAllHoldSplit(rest: string, b: string, tok: string)
  requires |tok| > 0
  requires IndexOf(rest, tok) < 0
  ensures var k := TPSL(rest, tok); var m := |rest| - k;
          ReplaceAll(rest + b, tok, PH)
            == rest[..m] + ReplaceAll(rest[m..] + b, tok, PH)
  decreases |rest|
{
  var k := TPSL(rest, tok);
  var m := |rest| - k;
  if m == 0 {
    assert rest[..m] == "";
    assert rest[m..] == rest;
  } else if |rest + b| < |tok| {
    // Nothing can ever match; both sides are the input unchanged.
    ReplaceAllShort(rest + b, tok);
    assert |rest[m..] + b| <= |rest + b| < |tok|;
    ReplaceAllShort(rest[m..] + b, tok);
    assert rest[..m] + (rest[m..] + b) == rest + b;
  } else {
    HoldNotWholePrefix(rest, tok);
    // rest + b cannot start with tok.
    assert !IsPrefix(tok, rest + b) by {
      if IsPrefix(tok, rest + b) {
        if |tok| <= |rest| {
          IndexOfSpec(rest, tok);
          assert OccursAt(rest, tok, 0) by {
            assert rest[0..|tok|] == (rest + b)[0..|tok|] == tok;
          }
          assert false;
        } else {
          assert IsPrefix(rest, tok) by {
            assert |rest| <= |tok|;
            assert tok[..|rest|] == (rest + b)[..|rest|] == rest;
          }
          assert false;
        }
      }
    }
    assert (rest + b)[..|tok|] != tok;
    assert ReplaceAll(rest + b, tok, PH)
           == [(rest + b)[0]] + ReplaceAll((rest + b)[1..], tok, PH);
    assert (rest + b)[0] == rest[0];
    assert (rest + b)[1..] == rest[1..] + b;

    TPSLShift(rest, tok);
    IndexOfNegOnSuffix(rest, tok, 1);
    ReplaceAllHoldSplit(rest[1..], b, tok);
    var b2 := rest[1..];
    assert TPSL(b2, tok) == k;
    assert |b2| - k == m - 1;
    assert b2[..m - 1] == rest[1..m];
    assert b2[m - 1..] == rest[m..];
    assert [rest[0]] + rest[1..m] == rest[..m];
  }
}

// =====================================================================
// One stage of the cascade: tokenReplacer.
// =====================================================================
datatype Repl = Repl(tok: string, held: string)

ghost predicate ValidRepl(r: Repl)
{ |r.tok| > 0 && |r.held| < |r.tok| }

ghost predicate ValidCascade(st: seq<Repl>)
{ forall i :: 0 <= i < |st| ==> ValidRepl(st[i]) }

predicate OkToks(st: seq<Repl>)
{ forall i :: 0 <= i < |st| ==> |st[i].tok| > 0 }

// Go: tokenReplacer.push
function PushRepl(r: Repl, data: string): (Repl, string)
  requires |r.tok| > 0
  ensures PushRepl(r, data).0.tok == r.tok
  ensures |PushRepl(r, data).0.held| < |r.tok|
{
  var buf := r.held + data;
  var sc := ScanReplace(buf, r.tok);
  var rest := sc.1;
  var k := TPSL(rest, r.tok);
  var m := |rest| - k;
  (Repl(r.tok, rest[m..]), sc.0 + rest[..m])
}

// Go: tokenReplacer.flush -- release the held tail, which cannot contain
// a complete occurrence of this stage's token.
function FlushRepl(r: Repl): (Repl, string)
{ (Repl(r.tok, ""), r.held) }

// THE STAGE INVARIANT: everything a push returns is final. For any
// continuation b, ReplaceAll over the whole remaining input equals what
// this push emitted followed by ReplaceAll of (held + b).
lemma PushReplSplit(r: Repl, data: string, b: string)
  requires |r.tok| > 0
  ensures var p := PushRepl(r, data);
          ReplaceAll(r.held + data + b, r.tok, PH)
            == p.1 + ReplaceAll(p.0.held + b, r.tok, PH)
{
  var tok := r.tok;
  var buf := r.held + data;
  var sc := ScanReplace(buf, tok);
  var rest := sc.1;
  var k := TPSL(rest, tok);
  var m := |rest| - k;

  assert r.held + data + b == buf + b;
  ScanSplit(buf, b, tok);
  assert ReplaceAll(buf + b, tok, PH) == sc.0 + ReplaceAll(rest + b, tok, PH);

  ScanReplaceRestNoMatch(buf, tok);
  ReplaceAllHoldSplit(rest, b, tok);
  assert ReplaceAll(rest + b, tok, PH) == rest[..m] + ReplaceAll(rest[m..] + b, tok, PH);

  assert sc.0 + (rest[..m] + ReplaceAll(rest[m..] + b, tok, PH))
         == (sc.0 + rest[..m]) + ReplaceAll(rest[m..] + b, tok, PH);
}

// ---------------------------------------------------------------------
// A stage driven over a whole chunk list, recording its output pieces.
// ---------------------------------------------------------------------
function StageRun(r: Repl, chunks: seq<string>): (Repl, seq<string>)
  requires |r.tok| > 0
  requires |r.held| < |r.tok|
  ensures StageRun(r, chunks).0.tok == r.tok
  ensures |StageRun(r, chunks).0.held| < |r.tok|
  ensures |StageRun(r, chunks).1| == |chunks|
  decreases |chunks|
{
  if |chunks| == 0 then (r, [])
  else
    var p := PushRepl(r, chunks[0]);
    var q := StageRun(p.0, chunks[1..]);
    (q.0, [p.1] + q.1)
}

function Concat(chunks: seq<string>): string
  decreases |chunks|
{
  if |chunks| == 0 then "" else chunks[0] + Concat(chunks[1..])
}

lemma ConcatAppend(x: seq<string>, y: seq<string>)
  ensures Concat(x + y) == Concat(x) + Concat(y)
  decreases |x|
{
  if |x| == 0 {
    assert x + y == y;
  } else {
    assert (x + y)[0] == x[0];
    assert (x + y)[1..] == x[1..] + y;
    ConcatAppend(x[1..], y);
  }
}

lemma ConcatSingle(s: string)
  ensures Concat([s]) == s
{}

// The stage invariant lifted to a whole chunk list: ANY chunking of the
// same bytes produces the same emitted prefix plus the same held tail.
lemma StageRunSplit(r: Repl, chunks: seq<string>, b: string)
  requires |r.tok| > 0 && |r.held| < |r.tok|
  ensures var sr := StageRun(r, chunks);
          ReplaceAll(r.held + Concat(chunks) + b, r.tok, PH)
            == Concat(sr.1) + ReplaceAll(sr.0.held + b, r.tok, PH)
  decreases |chunks|
{
  if |chunks| == 0 {
    assert Concat(chunks) == "";
    assert r.held + "" + b == r.held + b;
  } else {
    var p := PushRepl(r, chunks[0]);
    var q := StageRun(p.0, chunks[1..]);
    var tail := Concat(chunks[1..]);

    PushReplSplit(r, chunks[0], tail + b);
    assert r.held + chunks[0] + (tail + b) == r.held + Concat(chunks) + b by {
      assert Concat(chunks) == chunks[0] + tail;
    }
    assert ReplaceAll(r.held + Concat(chunks) + b, r.tok, PH)
           == p.1 + ReplaceAll(p.0.held + (tail + b), r.tok, PH);

    StageRunSplit(p.0, chunks[1..], b);
    assert p.0.held + tail + b == p.0.held + (tail + b);
    assert ReplaceAll(p.0.held + (tail + b), r.tok, PH)
           == Concat(q.1) + ReplaceAll(q.0.held + b, r.tok, PH);

    ConcatAppend([p.1], q.1);
    assert Concat([p.1] + q.1) == p.1 + Concat(q.1);
    assert p.1 + (Concat(q.1) + ReplaceAll(q.0.held + b, r.tok, PH))
           == (p.1 + Concat(q.1)) + ReplaceAll(q.0.held + b, r.tok, PH);
  }
}

// A stage started empty, driven over chunks and then flushed, emits
// exactly ReplaceAll over the concatenated input.
lemma StageTotal(tok: string, chunks: seq<string>)
  requires |tok| > 0
  ensures var sr := StageRun(Repl(tok, ""), chunks);
          Concat(sr.1) + sr.0.held == ReplaceAll(Concat(chunks), tok, PH)
{
  var r := Repl(tok, "");
  var sr := StageRun(r, chunks);
  StageRunSplit(r, chunks, "");
  assert r.held + Concat(chunks) + "" == Concat(chunks);
  assert sr.0.held + "" == sr.0.held;
  ReplaceAllShort(sr.0.held, tok);
  assert ReplaceAll(sr.0.held, tok, PH) == sr.0.held;
}

// =====================================================================
// The cascade: streamRedactor.
// =====================================================================

// Go: streamRedactor.push -- each stage's output is the next's input.
function PushCascade(st: seq<Repl>, data: string): (seq<Repl>, string)
  requires OkToks(st)
  ensures |PushCascade(st, data).0| == |st|
  ensures forall i :: 0 <= i < |st| ==> PushCascade(st, data).0[i].tok == st[i].tok
  ensures OkToks(PushCascade(st, data).0)
  decreases |st|
{
  if |st| == 0 then (st, data)
  else
    var p := PushRepl(st[0], data);
    var q := PushCascade(st[1..], p.1);
    ([p.0] + q.0, q.1)
}

// Go: streamRedactor.flush -- drain each stage in order, pushing its
// held tail through the stages behind it before draining those.
function FlushCascade(st: seq<Repl>): (seq<Repl>, string)
  requires OkToks(st)
  decreases |st|
{
  if |st| == 0 then (st, "")
  else
    var f := FlushRepl(st[0]);
    var p := PushCascade(st[1..], f.1);
    var g := FlushCascade(p.0);
    ([f.0] + g.0, p.1 + g.1)
}

function RunCascade(st: seq<Repl>, chunks: seq<string>): (seq<Repl>, string)
  requires OkToks(st)
  ensures |RunCascade(st, chunks).0| == |st|
  ensures forall i :: 0 <= i < |st| ==> RunCascade(st, chunks).0[i].tok == st[i].tok
  ensures OkToks(RunCascade(st, chunks).0)
  decreases |chunks|
{
  if |chunks| == 0 then (st, "")
  else
    var p := PushCascade(st, chunks[0]);
    var q := RunCascade(p.0, chunks[1..]);
    (q.0, p.1 + q.1)
}

// Push every chunk, then flush once. This is what both shipped readers do.
function StreamOut(st: seq<Repl>, chunks: seq<string>): string
  requires OkToks(st)
{
  var r := RunCascade(st, chunks);
  r.1 + FlushCascade(r.0).1
}

function InitCascade(toks: seq<string>): seq<Repl>
  ensures |InitCascade(toks)| == |toks|
  ensures forall i :: 0 <= i < |toks| ==> InitCascade(toks)[i] == Repl(toks[i], "")
{
  if |toks| == 0 then []
  else [Repl(toks[0], "")] + InitCascade(toks[1..])
}

lemma InitCascadePeel(toks: seq<string>)
  requires |toks| > 0
  ensures InitCascade(toks) == [Repl(toks[0], "")] + InitCascade(toks[1..])
{}

// Running a cascade over x then y is running it over x + y.
lemma RunCascadeAppend(st: seq<Repl>, x: seq<string>, y: seq<string>)
  requires OkToks(st)
  ensures var a := RunCascade(st, x);
          var b := RunCascade(a.0, y);
          RunCascade(st, x + y) == (b.0, a.1 + b.1)
  decreases |x|
{
  if |x| == 0 {
    assert x + y == y;
    assert RunCascade(st, x) == (st, "");
    var b := RunCascade(st, y);
    assert "" + b.1 == b.1;
  } else {
    assert (x + y)[0] == x[0];
    assert (x + y)[1..] == x[1..] + y;
    var p := PushCascade(st, x[0]);
    RunCascadeAppend(p.0, x[1..], y);
    var a1 := RunCascade(p.0, x[1..]);
    var b := RunCascade(a1.0, y);
    assert p.1 + (a1.1 + b.1) == (p.1 + a1.1) + b.1;
  }
}

// An empty cascade is the identity: no stages, no redaction.
lemma RunCascadeEmpty(chunks: seq<string>)
  ensures RunCascade([], chunks) == ([], Concat(chunks))
  decreases |chunks|
{
  if |chunks| == 0 {
  } else {
    assert PushCascade([], chunks[0]) == ([], chunks[0]);
    RunCascadeEmpty(chunks[1..]);
  }
}

// ---------------------------------------------------------------------
// THE PEEL LEMMA. The first stage sees the raw chunk list; every stage
// behind it sees the first stage's OUTPUT list, in order. This is what
// makes the cascade a composition rather than an interleaving, and it
// is the step that justifies streamRedactor.flush's ordering.
// ---------------------------------------------------------------------
lemma CascadePeel(r: Repl, st: seq<Repl>, chunks: seq<string>)
  requires |r.tok| > 0 && |r.held| < |r.tok| && OkToks(st)
  ensures var sr := StageRun(r, chunks);
          var rc := RunCascade([r] + st, chunks);
          var inner := RunCascade(st, sr.1);
          rc.0 == [sr.0] + inner.0 && rc.1 == inner.1
  decreases |chunks|
{
  if |chunks| == 0 {
    assert StageRun(r, chunks) == (r, []);
    assert RunCascade(st, []) == (st, "");
  } else {
    var p := PushRepl(r, chunks[0]);
    var qc := PushCascade(st, p.1);
    assert ([r] + st)[0] == r;
    assert ([r] + st)[1..] == st;
    assert PushCascade([r] + st, chunks[0]) == ([p.0] + qc.0, qc.1);

    CascadePeel(p.0, qc.0, chunks[1..]);
    var sr2 := StageRun(p.0, chunks[1..]);
    var inner2 := RunCascade(qc.0, sr2.1);

    // StageRun(r, chunks) == (sr2.0, [p.1] + sr2.1)
    var sr := StageRun(r, chunks);
    assert sr == (sr2.0, [p.1] + sr2.1);

    // RunCascade(st, [p.1] + sr2.1) unfolds to PushCascade(st, p.1)
    // followed by RunCascade(qc.0, sr2.1).
    RunCascadeAppend(st, [p.1], sr2.1);
    assert RunCascade(st, [p.1]) == (qc.0, qc.1) by {
      assert [p.1][0] == p.1;
      assert [p.1][1..] == [];
      assert RunCascade(qc.0, []) == (qc.0, "");
      assert qc.1 + "" == qc.1;
    }
    assert RunCascade(st, sr.1) == (inner2.0, qc.1 + inner2.1);
  }
}

// Flushing a peeled cascade is the same as running the sub-cascade over
// one extra chunk -- the peeled stage's held tail -- and flushing that.
lemma FlushCascadePeel(rf: Repl, st: seq<Repl>)
  requires |rf.tok| > 0 && OkToks(st)
  ensures FlushCascade([rf] + st).1 == StreamOut(st, [rf.held])
{
  assert ([rf] + st)[0] == rf;
  assert ([rf] + st)[1..] == st;
  var p := PushCascade(st, rf.held);
  assert FlushCascade([rf] + st).1 == p.1 + FlushCascade(p.0).1;
  assert RunCascade(st, [rf.held]) == (p.0, p.1 + "");
  assert p.1 + "" == p.1;
}

// THE PEEL THEOREM: one stage can always be stripped off the front.
lemma {:vcs_split_on_every_assert} StreamOutPeel(r: Repl, st: seq<Repl>, chunks: seq<string>)
  requires |r.tok| > 0 && |r.held| < |r.tok| && OkToks(st)
  ensures var sr := StageRun(r, chunks);
          StreamOut([r] + st, chunks) == StreamOut(st, sr.1 + [sr.0.held])
{
  var sr := StageRun(r, chunks);
  var rc := RunCascade([r] + st, chunks);
  var inner := RunCascade(st, sr.1);

  CascadePeel(r, st, chunks);
  assert rc.0 == [sr.0] + inner.0 && rc.1 == inner.1;

  FlushCascadePeel(sr.0, inner.0);
  assert FlushCascade(rc.0).1 == StreamOut(inner.0, [sr.0.held]);
  assert StreamOut([r] + st, chunks) == inner.1 + StreamOut(inner.0, [sr.0.held]);

  RunCascadeAppend(st, sr.1, [sr.0.held]);
  var tailrun := RunCascade(inner.0, [sr.0.held]);
  assert RunCascade(st, sr.1 + [sr.0.held]) == (tailrun.0, inner.1 + tailrun.1);
  assert StreamOut(st, sr.1 + [sr.0.held])
         == (inner.1 + tailrun.1) + FlushCascade(tailrun.0).1;
  assert StreamOut(inner.0, [sr.0.held]) == tailrun.1 + FlushCascade(tailrun.0).1;
  assert inner.1 + (tailrun.1 + FlushCascade(tailrun.0).1)
         == (inner.1 + tailrun.1) + FlushCascade(tailrun.0).1;
}

// =====================================================================
// S1: STREAMED REDACTION EQUALS ONE-SHOT REDACTION, FOR ANY CHUNKING.
//
// `chunks` is universally quantified: every way of splitting the body
// into pieces -- including splitting a secret character by character --
// yields exactly redactAll of the whole body. This is the property
// docs/security.md claims when it says the bytes the agent receives do
// not depend on the chunk boundaries.
// =====================================================================
lemma StreamEqualsOneShot(toks: seq<string>, chunks: seq<string>)
  requires forall i :: 0 <= i < |toks| ==> |toks[i]| > 0
  ensures OkToks(InitCascade(toks))
  ensures StreamOut(InitCascade(toks), chunks) == OneShot(Concat(chunks), toks)
  decreases |toks|
{
  if |toks| == 0 {
    assert InitCascade(toks) == [];
    RunCascadeEmpty(chunks);
    assert FlushCascade([]).1 == "";
    assert Concat(chunks) + "" == Concat(chunks);
  } else {
    var r := Repl(toks[0], "");
    var st := InitCascade(toks[1..]);
    InitCascadePeel(toks);
    assert InitCascade(toks) == [r] + st;

    var sr := StageRun(r, chunks);
    StreamOutPeel(r, st, chunks);
    assert StreamOut(InitCascade(toks), chunks) == StreamOut(st, sr.1 + [sr.0.held]);

    StreamEqualsOneShot(toks[1..], sr.1 + [sr.0.held]);
    assert StreamOut(st, sr.1 + [sr.0.held])
           == OneShot(Concat(sr.1 + [sr.0.held]), toks[1..]);

    ConcatAppend(sr.1, [sr.0.held]);
    assert Concat(sr.1 + [sr.0.held]) == Concat(sr.1) + sr.0.held;

    StageTotal(toks[0], chunks);
    assert Concat(sr.1) + sr.0.held == ReplaceAll(Concat(chunks), toks[0], PH);
  }
}

// =====================================================================
// S2: NO SECRET APPEARS IN THE STREAMED OUTPUT, FOR ANY CHUNKING.
//
// S1 plus redact.dfy's R3. This is the end-to-end guarantee: whatever
// the upstream's framing, the bytes the agent sees contain none of the
// injected credentials.
// =====================================================================
lemma NoSecretInStreamedOutput(toks: seq<string>, chunks: seq<string>)
  requires RedactableTokens(toks)
  ensures OkToks(InitCascade(toks))
  ensures forall i :: (0 <= i < |toks|
          ==> !Occurs(StreamOut(InitCascade(toks), chunks), toks[i]))
{
  assert forall i :: 0 <= i < |toks| ==> |toks[i]| > 0;
  StreamEqualsOneShot(toks, chunks);
  NoSecretInOneShotOutput(Concat(chunks), toks);
}

// A restatement making the "any chunking" quantifier explicit: two
// different chunkings of the same body give byte-identical output.
lemma ChunkingIrrelevant(toks: seq<string>, c1: seq<string>, c2: seq<string>)
  requires forall i :: 0 <= i < |toks| ==> |toks[i]| > 0
  requires Concat(c1) == Concat(c2)
  ensures OkToks(InitCascade(toks))
  ensures StreamOut(InitCascade(toks), c1) == StreamOut(InitCascade(toks), c2)
{
  StreamEqualsOneShot(toks, c1);
  StreamEqualsOneShot(toks, c2);
}

// =====================================================================
// S3: NO SECRET IN THE STREAMED OUTPUT, UNDER THE SHIPPED CHECK.
//
// S2 with its hypothesis replaced by redact.dfy's model of
// redactionSafe, which R4 proves implies RedactableTokens. The only
// assumption left is that the cascade receives some partition of the
// body followed by one flush, which is a fact about the reader plumbing
// and not about the credential.
// =====================================================================
lemma NoStreamedSecretSurvivesTheShippedCheck(toks: seq<string>, chunks: seq<string>)
  requires RedactionSafe(toks)
  ensures RedactableTokens(toks)
  ensures forall i :: 0 <= i < |toks| ==> |toks[i]| > 0
  ensures OkToks(InitCascade(toks))
  ensures forall i :: (0 <= i < |toks|
          ==> !Occurs(StreamOut(InitCascade(toks), chunks), toks[i]))
{
  RedactionSafeImpliesRedactable(toks);
  NoSecretInStreamedOutput(toks, chunks);
}
