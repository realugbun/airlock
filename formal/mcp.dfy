// =====================================================================
// formal/mcp.dfy
//
// Model of MCP tool authorization in internal/proxy/mcp.go.
//
// Modelled Go functions:
//   NewMCPToolPolicy                  -> NewPolicy
//   (config.go) mcp_rules validation  -> ConfigAccepted
//   (*MCPToolPolicy).isToolDenied     -> IsToolDenied
//   (*MCPToolPolicy).isToolAllowed    -> IsToolAllowed
//   (*MCPToolPolicy).hasToolRules     -> HasToolRules
//   (*MCPToolPolicy).checkSingle      -> CheckSingle
//   (*MCPToolPolicy).checkBatch       -> CheckBatch
//   (*MCPToolPolicy).enforceRequest   -> EnforceRequest
//   (*MCPToolPolicy).observeRequest   -> ObserveRequest
//   (*MCPToolPolicy).CheckRequest     -> CheckRequest
//   filterJSONToolsList (name filter) -> FilterEntries
//
// What is proved here:
//
//   C1  THE TWO LISTS ARE EXCLUSIVE. A config that sets both
//       allowed_tools and denied_tools is refused, so no policy value
//       that both theorems below quantify over can carry both lists.
//   C2  A NON-EMPTY LIST ALWAYS SELECTS ITS MODE. Every entry lands in
//       the exact set or the pattern list, so a non-empty allowed_tools
//       always produces allowlist mode and never pass-through.
//   A1  ALLOWLIST MODE ALLOWS ONLY LISTED TOOLS.
//   A2  DENYLIST MODE DENIES EXACTLY THE LISTED TOOLS.
//   A3  NO LISTS MEANS PASS-THROUGH -- nothing is denied.
//   M1  A FORWARDED tools/call NAMES AN ALLOWED TOOL (single message).
//   M2  A BATCH IS ALL-OR-NOTHING. It is forwarded if and only if every
//       element parsed and no element is a denied tools/call.
//   M3  FAIL CLOSED. With tool rules set, a body that cannot be
//       inspected is never forwarded.
//   M4  THE WHOLE REQUEST PATH. Whatever the mode, a forwarded POST
//       carries no tools/call the policy does not allow.
//   L1  tools/list FILTERING KEEPS EXACTLY THE ALLOWED TOOLS IN ORDER,
//       as an ascending index map into the upstream list.
//   L2  LISTING AND CALLING AGREE. A tool survives the list filter if
//       and only if a tools/call naming it is forwarded -- both sides
//       are the same predicate, so they cannot drift.
//
// path.Match is left UNINTERPRETED (the function field `matcher`), and
// the SAME field is used by the tools/call check and by the tools/list
// filter. Every theorem below therefore holds for any glob behaviour
// whatsoever, and L2 holds because neither path can consult a different
// matcher, not because both were checked against one.
//
// JSON decoding is NOT modelled. A message arrives here already parsed
// into (method, tool name, id), or as Malformed, which is what
// parseRPCMessage returns for a body that is ambiguous or not
// well-formed. That decoding step is trusted and is tied to the shipped
// parser by internal/proxy/formal_mcp_diff_test.go instead.
// =====================================================================

// ---------------------------------------------------------------------
// 1. Config
//
// Go (internal/config/config.go):
//   if r.MCPRules != nil && len(r.MCPRules.AllowedTools) > 0 &&
//      len(r.MCPRules.DeniedTools) > 0 {
//       return fmt.Errorf("route %d: mcp_rules cannot have both ...")
//   }
// and again in NewMCPToolPolicy:
//   if len(cfg.AllowedTools) > 0 && len(cfg.DeniedTools) > 0 {
//       return nil, fmt.Errorf("mcp_rules: cannot set both ...")
//   }
// ---------------------------------------------------------------------

datatype MCPRules = MCPRules(allowedTools: seq<string>, deniedTools: seq<string>)

predicate ConfigAccepted(cfg: MCPRules)
{
  |cfg.allowedTools| == 0 || |cfg.deniedTools| == 0
}

// ---------------------------------------------------------------------
// 2. The policy value
//
// Go:
//   type MCPToolPolicy struct {
//       allowedExact    map[string]struct{}
//       allowedPatterns []string
//       deniedExact     map[string]struct{}
//       deniedPatterns  []string
//   }
//
// The shipped code tests `p.allowedExact != nil`, and the map is only
// created immediately before an entry is written to it, so a non-nil
// map is always a non-empty one. A set with |s| > 0 therefore models
// "non-nil" exactly; C2 below is what keeps that correspondence honest.
//
// `matcher` is path.Match, uninterpreted.
// ---------------------------------------------------------------------

datatype Policy = Policy(
  allowedExact: set<string>,
  allowedPatterns: seq<string>,
  deniedExact: set<string>,
  deniedPatterns: seq<string>,
  matcher: (string, string) -> bool
)

predicate HasAllowRules(p: Policy)
{
  |p.allowedExact| > 0 || |p.allowedPatterns| > 0
}

predicate HasDenyRules(p: Policy)
{
  |p.deniedExact| > 0 || |p.deniedPatterns| > 0
}

// Go: (*MCPToolPolicy).hasToolRules
predicate HasToolRules(p: Policy)
{
  HasAllowRules(p) || HasDenyRules(p)
}

// The config rule of section 1, as a property of the built policy.
// C1 proves the constructor can only ever hand out such a value.
predicate WellFormed(p: Policy)
{
  !(HasAllowRules(p) && HasDenyRules(p))
}

// Go:
//   for _, pat := range p.allowedPatterns {
//       if matched, _ := path.Match(pat, name); matched { return false }
//   }
predicate MatchesAny(m: (string, string) -> bool, pats: seq<string>, name: string)
  decreases |pats|
{
  |pats| > 0 && (m(pats[0], name) || MatchesAny(m, pats[1..], name))
}

// The recursive form above is the loop; this is what the loop means.
lemma MatchesAnyIsExistential(m: (string, string) -> bool, pats: seq<string>, name: string)
  ensures MatchesAny(m, pats, name) <==> exists i :: 0 <= i < |pats| && m(pats[i], name)
  decreases |pats|
{
  if |pats| == 0 {
    return;
  }
  MatchesAnyIsExistential(m, pats[1..], name);
  if MatchesAny(m, pats, name) {
    if !m(pats[0], name) {
      var i :| 0 <= i < |pats[1..]| && m(pats[1..][i], name);
      assert pats[1..][i] == pats[i + 1];
      assert m(pats[i + 1], name);
    }
  } else {
    forall i | 0 <= i < |pats|
      ensures !m(pats[i], name)
    {
      if i > 0 {
        assert pats[1..][i - 1] == pats[i];
      }
    }
  }
}

// ---------------------------------------------------------------------
// 3. The decision over a tool name
//
// Go:
//   func (p *MCPToolPolicy) isToolDenied(name string) bool {
//       if p.allowedExact != nil || len(p.allowedPatterns) > 0 {
//           if _, ok := p.allowedExact[name]; ok { return false }
//           for _, pat := range p.allowedPatterns {
//               if matched, _ := path.Match(pat, name); matched { return false }
//           }
//           return true
//       }
//       if p.deniedExact != nil || len(p.deniedPatterns) > 0 {
//           if _, ok := p.deniedExact[name]; ok { return true }
//           for _, pat := range p.deniedPatterns {
//               if matched, _ := path.Match(pat, name); matched { return true }
//           }
//           return false
//       }
//       return false
//   }
// ---------------------------------------------------------------------

function IsToolDenied(p: Policy, name: string): bool
{
  if HasAllowRules(p) then
    !(name in p.allowedExact) && !MatchesAny(p.matcher, p.allowedPatterns, name)
  else if HasDenyRules(p) then
    (name in p.deniedExact) || MatchesAny(p.matcher, p.deniedPatterns, name)
  else
    false
}

// Go: isToolAllowed. The single predicate both request authorization
// and response filtering are defined in terms of.
function IsToolAllowed(p: Policy, name: string): bool
{
  !IsToolDenied(p, name)
}

// --- A1 ALLOWLIST MODE ALLOWS ONLY LISTED TOOLS ----------------------
//
// In allowlist mode a tool is allowed exactly when it is named in the
// exact set or matched by one of the patterns. Nothing else is allowed,
// whatever path.Match does.
lemma AllowlistAllowsOnlyListed(p: Policy, name: string)
  requires WellFormed(p)
  requires HasAllowRules(p)
  ensures IsToolAllowed(p, name) <==>
          (name in p.allowedExact
           || exists i :: 0 <= i < |p.allowedPatterns| && p.matcher(p.allowedPatterns[i], name))
{
  MatchesAnyIsExistential(p.matcher, p.allowedPatterns, name);
}

// --- A2 DENYLIST MODE DENIES EXACTLY THE LISTED TOOLS ----------------
lemma DenylistDeniesExactlyListed(p: Policy, name: string)
  requires WellFormed(p)
  requires HasDenyRules(p)
  ensures IsToolDenied(p, name) <==>
          (name in p.deniedExact
           || exists i :: 0 <= i < |p.deniedPatterns| && p.matcher(p.deniedPatterns[i], name))
{
  MatchesAnyIsExistential(p.matcher, p.deniedPatterns, name);
}

// --- A3 NO LISTS MEANS PASS-THROUGH ----------------------------------
//
// Faithful to the shipped code: mcp_rules: {} builds a policy that
// denies nothing. This is not a fail-open path in the sense that
// matters -- it is the configured absence of tool rules, and
// checkEmptyAllowlists (internal/config/config.go) rejects a config
// that writes `allowed_tools:` with an empty list, which is the one way
// an operator could reach pass-through while believing they had
// written an allowlist.
lemma PassThroughDeniesNothing(p: Policy, name: string)
  requires !HasToolRules(p)
  ensures IsToolAllowed(p, name)
{
}

// ---------------------------------------------------------------------
// 4. The constructor
//
// Go: NewMCPToolPolicy. `isGlob` is isGlobPattern, left uninterpreted:
// the split between the exact map and the pattern list is irrelevant to
// every property here, and C2 holds for any split precisely because
// each entry goes to exactly one of the two buckets.
// ---------------------------------------------------------------------

method NewPolicy(cfg: MCPRules, isGlob: string -> bool, m: (string, string) -> bool)
  returns (err: bool, p: Policy)

  // --- C1 THE TWO LISTS ARE EXCLUSIVE -------------------------------
  ensures err <==> !ConfigAccepted(cfg)
  ensures !err ==> WellFormed(p)

  // --- C2 A NON-EMPTY LIST ALWAYS SELECTS ITS MODE ------------------
  ensures !err ==> (HasAllowRules(p) <==> |cfg.allowedTools| > 0)
  ensures !err ==> (HasDenyRules(p) <==> |cfg.deniedTools| > 0)
  ensures !err ==> (HasToolRules(p) <==>
                    (|cfg.allowedTools| > 0 || |cfg.deniedTools| > 0))
  ensures !err ==> p.matcher == m
{
  if |cfg.allowedTools| > 0 && |cfg.deniedTools| > 0 {
    return true, Policy({}, [], {}, [], m);
  }

  var aExact: set<string> := {};
  var aPats: seq<string> := [];
  var i := 0;
  while i < |cfg.allowedTools|
    invariant 0 <= i <= |cfg.allowedTools|
    invariant (|aExact| > 0 || |aPats| > 0) <==> i > 0
    decreases |cfg.allowedTools| - i
  {
    var t := cfg.allowedTools[i];
    if isGlob(t) {
      aPats := aPats + [t];
    } else {
      aExact := aExact + {t};
      assert t in aExact;
    }
    i := i + 1;
  }

  var dExact: set<string> := {};
  var dPats: seq<string> := [];
  var j := 0;
  while j < |cfg.deniedTools|
    invariant 0 <= j <= |cfg.deniedTools|
    invariant (|dExact| > 0 || |dPats| > 0) <==> j > 0
    decreases |cfg.deniedTools| - j
  {
    var t := cfg.deniedTools[j];
    if isGlob(t) {
      dPats := dPats + [t];
    } else {
      dExact := dExact + {t};
      assert t in dExact;
    }
    j := j + 1;
  }

  p := Policy(aExact, aPats, dExact, dPats, m);
  err := false;
}

// ---------------------------------------------------------------------
// 5. A parsed JSON-RPC message
//
// Go: rpcMessage plus the reason string parseRPCMessage returns. A
// non-empty reason means the message is malformed OR ambiguous (a
// duplicate or case-variant `method`, `params` or `name` key), and the
// caller turns it into a 400 rather than guessing which reading the
// upstream would take.
// ---------------------------------------------------------------------

const ToolsCall: string := "tools/call"
const ToolsList: string := "tools/list"

datatype Parsed =
  | Malformed(reason: string)
  | Msg(rpcMethod: string, toolName: string, id: string)

predicate IsToolCall(x: Parsed)
{
  x.Msg? && x.rpcMethod == ToolsCall
}

// parseRPCMessage rejects a tools/call whose params.name is absent, not
// a string, or empty, so a tools/call that reaches the decision always
// carries a name. That is a property of the trusted parser, checked
// against the shipped one by TestParseRPCMessageToolCallAlwaysNamesATool.
//
// NO THEOREM BELOW NEEDS IT. They are stated without it, so they hold
// for any parsed message, including one naming the empty tool -- which
// is the right strength, because an empty name is just another name the
// policy decides on. ParsedOK is kept only to say so explicitly.
predicate ParsedOK(x: Parsed)
{
  IsToolCall(x) ==> |x.toolName| > 0
}

// The theorems do not depend on it: the decision for a tools/call
// naming the empty tool is the same function of the policy as for any
// other name.
lemma TheoremsDoNotNeedParsedOK(p: Policy, x: Parsed)
  requires IsToolCall(x) && !ParsedOK(x)
  ensures x.toolName == ""
  ensures IsToolDenied(p, x.toolName) == IsToolDenied(p, "")
{
}

// Go: MCPCheckResult plus *MCPRequestError.
//   Forward   -- the request goes upstream (Denied false, no error)
//   DenyTool  -- 403 JSON-RPC error naming the tool, nothing forwarded
//   Reject    -- 400/413/415, the body could not be inspected safely
datatype Decision =
  | Forward(rpcMethod: string)
  | DenyTool(toolName: string, id: string)
  | Reject(reason: string)

predicate Forwarded(d: Decision)
{
  d.Forward?
}

// ---------------------------------------------------------------------
// 6. checkSingle
//
// Go:
//   func (p *MCPToolPolicy) checkSingle(body []byte) (*MCPCheckResult, string) {
//       msg, reason := parseRPCMessage(body)
//       if reason != "" { return nil, reason }
//       result := &MCPCheckResult{Method: msg.rpcMethod}
//       if msg.rpcMethod == "tools/call" && p.isToolDenied(msg.toolName) {
//           result.Denied = true; ...
//       }
//       return result, ""
//   }
// A non-empty reason becomes mcpReject(400, reason) in enforceRequest.
// ---------------------------------------------------------------------

method CheckSingle(p: Policy, x: Parsed) returns (d: Decision)
  // --- M1 A FORWARDED tools/call NAMES AN ALLOWED TOOL --------------
  ensures Forwarded(d) && IsToolCall(x) ==> IsToolAllowed(p, x.toolName)
  // and the converse: an allowed call is forwarded as a tools/call
  ensures IsToolCall(x) && IsToolAllowed(p, x.toolName)
          ==> d == Forward(ToolsCall)
  // a denied call is reported as denied, with its own name and id
  ensures IsToolCall(x) && IsToolDenied(p, x.toolName)
          ==> d == DenyTool(x.toolName, x.id)
  // an unparseable or ambiguous message is never forwarded
  ensures x.Malformed? <==> d.Reject?
  ensures Forwarded(d) ==> x.Msg?
  // every other method passes through unchanged
  ensures x.Msg? && !IsToolCall(x) ==> d == Forward(x.rpcMethod)
{
  if x.Malformed? {
    return Reject(x.reason);
  }
  if x.rpcMethod == ToolsCall && IsToolDenied(p, x.toolName) {
    return DenyTool(x.toolName, x.id);
  }
  return Forward(x.rpcMethod);
}

// ---------------------------------------------------------------------
// 7. checkBatch
//
// Go:
//   for i, raw := range batch {
//       msg, reason := parseRPCMessage(raw)
//       if reason != "" { return nil, fmt.Sprintf("batch element %d: %s", ...) }
//       msgs = append(msgs, msg)
//   }
//   for _, msg := range msgs {
//       if msg.rpcMethod == "tools/call" && p.isToolDenied(msg.toolName) {
//           return &MCPCheckResult{Denied: true, ...}, ""
//       }
//   }
//   return &MCPCheckResult{Method: "batch"}, ""
//
// Two passes, deliberately: every element is parsed before any element
// is executed, so one malformed element rejects the whole batch instead
// of being forwarded alongside the others.
// ---------------------------------------------------------------------

ghost predicate AllParsed(xs: seq<Parsed>)
{
  forall i :: 0 <= i < |xs| ==> xs[i].Msg?
}

ghost predicate NoDeniedCall(p: Policy, xs: seq<Parsed>)
{
  forall i :: 0 <= i < |xs| ==>
    (IsToolCall(xs[i]) ==> IsToolAllowed(p, xs[i].toolName))
}

method CheckBatch(p: Policy, xs: seq<Parsed>) returns (d: Decision)
  // --- M2 A BATCH IS ALL-OR-NOTHING --------------------------------
  ensures Forwarded(d) <==> (AllParsed(xs) && NoDeniedCall(p, xs))
  ensures Forwarded(d) ==> d == Forward("batch")
  // the two ways a batch is stopped, each with its witness
  ensures d.Reject? ==> !AllParsed(xs)
  ensures d.DenyTool? ==>
          exists i :: 0 <= i < |xs| && IsToolCall(xs[i])
                      && xs[i].toolName == d.toolName
                      && IsToolDenied(p, xs[i].toolName)
{
  var i := 0;
  while i < |xs|
    invariant 0 <= i <= |xs|
    invariant forall j :: 0 <= j < i ==> xs[j].Msg?
    decreases |xs| - i
  {
    if xs[i].Malformed? {
      return Reject(xs[i].reason);
    }
    i := i + 1;
  }
  assert AllParsed(xs);

  var k := 0;
  while k < |xs|
    invariant 0 <= k <= |xs|
    invariant forall j :: 0 <= j < k ==>
              (IsToolCall(xs[j]) ==> IsToolAllowed(p, xs[j].toolName))
    decreases |xs| - k
  {
    if IsToolCall(xs[k]) && IsToolDenied(p, xs[k].toolName) {
      return DenyTool(xs[k].toolName, xs[k].id);
    }
    k := k + 1;
  }
  assert NoDeniedCall(p, xs);
  return Forward("batch");
}

// A malformed element anywhere stops the batch, even when every other
// element is an allowed call: M2 restated as the all-or-nothing claim.
method BatchWithOneBadElementIsNotForwarded(p: Policy, xs: seq<Parsed>, bad: int)
  returns (d: Decision)
  requires 0 <= bad < |xs|
  requires xs[bad].Malformed?
  ensures !Forwarded(d)
{
  d := CheckBatch(p, xs);
}

method BatchWithOneDeniedCallIsNotForwarded(p: Policy, xs: seq<Parsed>, bad: int)
  returns (d: Decision)
  requires 0 <= bad < |xs|
  requires IsToolCall(xs[bad]) && IsToolDenied(p, xs[bad].toolName)
  ensures !Forwarded(d)
{
  d := CheckBatch(p, xs);
}

// ---------------------------------------------------------------------
// 8. The request body as the enforcement path sees it
//
// Go: enforceRequest. Uninspectable collects every branch that returns
// an *MCPRequestError before any policy decision is made:
//
//   Content-Encoding other than identity        -> 415
//   more than one Content-Type header           -> 400
//   a Content-Type that is not a JSON media type-> 415
//   ContentLength or body over maxMCPBodySize   -> 413
//   a body that is not valid UTF-8              -> 400
//   a batch that does not unmarshal as an array -> 400
//
// Each of those is a body Airlock cannot read the way the upstream
// will, so none of them is forwarded. Empty is a body that is
// determinately nothing to execute (`len(trimmed) == 0`): it is
// inspectable, carries no call, and is forwarded for the upstream to
// reject.
// ---------------------------------------------------------------------

datatype Body =
  | Uninspectable(reason: string)
  | Empty
  | Single(msg: Parsed)
  | BatchBody(elems: seq<Parsed>)

predicate Inspectable(b: Body)
{
  !b.Uninspectable?
}

// The tool names a body would have the upstream execute.
function CallNames(xs: seq<Parsed>): seq<string>
  decreases |xs|
{
  if |xs| == 0 then []
  else if IsToolCall(xs[0]) then [xs[0].toolName] + CallNames(xs[1..])
  else CallNames(xs[1..])
}

function ToolCallsIn(b: Body): seq<string>
{
  match b
  case Uninspectable(_) => []
  case Empty => []
  case Single(x) => if IsToolCall(x) then [x.toolName] else []
  case BatchBody(xs) => CallNames(xs)
}

lemma NoDeniedCallSplit(p: Policy, xs: seq<Parsed>)
  requires |xs| > 0
  ensures NoDeniedCall(p, xs) <==>
          ((IsToolCall(xs[0]) ==> IsToolAllowed(p, xs[0].toolName))
           && NoDeniedCall(p, xs[1..]))
{
  if NoDeniedCall(p, xs) {
    forall i | 0 <= i < |xs[1..]|
      ensures IsToolCall(xs[1..][i]) ==> IsToolAllowed(p, xs[1..][i].toolName)
    {
      assert xs[1..][i] == xs[i + 1];
    }
  }
  if (IsToolCall(xs[0]) ==> IsToolAllowed(p, xs[0].toolName))
     && NoDeniedCall(p, xs[1..]) {
    forall i | 0 <= i < |xs|
      ensures IsToolCall(xs[i]) ==> IsToolAllowed(p, xs[i].toolName)
    {
      if i > 0 {
        assert xs[1..][i - 1] == xs[i];
      }
    }
  }
}

// CallNames is exactly the set of names NoDeniedCall quantifies over.
lemma CallNamesCharacterisation(p: Policy, xs: seq<Parsed>)
  ensures NoDeniedCall(p, xs) <==>
          forall n :: n in CallNames(xs) ==> IsToolAllowed(p, n)
  decreases |xs|
{
  if |xs| == 0 {
    return;
  }
  CallNamesCharacterisation(p, xs[1..]);
  NoDeniedCallSplit(p, xs);
  if IsToolCall(xs[0]) {
    assert CallNames(xs) == [xs[0].toolName] + CallNames(xs[1..]);
    forall n | n in CallNames(xs)
      ensures n == xs[0].toolName || n in CallNames(xs[1..])
    {
    }
  }
}

// ---------------------------------------------------------------------
// 9. enforceRequest -- the fail-closed path
// ---------------------------------------------------------------------

method EnforceRequest(p: Policy, b: Body) returns (d: Decision)
  requires HasToolRules(p)

  // --- M3 FAIL CLOSED ----------------------------------------------
  //
  // With tool rules set, a body that cannot be inspected is never
  // forwarded. Stated both ways round: uninspectable implies rejected,
  // and forwarded implies inspectable.
  ensures !Inspectable(b) ==> d.Reject?
  ensures Forwarded(d) ==> Inspectable(b)

  // --- M1 and M2 lifted to the body --------------------------------
  ensures Forwarded(d) ==>
          forall n :: n in ToolCallsIn(b) ==> IsToolAllowed(p, n)
  ensures Forwarded(d) && b.Single? ==> !b.msg.Malformed?
  ensures Forwarded(d) && b.BatchBody? ==>
          AllParsed(b.elems) && NoDeniedCall(p, b.elems)
  ensures b.Single? && IsToolCall(b.msg) && IsToolDenied(p, b.msg.toolName)
          ==> d == DenyTool(b.msg.toolName, b.msg.id)
{
  match b
  case Uninspectable(reason) =>
    d := Reject(reason);
  case Empty =>
    // Go: `if len(trimmed) == 0 { return &MCPCheckResult{}, nil }`
    d := Forward("");
  case Single(x) =>
    d := CheckSingle(p, x);
    if Forwarded(d) && IsToolCall(x) {
      assert ToolCallsIn(b) == [x.toolName];
    }
  case BatchBody(xs) =>
    d := CheckBatch(p, xs);
    if Forwarded(d) {
      CallNamesCharacterisation(p, xs);
    }
}

// ---------------------------------------------------------------------
// 10. observeRequest -- the pass-through path (mcp_rules: {})
//
// Go: nothing is enforced and nothing is rejected; the method is
// recorded so a tools/list response can be logged. An oversized body is
// forwarded whole and uninspected, which is safe here precisely because
// there are no tool rules to enforce.
// ---------------------------------------------------------------------

method ObserveRequest(p: Policy, b: Body) returns (d: Decision)
  requires !HasToolRules(p)
  ensures Forwarded(d)
  ensures forall n :: n in ToolCallsIn(b) ==> IsToolAllowed(p, n)
{
  d := Forward("");
}

// ---------------------------------------------------------------------
// 11. CheckRequest -- the whole path
//
// Go:
//   if p == nil { return &MCPCheckResult{}, nil }
//   if r.Method != http.MethodPost { return &MCPCheckResult{}, nil }
//   if !p.hasToolRules() { return p.observeRequest(r) }
//   return p.enforceRequest(r)
//
// A non-POST request is forwarded without inspection. MCP carries
// JSON-RPC payloads over POST; GET opens the server-sent-event channel
// and DELETE ends a session, neither of which can invoke a tool. That
// is a statement about the MCP transport, not something proved here,
// so the theorems are stated for POST and the non-POST branch is
// modelled as the uninspected forward it is.
// ---------------------------------------------------------------------

method CheckRequest(p: Policy, isPost: bool, b: Body) returns (d: Decision)

  // --- M3 FAIL CLOSED, at the entry point --------------------------
  ensures HasToolRules(p) && isPost && !Inspectable(b) ==> d.Reject?
  ensures Forwarded(d) && isPost && HasToolRules(p) ==> Inspectable(b)

  // --- M4 THE WHOLE REQUEST PATH -----------------------------------
  //
  // Whatever the mode, a forwarded POST carries no tools/call the
  // policy does not allow. In pass-through mode this holds because the
  // policy allows everything (A3), which is the configured behaviour.
  ensures Forwarded(d) && isPost ==>
          forall n :: n in ToolCallsIn(b) ==> IsToolAllowed(p, n)

  // pass-through never rejects and never denies
  ensures !HasToolRules(p) ==> Forwarded(d)

  ensures Forwarded(d) && isPost && HasToolRules(p) && b.BatchBody? ==>
          AllParsed(b.elems) && NoDeniedCall(p, b.elems)
  ensures isPost && HasToolRules(p) && b.Single? && IsToolCall(b.msg)
          && IsToolDenied(p, b.msg.toolName)
          ==> d == DenyTool(b.msg.toolName, b.msg.id)

  // a non-POST request is forwarded uninspected
  ensures !isPost ==> d == Forward("")
{
  if !isPost {
    return Forward("");
  }
  if !HasToolRules(p) {
    d := ObserveRequest(p, b);
    return d;
  }
  d := EnforceRequest(p, b);
}

// =====================================================================
// The request-side contract, stated once in the form the acceptance
// criteria ask for: for a route WITH tool rules, an uninspectable body
// is rejected, a forwarded body names only allowed tools, and a
// forwarded batch is one in which every element parsed and none was a
// denied call.
// =====================================================================
method MCPRequestContract(p: Policy, b: Body) returns (d: Decision)
  requires WellFormed(p)
  requires HasToolRules(p)
  ensures !Inspectable(b) ==> !Forwarded(d)
  ensures Forwarded(d) ==>
          forall n :: n in ToolCallsIn(b) ==> IsToolAllowed(p, n)
  ensures Forwarded(d) && b.BatchBody? ==>
          AllParsed(b.elems) && NoDeniedCall(p, b.elems)
  ensures b.Single? && IsToolCall(b.msg) && IsToolDenied(p, b.msg.toolName)
          ==> d == DenyTool(b.msg.toolName, b.msg.id)
{
  d := CheckRequest(p, true, b);
}

// =====================================================================
// 12. tools/list response filtering
//
// Go: filterJSONToolsList.
//
//   for _, raw := range tools {
//       var t struct{ Name string `json:"name"` }
//       if err := json.Unmarshal(raw, &t); err != nil {
//           kept = append(kept, raw)   // preserve unparseable entries
//           continue
//       }
//       allNames = append(allNames, t.Name)
//       if p.isToolAllowed(t.Name) {
//           kept = append(kept, raw)
//           allowedNames = append(allowedNames, t.Name)
//       }
//   }
//
// An entry that does not decode into {name string} -- a bare string or
// number in the tools array -- is kept as-is. Unnamed models that
// branch: such an entry contributes no tool name, so it cannot be the
// reason a tools/call is authorized, and L2 below is about named
// entries for that reason.
// =====================================================================

datatype ToolEntry = Named(name: string) | Unnamed

// Go: allNames -- every upstream entry that decoded, in order.
function NamesOf(entries: seq<ToolEntry>): seq<string>
  decreases |entries|
{
  if |entries| == 0 then []
  else if entries[0].Named? then [entries[0].name] + NamesOf(entries[1..])
  else NamesOf(entries[1..])
}

// Go: kept.
function FilterEntries(p: Policy, entries: seq<ToolEntry>): seq<ToolEntry>
  decreases |entries|
{
  if |entries| == 0 then []
  else if entries[0].Unnamed? then
    [entries[0]] + FilterEntries(p, entries[1..])
  else if IsToolAllowed(p, entries[0].name) then
    [entries[0]] + FilterEntries(p, entries[1..])
  else
    FilterEntries(p, entries[1..])
}

// Go: allowedNames.
function FilterNames(p: Policy, names: seq<string>): seq<string>
  decreases |names|
{
  if |names| == 0 then []
  else if IsToolAllowed(p, names[0]) then
    [names[0]] + FilterNames(p, names[1..])
  else
    FilterNames(p, names[1..])
}

// The ascending index map: which positions of `names` survive.
function AllowedIdx(p: Policy, names: seq<string>, from: nat): seq<nat>
  requires from <= |names|
  decreases |names| - from
{
  if from == |names| then []
  else if IsToolAllowed(p, names[from]) then
    [from] + AllowedIdx(p, names, from + 1)
  else
    AllowedIdx(p, names, from + 1)
}

function ApplyIdx(names: seq<string>, idx: seq<nat>): seq<string>
  requires forall j :: 0 <= j < |idx| ==> idx[j] < |names|
  decreases |idx|
{
  if |idx| == 0 then []
  else [names[idx[0]]] + ApplyIdx(names, idx[1..])
}

// Everything L1 needs, by induction on the tail of the list. The range
// conjunct comes first so that the ApplyIdx equation below it is
// well-formed.
lemma AllowedIdxFacts(p: Policy, names: seq<string>, from: nat)
  requires from <= |names|
  ensures var idx := AllowedIdx(p, names, from);
          && (forall j :: 0 <= j < |idx| ==> from <= idx[j] < |names|)
          && (forall j :: 0 <= j < |idx| - 1 ==> idx[j] < idx[j + 1])
          && (forall i :: from <= i < |names| ==>
                (i in idx <==> IsToolAllowed(p, names[i])))
          && FilterNames(p, names[from..]) == ApplyIdx(names, idx)
  decreases |names| - from
{
  if from == |names| {
    assert names[from..] == [];
    return;
  }
  AllowedIdxFacts(p, names, from + 1);
  var rest := AllowedIdx(p, names, from + 1);
  assert names[from..][1..] == names[from + 1..];
  assert names[from..][0] == names[from];

  if IsToolAllowed(p, names[from]) {
    var idx := [from] + rest;
    assert AllowedIdx(p, names, from) == idx;
    assert idx[1..] == rest;
    forall j | 0 <= j < |idx| - 1
      ensures idx[j] < idx[j + 1]
    {
      if j == 0 {
        assert idx[1] == rest[0];
      } else {
        assert idx[j] == rest[j - 1];
        assert idx[j + 1] == rest[j];
      }
    }
    assert ApplyIdx(names, idx) == [names[from]] + ApplyIdx(names, rest);
  } else {
    assert AllowedIdx(p, names, from) == rest;
    assert from !in rest;
  }
}

// --- L1 FILTERING KEEPS EXACTLY THE ALLOWED TOOLS IN ORDER ----------
//
// The filtered name list is the upstream list read through a strictly
// ascending index map that selects precisely the allowed positions. So
// it contains every allowed tool, no denied tool, no invented tool, and
// in the upstream's own order.
lemma FilteredListIsExactlyAllowedInOrder(p: Policy, names: seq<string>)
  ensures var idx := AllowedIdx(p, names, 0);
          && (forall j :: 0 <= j < |idx| ==> idx[j] < |names|)
          && FilterNames(p, names) == ApplyIdx(names, idx)
          && (forall j :: 0 <= j < |idx| - 1 ==> idx[j] < idx[j + 1])
          && (forall i :: 0 <= i < |names| ==>
                (i in idx <==> IsToolAllowed(p, names[i])))
{
  AllowedIdxFacts(p, names, 0);
  assert names[0..] == names;
}

// The membership form of the same fact, and the one the response
// filter's safety rests on: nothing denied survives.
lemma FilterNamesKeepsOnlyAllowed(p: Policy, names: seq<string>)
  ensures forall n :: n in FilterNames(p, names) ==>
          n in names && IsToolAllowed(p, n)
  ensures forall i :: 0 <= i < |names| && IsToolAllowed(p, names[i]) ==>
          names[i] in FilterNames(p, names)
  decreases |names|
{
  if |names| == 0 {
    return;
  }
  FilterNamesKeepsOnlyAllowed(p, names[1..]);
  forall n | n in FilterNames(p, names)
    ensures n in names && IsToolAllowed(p, n)
  {
    if IsToolAllowed(p, names[0]) {
      assert FilterNames(p, names) == [names[0]] + FilterNames(p, names[1..]);
    }
  }
  forall i | 0 <= i < |names| && IsToolAllowed(p, names[i])
    ensures names[i] in FilterNames(p, names)
  {
    if i > 0 {
      assert names[1..][i - 1] == names[i];
    }
  }
}

// The entry-level filter agrees with the name-level filter, and an
// entry with no decodable name is passed through without ever being
// offered to the predicate.
lemma FilterEntriesMatchesFilterNames(p: Policy, entries: seq<ToolEntry>)
  ensures NamesOf(FilterEntries(p, entries)) == FilterNames(p, NamesOf(entries))
  ensures forall e :: e in entries && e.Unnamed? ==> e in FilterEntries(p, entries)
  decreases |entries|
{
  if |entries| == 0 {
    return;
  }
  FilterEntriesMatchesFilterNames(p, entries[1..]);
  if entries[0].Unnamed? {
    assert NamesOf(entries) == NamesOf(entries[1..]);
    assert FilterEntries(p, entries) == [entries[0]] + FilterEntries(p, entries[1..]);
    assert NamesOf([entries[0]] + FilterEntries(p, entries[1..]))
           == NamesOf(FilterEntries(p, entries[1..]));
  } else {
    assert NamesOf(entries) == [entries[0].name] + NamesOf(entries[1..]);
  }
}

// --- L2 LISTING AND CALLING AGREE -----------------------------------
//
// For every tool the upstream advertises: it survives the tools/list
// filter if and only if a tools/call naming it is forwarded. Both sides
// are IsToolAllowed over the same uninterpreted `matcher`, so the two
// paths cannot disagree for any glob behaviour, and a tool hidden from
// the listing cannot be called.
lemma ListingAndCallingAgree(p: Policy, names: seq<string>, i: int)
  requires 0 <= i < |names|
  ensures names[i] in FilterNames(p, names) <==> IsToolAllowed(p, names[i])
{
  FilterNamesKeepsOnlyAllowed(p, names);
}

// The listing request itself is not a tools/call, so it is always
// forwarded whatever the mode; it is the RESPONSE that is filtered.
method ToolsListRequestIsForwarded(p: Policy, id: string) returns (d: Decision)
  ensures d == Forward(ToolsList)
{
  d := CheckSingle(p, Msg(ToolsList, "", id));
}

method HiddenToolsCannotBeCalled(p: Policy, names: seq<string>, i: int, id: string)
  returns (d: Decision)
  requires 0 <= i < |names|
  requires names[i] !in FilterNames(p, names)
  // a tool the listing hides is refused when called, by name and id
  ensures d == DenyTool(names[i], id)
{
  FilterNamesKeepsOnlyAllowed(p, names);
  assert IsToolDenied(p, names[i]);
  d := CheckSingle(p, Msg(ToolsCall, names[i], id));
}

method ListedToolsCanBeCalled(p: Policy, names: seq<string>, i: int, id: string)
  returns (d: Decision)
  requires 0 <= i < |names|
  requires names[i] in FilterNames(p, names)
  // and a tool the listing keeps is forwarded when called
  ensures d == Forward(ToolsCall)
{
  FilterNamesKeepsOnlyAllowed(p, names);
  assert IsToolAllowed(p, names[i]);
  d := CheckSingle(p, Msg(ToolsCall, names[i], id));
}

// =====================================================================
// The two paths, composed: the same policy value decides both, so the
// set of tools an agent can see is exactly the set it can call.
// =====================================================================
method MCPToolContract(p: Policy, names: seq<string>, i: int, id: string)
  returns (listed: seq<string>, d: Decision)
  requires WellFormed(p)
  requires 0 <= i < |names|
  ensures listed == FilterNames(p, names)
  ensures forall n :: n in listed ==> IsToolAllowed(p, n)
  ensures d == (if IsToolAllowed(p, names[i])
                then Forward(ToolsCall)
                else DenyTool(names[i], id))
  ensures (names[i] in listed) <==> Forwarded(d)
{
  listed := FilterNames(p, names);
  FilterNamesKeepsOnlyAllowed(p, names);
  d := CheckSingle(p, Msg(ToolsCall, names[i], id));
}
