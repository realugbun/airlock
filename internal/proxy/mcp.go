package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"path"
	"strings"
	"time"
	"unicode/utf8"
)

const maxMCPBodySize = 10 * 1024 * 1024 // 10 MB

// maxMCPResponseSize caps a non-streaming tools/list response, which is
// buffered in full to filter it. Larger responses fail with 502.
const maxMCPResponseSize = 10 * 1024 * 1024 // 10 MB

// mcpInfoKey stores MCP request metadata in context for ModifyResponse.
type mcpInfoKey struct{}

// mcpRequestInfo carries MCP request metadata through the context.
type mcpRequestInfo struct {
	Method string          // JSON-RPC method (e.g. "tools/list", "tools/call")
	Policy *MCPToolPolicy  // policy for response filtering
}

func withMCPInfo(ctx context.Context, info *mcpRequestInfo) context.Context {
	return context.WithValue(ctx, mcpInfoKey{}, info)
}

func mcpInfoFromContext(ctx context.Context) *mcpRequestInfo {
	if v, ok := ctx.Value(mcpInfoKey{}).(*mcpRequestInfo); ok {
		return v
	}
	return nil
}

// MCPToolPolicyConfig is the input for constructing an MCPToolPolicy.
type MCPToolPolicyConfig struct {
	AllowedTools []string
	DeniedTools  []string
}

// MCPToolPolicy enforces tool-level access control for MCP JSON-RPC requests.
// A nil MCPToolPolicy means no MCP filtering (all requests pass through).
//
// Tool names can be exact strings or glob patterns (using path.Match syntax):
//
//	allowed_tools: ["calendar_*", "drive_get_*"]
//	denied_tools: ["*_delete", "*_remove", "admin_*"]
//
// Exact matches are checked first via map lookup for O(1) performance.
// Glob patterns are checked only when the exact lookup misses.
type MCPToolPolicy struct {
	allowedExact    map[string]struct{}
	allowedPatterns []string
	deniedExact     map[string]struct{}
	deniedPatterns  []string
}

// isGlobPattern returns true if s contains glob metacharacters.
func isGlobPattern(s string) bool {
	return strings.ContainsAny(s, "*?[")
}

// NewMCPToolPolicy creates an MCP tool policy from the given config.
// Returns nil if cfg is nil. Returns a pass-through policy if cfg is
// non-nil but both lists are empty (mcp_rules: {}).
//
// Tool entries may be exact names or glob patterns (*, ?, [chars]).
func NewMCPToolPolicy(cfg *MCPToolPolicyConfig) (*MCPToolPolicy, error) {
	if cfg == nil {
		return nil, nil
	}
	if len(cfg.AllowedTools) > 0 && len(cfg.DeniedTools) > 0 {
		return nil, fmt.Errorf("mcp_rules: cannot set both allowed_tools and denied_tools")
	}

	p := &MCPToolPolicy{}

	for _, t := range cfg.AllowedTools {
		if isGlobPattern(t) {
			// Validate the pattern at config load time.
			if _, err := path.Match(t, ""); err != nil {
				return nil, fmt.Errorf("mcp_rules: invalid glob pattern %q: %w", t, err)
			}
			p.allowedPatterns = append(p.allowedPatterns, t)
		} else {
			if p.allowedExact == nil {
				p.allowedExact = make(map[string]struct{})
			}
			p.allowedExact[t] = struct{}{}
		}
	}

	for _, t := range cfg.DeniedTools {
		if isGlobPattern(t) {
			if _, err := path.Match(t, ""); err != nil {
				return nil, fmt.Errorf("mcp_rules: invalid glob pattern %q: %w", t, err)
			}
			p.deniedPatterns = append(p.deniedPatterns, t)
		} else {
			if p.deniedExact == nil {
				p.deniedExact = make(map[string]struct{})
			}
			p.deniedExact[t] = struct{}{}
		}
	}

	return p, nil
}

// jsonRPCRequest is the minimal structure of an MCP request, as decoded by a
// typical upstream. Request inspection uses parseRPCMessage instead.
type jsonRPCRequest struct {
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
	Params *struct {
		Name string `json:"name"`
	} `json:"params,omitempty"`
}

// jsonRPCErrorResp is a standard JSON-RPC 2.0 error response.
type jsonRPCErrorResp struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Error   struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// MCPCheckResult holds the result of inspecting an MCP request.
type MCPCheckResult struct {
	Denied    bool
	ToolName  string
	RequestID json.RawMessage
	Method    string // JSON-RPC method (e.g. "tools/call", "tools/list")
}

// MCPRequestError reports an MCP request that Airlock refuses to forward
// because it cannot be inspected safely. Status is the HTTP status to return.
type MCPRequestError struct {
	Status int
	Reason string
}

func (e *MCPRequestError) Error() string { return e.Reason }

func mcpReject(status int, reason string) error {
	return &MCPRequestError{Status: status, Reason: reason}
}

// CheckRequest inspects the request body for MCP tool calls and enforces
// the tool policy. It reads and re-attaches the body so downstream handlers
// can still consume it.
//
// When the policy has tool rules, inspection fails closed: a POST body that
// cannot be inspected exactly as the upstream will read it is rejected with an
// *MCPRequestError (400, 413 or 415) instead of being forwarded. Other errors
// are failures to read the request body.
//
// Non-tool MCP methods (initialize, tools/list, ping, etc.) always pass through.
func (p *MCPToolPolicy) CheckRequest(r *http.Request) (*MCPCheckResult, error) {
	if p == nil {
		return &MCPCheckResult{}, nil
	}

	// Only inspect POST requests.
	if r.Method != http.MethodPost {
		return &MCPCheckResult{}, nil
	}

	if !p.hasToolRules() {
		return p.observeRequest(r)
	}
	return p.enforceRequest(r)
}

// enforceRequest inspects a POST on a route with tool rules. Anything that
// could be read differently by the upstream is rejected.
func (p *MCPToolPolicy) enforceRequest(r *http.Request) (*MCPCheckResult, error) {
	// A compressed body would be inspected as opaque bytes while the upstream
	// may decompress it and run the call.
	for _, enc := range r.Header.Values("Content-Encoding") {
		for _, tok := range strings.Split(enc, ",") {
			if t := strings.TrimSpace(tok); t != "" && !strings.EqualFold(t, "identity") {
				return nil, mcpReject(http.StatusUnsupportedMediaType, "Content-Encoding not supported on MCP requests")
			}
		}
	}

	// An empty Content-Type is inspected as JSON. Anything else must parse
	// as a JSON media type.
	cts := r.Header.Values("Content-Type")
	if len(cts) > 1 {
		return nil, mcpReject(http.StatusBadRequest, "multiple Content-Type headers")
	}
	if len(cts) == 1 && !isJSONContentType(cts[0]) {
		return nil, mcpReject(http.StatusUnsupportedMediaType, "MCP requests must be application/json")
	}

	if r.ContentLength > maxMCPBodySize {
		return nil, mcpReject(http.StatusRequestEntityTooLarge, "MCP request body too large")
	}

	body, err := readBodyContext(r.Context(), r.Body, maxMCPBodySize+1)
	if err != nil {
		return nil, fmt.Errorf("reading request body: %w", err)
	}
	_ = r.Body.Close()
	if len(body) > maxMCPBodySize {
		return nil, mcpReject(http.StatusRequestEntityTooLarge, "MCP request body too large")
	}

	// Re-attach body for downstream consumption.
	r.Body = io.NopCloser(bytes.NewReader(body))

	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		// Nothing to execute; the upstream rejects it.
		return &MCPCheckResult{}, nil
	}
	if !utf8.Valid(trimmed) {
		return nil, mcpReject(http.StatusBadRequest, "MCP request body is not valid UTF-8")
	}

	var (
		result *MCPCheckResult
		reason string
	)
	if trimmed[0] == '[' {
		result, reason = p.checkBatch(trimmed)
	} else {
		result, reason = p.checkSingle(trimmed)
	}
	if reason != "" {
		return nil, mcpReject(http.StatusBadRequest, reason)
	}
	return result, nil
}

// observeRequest handles a pass-through policy (mcp_rules: {}). Nothing is
// enforced; the method is recorded so tools/list responses can be logged.
// The body is never truncated.
func (p *MCPToolPolicy) observeRequest(r *http.Request) (*MCPCheckResult, error) {
	if ct := r.Header.Get("Content-Type"); ct != "" && !isJSONContentType(ct) {
		return &MCPCheckResult{}, nil
	}

	body, err := readBodyContext(r.Context(), r.Body, maxMCPBodySize+1)
	if err != nil {
		return nil, fmt.Errorf("reading request body: %w", err)
	}
	if len(body) > maxMCPBodySize {
		// Forward the whole body uninspected.
		r.Body = struct {
			io.Reader
			io.Closer
		}{io.MultiReader(bytes.NewReader(body), r.Body), r.Body}
		return &MCPCheckResult{}, nil
	}
	_ = r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(body))

	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 || trimmed[0] == '[' {
		return &MCPCheckResult{}, nil
	}
	msg, reason := parseRPCMessage(trimmed)
	if reason != "" {
		return &MCPCheckResult{}, nil
	}
	return &MCPCheckResult{Method: msg.method}, nil
}

// readBodyContext reads up to limit bytes from body, returning early with the
// context error if ctx ends first. The abandoned read finishes in the
// background once the connection read deadline fires or the client sends.
//
// Once ctx's deadline has passed, any failure is reported as
// context.DeadlineExceeded. The connection read deadline is set to the same
// instant, and when it fires first net/http cancels the connection context,
// so ctx can end with context.Canceled and the read with some other error,
// depending on which goroutine wins.
func readBodyContext(ctx context.Context, body io.Reader, limit int64) ([]byte, error) {
	if ctx.Done() == nil {
		return io.ReadAll(io.LimitReader(body, limit))
	}
	type result struct {
		b   []byte
		err error
	}
	ch := make(chan result, 1)
	go func() {
		b, err := io.ReadAll(io.LimitReader(body, limit))
		ch <- result{b, err}
	}()
	var err error
	select {
	case res := <-ch:
		if res.err == nil {
			return res.b, nil
		}
		err = res.err
	case <-ctx.Done():
		err = ctx.Err()
	}
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		return nil, fmt.Errorf("%w: %w", context.DeadlineExceeded, err)
	}
	return nil, err
}

// rpcMessage is a JSON-RPC message as inspected by Airlock.
type rpcMessage struct {
	id       json.RawMessage
	method   string
	toolName string // set only for tools/call
}

// parseRPCMessage parses one JSON-RPC message for policy checks. It returns
// a non-empty reason if the message is malformed or ambiguous.
//
// encoding/json matches object keys case-insensitively and keeps the last
// duplicate, while most upstream runtimes are case-sensitive. A body such as
// {"params":{"name":"delete_all","Name":"read"}} would be checked as "read"
// and executed as "delete_all". Keys that drive the policy decision must
// therefore appear exactly once, in exact case.
func parseRPCMessage(raw []byte) (*rpcMessage, string) {
	fields, reason := decodeStrictObject(raw, "method", "params")
	if reason != "" {
		return nil, reason
	}
	msg := &rpcMessage{id: fields["id"]}

	methodRaw, ok := fields["method"]
	if !ok {
		// A response or other method-less message: nothing to execute.
		return msg, ""
	}
	if err := json.Unmarshal(methodRaw, &msg.method); err != nil {
		return nil, "JSON-RPC method must be a string"
	}
	if msg.method != "tools/call" {
		return msg, ""
	}

	paramsRaw, ok := fields["params"]
	if !ok {
		return nil, "tools/call requires params"
	}
	params, reason := decodeStrictObject(paramsRaw, "name")
	if reason != "" {
		return nil, "tools/call params: " + reason
	}
	nameRaw, ok := params["name"]
	if !ok {
		return nil, "tools/call requires params.name"
	}
	if err := json.Unmarshal(nameRaw, &msg.toolName); err != nil || msg.toolName == "" {
		return nil, "tools/call params.name must be a non-empty string"
	}
	return msg, ""
}

// decodeStrictObject decodes raw as a single JSON object. Each guarded key
// must not appear more than once or in any other letter case.
func decodeStrictObject(raw []byte, guarded ...string) (map[string]json.RawMessage, string) {
	if !json.Valid(raw) {
		return nil, "malformed JSON"
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return nil, "JSON-RPC message must be an object"
	}
	fields := make(map[string]json.RawMessage)
	seen := make(map[string]bool, len(guarded))
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, "malformed JSON"
		}
		key, _ := tok.(string)
		for _, g := range guarded {
			if !strings.EqualFold(key, g) {
				continue
			}
			if key != g {
				return nil, fmt.Sprintf("key %q must be lowercase %q", key, g)
			}
			if seen[g] {
				return nil, fmt.Sprintf("duplicate key %q", g)
			}
			seen[g] = true
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, "malformed JSON"
		}
		fields[key] = v
	}
	return fields, ""
}

func (p *MCPToolPolicy) checkSingle(body []byte) (*MCPCheckResult, string) {
	msg, reason := parseRPCMessage(body)
	if reason != "" {
		return nil, reason
	}
	result := &MCPCheckResult{Method: msg.method}
	if msg.method == "tools/call" && p.isToolDenied(msg.toolName) {
		result.Denied = true
		result.ToolName = msg.toolName
		result.RequestID = msg.id
	}
	return result, ""
}

func (p *MCPToolPolicy) checkBatch(body []byte) (*MCPCheckResult, string) {
	var batch []json.RawMessage
	if err := json.Unmarshal(body, &batch); err != nil {
		return nil, "malformed JSON-RPC batch"
	}

	msgs := make([]*rpcMessage, 0, len(batch))
	for i, raw := range batch {
		msg, reason := parseRPCMessage(raw)
		if reason != "" {
			return nil, fmt.Sprintf("batch element %d: %s", i, reason)
		}
		msgs = append(msgs, msg)
	}
	for _, msg := range msgs {
		if msg.method == "tools/call" && p.isToolDenied(msg.toolName) {
			return &MCPCheckResult{
				Denied:    true,
				ToolName:  msg.toolName,
				RequestID: msg.id,
				Method:    "tools/call",
			}, ""
		}
	}
	return &MCPCheckResult{Method: "batch"}, ""
}

func (p *MCPToolPolicy) isToolDenied(name string) bool {
	// Allowlist mode: only listed tools are permitted.
	if p.allowedExact != nil || len(p.allowedPatterns) > 0 {
		if _, ok := p.allowedExact[name]; ok {
			return false
		}
		for _, pat := range p.allowedPatterns {
			if matched, _ := path.Match(pat, name); matched {
				return false
			}
		}
		return true // not in allowlist
	}
	// Denylist mode: only listed tools are blocked.
	if p.deniedExact != nil || len(p.deniedPatterns) > 0 {
		if _, ok := p.deniedExact[name]; ok {
			return true
		}
		for _, pat := range p.deniedPatterns {
			if matched, _ := path.Match(pat, name); matched {
				return true
			}
		}
		return false
	}
	// No lists = pass-through mode.
	return false
}

// isToolAllowed returns true if the tool is permitted by the policy.
func (p *MCPToolPolicy) isToolAllowed(name string) bool {
	return !p.isToolDenied(name)
}

// hasToolRules returns true if the policy has any allow or deny lists configured.
func (p *MCPToolPolicy) hasToolRules() bool {
	return p.allowedExact != nil || len(p.allowedPatterns) > 0 ||
		p.deniedExact != nil || len(p.deniedPatterns) > 0
}

// ToolsFilterResult holds the result of filtering a tools/list response.
type ToolsFilterResult struct {
	Body         []byte   // filtered response body
	AllTools     []string // all tool names from upstream (before filtering)
	AllowedTools []string // tool names that passed the filter
}

// FilterToolsListResponse filters a tools/list JSON-RPC response body,
// removing tools that the policy does not allow. Returns all upstream
// tool names and the allowed subset for logging/debugging.
// If the body is SSE-framed, it handles the envelope.
func (p *MCPToolPolicy) FilterToolsListResponse(body []byte, contentType string) (*ToolsFilterResult, error) {
	if p == nil {
		return &ToolsFilterResult{Body: body}, nil
	}

	// Check for SSE framing.
	if strings.HasPrefix(contentType, "text/event-stream") {
		fr, err := p.filterSSEToolsList(body)
		if err == nil && fr.AllTools != nil {
			return fr, nil
		}
		// SSE parsing found no tools — fall back to JSON parsing.
		// Handles servers that send bare JSON with SSE Content-Type.
	}

	// Plain JSON response (or SSE fallback).
	return p.filterJSONToolsList(body)
}

func (p *MCPToolPolicy) filterJSONToolsList(body []byte) (*ToolsFilterResult, error) {
	// Parse preserving all fields via json.RawMessage.
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(body, &envelope); err != nil {
		return &ToolsFilterResult{Body: body}, nil // pass through unparseable responses
	}

	resultRaw, ok := envelope["result"]
	if !ok {
		return &ToolsFilterResult{Body: body}, nil // no result field (might be an error response)
	}

	var result map[string]json.RawMessage
	if err := json.Unmarshal(resultRaw, &result); err != nil {
		return &ToolsFilterResult{Body: body}, nil
	}

	toolsRaw, ok := result["tools"]
	if !ok {
		return &ToolsFilterResult{Body: body}, nil
	}

	var tools []json.RawMessage
	if err := json.Unmarshal(toolsRaw, &tools); err != nil {
		return &ToolsFilterResult{Body: body}, nil
	}

	// Collect all upstream tool names and filter.
	var kept []json.RawMessage
	var allNames []string
	var allowedNames []string
	for _, raw := range tools {
		var t struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(raw, &t); err != nil {
			kept = append(kept, raw) // preserve unparseable entries
			continue
		}
		allNames = append(allNames, t.Name)
		if p.isToolAllowed(t.Name) {
			kept = append(kept, raw)
			allowedNames = append(allowedNames, t.Name)
		}
	}

	// Re-serialize.
	if kept == nil {
		kept = []json.RawMessage{} // ensure empty array, not null
	}
	filteredTools, err := json.Marshal(kept)
	if err != nil {
		return &ToolsFilterResult{Body: body}, err
	}
	result["tools"] = filteredTools

	filteredResult, err := json.Marshal(result)
	if err != nil {
		return &ToolsFilterResult{Body: body}, err
	}
	envelope["result"] = filteredResult

	out, err := json.Marshal(envelope)
	if err != nil {
		return &ToolsFilterResult{Body: body}, err
	}
	return &ToolsFilterResult{
		Body:         out,
		AllTools:     allNames,
		AllowedTools: allowedNames,
	}, nil
}

func (p *MCPToolPolicy) filterSSEToolsList(body []byte) (*ToolsFilterResult, error) {
	// SSE format: "event: message\ndata: {...}\n\n"
	// Find data: lines, filter JSON within them, reconstruct.
	var buf bytes.Buffer
	var allTools, allowedTools []string

	lines := bytes.Split(body, []byte("\n"))
	for _, line := range lines {
		trimmed := bytes.TrimSpace(line)
		if bytes.HasPrefix(trimmed, []byte("data:")) {
			jsonData := bytes.TrimSpace(bytes.TrimPrefix(trimmed, []byte("data:")))
			if len(jsonData) > 0 && jsonData[0] == '{' {
				fr, err := p.filterJSONToolsList(jsonData)
				if err == nil && fr.AllTools != nil {
					allTools = fr.AllTools
					allowedTools = fr.AllowedTools
					buf.WriteString("data: ")
					buf.Write(fr.Body)
					buf.WriteByte('\n')
					continue
				}
			}
		}
		buf.Write(line)
		buf.WriteByte('\n')
	}

	// Trim trailing extra newline from Split.
	out := buf.Bytes()
	if len(out) > 0 && out[len(out)-1] == '\n' && bytes.HasSuffix(body, []byte("\n")) && !bytes.HasSuffix(body, []byte("\n\n")) {
		out = out[:len(out)-1]
	}

	return &ToolsFilterResult{
		Body:         out,
		AllTools:     allTools,
		AllowedTools: allowedTools,
	}, nil
}

// isJSONContentType reports whether ct is a JSON media type. Media types are
// case-insensitive. A charset parameter, if present, must be UTF-8, since
// that is how the body is inspected.
func isJSONContentType(ct string) bool {
	mt, params, err := mime.ParseMediaType(ct)
	if err != nil {
		return false
	}
	if cs, ok := params["charset"]; ok && !strings.EqualFold(cs, "utf-8") && !strings.EqualFold(cs, "utf8") {
		return false
	}
	return mt == "application/json" || mt == "text/json"
}

// WriteJSONRPCError writes a JSON-RPC 2.0 error response.
func WriteJSONRPCError(w http.ResponseWriter, id json.RawMessage, code int, message string, httpStatus int) {
	resp := jsonRPCErrorResp{
		JSONRPC: "2.0",
		ID:      id,
	}
	resp.Error.Code = code
	resp.Error.Message = message

	if len(resp.ID) == 0 {
		resp.ID = json.RawMessage("null")
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpStatus)
	_ = json.NewEncoder(w).Encode(resp)
}

func newMCPToolFilterReader(r io.ReadCloser, policy *MCPToolPolicy, logger *slog.Logger, route string) io.ReadCloser {
	logged := false
	logDiscovery := func(fr *ToolsFilterResult) {
		if logged {
			return
		}
		logged = true
		logger.Info("MCP tools discovered",
			"route", route,
			"upstream_tools", fr.AllTools,
			"allowed_tools", fr.AllowedTools,
			"upstream_count", len(fr.AllTools),
			"allowed_count", len(fr.AllowedTools),
		)
	}

	return newSSEEventReader(r, func(data []byte) []byte {
		return filterMCPEventData(data, policy, logDiscovery)
	})
}

// filterMCPEventData filters tools/list results in SSE event data.
// Lines starting with "data:" that contain JSON-RPC tools/list results
// have disallowed tools removed. All other lines pass through unchanged.
// If no data: lines are found, falls back to JSON parsing (handles
// bare JSON sent with SSE Content-Type).
func filterMCPEventData(data []byte, policy *MCPToolPolicy, logDiscovery func(*ToolsFilterResult)) []byte {
	lines := bytes.Split(data, []byte("\n"))
	var buf bytes.Buffer
	foundDataLine := false
	modified := false

	for i, line := range lines {
		trimmed := bytes.TrimSpace(line)
		if bytes.HasPrefix(trimmed, []byte("data:")) {
			foundDataLine = true
			jsonData := bytes.TrimSpace(bytes.TrimPrefix(trimmed, []byte("data:")))
			if len(jsonData) > 0 && jsonData[0] == '{' {
				fr, err := policy.filterJSONToolsList(jsonData)
				if err == nil && fr.AllTools != nil {
					logDiscovery(fr)
					buf.WriteString("data: ")
					buf.Write(fr.Body)
					modified = true
					if i < len(lines)-1 {
						buf.WriteByte('\n')
					}
					continue
				}
			}
		}
		buf.Write(line)
		if i < len(lines)-1 {
			buf.WriteByte('\n')
		}
	}

	if modified {
		return buf.Bytes()
	}

	// No data: lines with tools found — try bare JSON fallback.
	if !foundDataLine {
		trimmed := bytes.TrimSpace(data)
		if len(trimmed) > 0 && trimmed[0] == '{' {
			fr, err := policy.filterJSONToolsList(trimmed)
			if err == nil && fr.AllTools != nil {
				logDiscovery(fr)
				return fr.Body
			}
		}
	}

	return data
}
