package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"path"
	"strings"
)

const maxMCPBodySize = 10 * 1024 * 1024 // 10 MB

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

// jsonRPCRequest is the minimal structure needed to inspect MCP requests.
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

// CheckRequest inspects the request body for MCP tool calls and enforces
// the tool policy. It reads and re-attaches the body so downstream handlers
// can still consume it.
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

	// Only inspect JSON content.
	ct := r.Header.Get("Content-Type")
	if ct != "" && !isJSONContentType(ct) {
		return &MCPCheckResult{}, nil
	}

	// Read the body up to the size limit + 1 byte so we can detect oversized
	// requests without buffering arbitrarily large payloads into memory.
	body, err := io.ReadAll(io.LimitReader(r.Body, maxMCPBodySize+1))
	_ = r.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("reading request body: %w", err)
	}

	// Re-attach body for downstream consumption.
	r.Body = io.NopCloser(bytes.NewReader(body))

	// Skip inspection for oversized bodies.
	if len(body) > maxMCPBodySize {
		return &MCPCheckResult{}, nil
	}

	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return &MCPCheckResult{}, nil
	}

	// Batch request (JSON array).
	if trimmed[0] == '[' {
		return p.checkBatch(trimmed)
	}

	// Single request.
	return p.checkSingle(trimmed)
}

func (p *MCPToolPolicy) checkSingle(body []byte) (*MCPCheckResult, error) {
	var req jsonRPCRequest
	if err := json.Unmarshal(body, &req); err != nil {
		// Malformed JSON — let upstream handle the error.
		return &MCPCheckResult{}, nil
	}

	result := &MCPCheckResult{Method: req.Method}

	// Only filter tools/call. All other methods pass through.
	if req.Method != "tools/call" {
		return result, nil
	}

	// tools/call without params or name — pass through, upstream will error.
	if req.Params == nil || req.Params.Name == "" {
		return result, nil
	}

	if p.isToolDenied(req.Params.Name) {
		result.Denied = true
		result.ToolName = req.Params.Name
		result.RequestID = req.ID
	}
	return result, nil
}

func (p *MCPToolPolicy) checkBatch(body []byte) (*MCPCheckResult, error) {
	var batch []jsonRPCRequest
	if err := json.Unmarshal(body, &batch); err != nil {
		// Malformed batch — let upstream handle it.
		return &MCPCheckResult{}, nil
	}

	for _, req := range batch {
		if req.Method != "tools/call" {
			continue
		}
		if req.Params == nil || req.Params.Name == "" {
			continue
		}
		if p.isToolDenied(req.Params.Name) {
			return &MCPCheckResult{
				Denied:    true,
				ToolName:  req.Params.Name,
				RequestID: req.ID,
				Method:    "tools/call",
			}, nil
		}
	}
	return &MCPCheckResult{Method: "batch"}, nil
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

func isJSONContentType(ct string) bool {
	return strings.HasPrefix(ct, "application/json") ||
		strings.HasPrefix(ct, "text/json")
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
