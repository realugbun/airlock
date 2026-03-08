package proxy

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func devNullLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// --- Constructor tests ---

func TestNewMCPToolPolicy_Nil(t *testing.T) {
	p, err := NewMCPToolPolicy(nil)
	require.NoError(t, err)
	assert.Nil(t, p)
}

func TestNewMCPToolPolicy_Empty(t *testing.T) {
	p, err := NewMCPToolPolicy(&MCPToolPolicyConfig{})
	require.NoError(t, err)
	require.NotNil(t, p)
	assert.Nil(t, p.allowedExact)
	assert.Nil(t, p.allowedPatterns)
	assert.Nil(t, p.deniedExact)
	assert.Nil(t, p.deniedPatterns)
}

func TestNewMCPToolPolicy_AllowedTools(t *testing.T) {
	p, err := NewMCPToolPolicy(&MCPToolPolicyConfig{
		AllowedTools: []string{"get_events", "list_calendars"},
	})
	require.NoError(t, err)
	require.NotNil(t, p)
	assert.Len(t, p.allowedExact, 2)
	assert.Contains(t, p.allowedExact, "get_events")
	assert.Contains(t, p.allowedExact, "list_calendars")
	assert.Nil(t, p.deniedExact)
}

func TestNewMCPToolPolicy_DeniedTools(t *testing.T) {
	p, err := NewMCPToolPolicy(&MCPToolPolicyConfig{
		DeniedTools: []string{"delete_event", "send_message"},
	})
	require.NoError(t, err)
	require.NotNil(t, p)
	assert.Nil(t, p.allowedExact)
	assert.Len(t, p.deniedExact, 2)
	assert.Contains(t, p.deniedExact, "delete_event")
}

func TestNewMCPToolPolicy_BothLists_Error(t *testing.T) {
	_, err := NewMCPToolPolicy(&MCPToolPolicyConfig{
		AllowedTools: []string{"get_events"},
		DeniedTools:  []string{"delete_event"},
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot set both")
}

// --- CheckRequest: nil / passthrough ---

func TestMCP_NilPolicy_Passthrough(t *testing.T) {
	var p *MCPToolPolicy
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_all"}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")

	result, err := p.CheckRequest(req)
	require.NoError(t, err)
	assert.False(t, result.Denied)
}

func TestMCP_PassthroughMode_AllowsAll(t *testing.T) {
	p, _ := NewMCPToolPolicy(&MCPToolPolicyConfig{})

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"anything"}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")

	result, err := p.CheckRequest(req)
	require.NoError(t, err)
	assert.False(t, result.Denied)
}

// --- CheckRequest: allowlist mode ---

func TestMCP_AllowedTools_Permits(t *testing.T) {
	p, _ := NewMCPToolPolicy(&MCPToolPolicyConfig{
		AllowedTools: []string{"get_events", "list_calendars"},
	})

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_events","arguments":{}}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")

	result, err := p.CheckRequest(req)
	require.NoError(t, err)
	assert.False(t, result.Denied)
	assert.Equal(t, "tools/call", result.Method)
}

func TestMCP_AllowedTools_Denies(t *testing.T) {
	p, _ := NewMCPToolPolicy(&MCPToolPolicyConfig{
		AllowedTools: []string{"get_events"},
	})

	body := `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"delete_repo","arguments":{}}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")

	result, err := p.CheckRequest(req)
	require.NoError(t, err)
	assert.True(t, result.Denied)
	assert.Equal(t, "delete_repo", result.ToolName)
	assert.Equal(t, "3", string(result.RequestID))
}

// --- CheckRequest: denylist mode ---

func TestMCP_DeniedTools_Blocks(t *testing.T) {
	p, _ := NewMCPToolPolicy(&MCPToolPolicyConfig{
		DeniedTools: []string{"delete_event", "send_message"},
	})

	body := `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"delete_event"}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")

	result, err := p.CheckRequest(req)
	require.NoError(t, err)
	assert.True(t, result.Denied)
	assert.Equal(t, "delete_event", result.ToolName)
}

func TestMCP_DeniedTools_AllowsOthers(t *testing.T) {
	p, _ := NewMCPToolPolicy(&MCPToolPolicyConfig{
		DeniedTools: []string{"delete_event"},
	})

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_events"}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")

	result, err := p.CheckRequest(req)
	require.NoError(t, err)
	assert.False(t, result.Denied)
}

// --- CheckRequest: non-tool methods ---

func TestMCP_NonToolMethod_Passthrough(t *testing.T) {
	p, _ := NewMCPToolPolicy(&MCPToolPolicyConfig{
		AllowedTools: []string{"get_events"}, // strict allowlist
	})

	methods := []string{"initialize", "tools/list", "ping", "notifications/initialized", "resources/list", "prompts/get"}
	for _, m := range methods {
		body := `{"jsonrpc":"2.0","id":1,"method":"` + m + `"}`
		req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")

		result, err := p.CheckRequest(req)
		require.NoError(t, err, "method %s should not error", m)
		assert.False(t, result.Denied, "method %s should pass through", m)
		assert.Equal(t, m, result.Method, "method should be captured")
	}
}

// --- CheckRequest: edge cases ---

func TestMCP_NonPostMethod_Passthrough(t *testing.T) {
	p, _ := NewMCPToolPolicy(&MCPToolPolicyConfig{
		AllowedTools: []string{"get_events"},
	})

	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	result, err := p.CheckRequest(req)
	require.NoError(t, err)
	assert.False(t, result.Denied)
}

func TestMCP_NonJSONContentType_Passthrough(t *testing.T) {
	p, _ := NewMCPToolPolicy(&MCPToolPolicyConfig{
		AllowedTools: []string{"get_events"},
	})

	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString("not json"))
	req.Header.Set("Content-Type", "text/plain")

	result, err := p.CheckRequest(req)
	require.NoError(t, err)
	assert.False(t, result.Denied)
}

func TestMCP_EmptyBody_Passthrough(t *testing.T) {
	p, _ := NewMCPToolPolicy(&MCPToolPolicyConfig{
		AllowedTools: []string{"get_events"},
	})

	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(""))
	req.Header.Set("Content-Type", "application/json")

	result, err := p.CheckRequest(req)
	require.NoError(t, err)
	assert.False(t, result.Denied)
}

func TestMCP_MalformedJSON_Passthrough(t *testing.T) {
	p, _ := NewMCPToolPolicy(&MCPToolPolicyConfig{
		AllowedTools: []string{"get_events"},
	})

	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString("{invalid json"))
	req.Header.Set("Content-Type", "application/json")

	result, err := p.CheckRequest(req)
	require.NoError(t, err)
	assert.False(t, result.Denied)
}

func TestMCP_MissingParams_Passthrough(t *testing.T) {
	p, _ := NewMCPToolPolicy(&MCPToolPolicyConfig{
		AllowedTools: []string{"get_events"},
	})

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call"}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")

	result, err := p.CheckRequest(req)
	require.NoError(t, err)
	assert.False(t, result.Denied)
}

func TestMCP_BodyReattached(t *testing.T) {
	p, _ := NewMCPToolPolicy(&MCPToolPolicyConfig{
		AllowedTools: []string{"get_events"},
	})

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_events"}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")

	result, err := p.CheckRequest(req)
	require.NoError(t, err)
	assert.False(t, result.Denied)

	// Body should still be readable with original content.
	reread, readErr := io.ReadAll(req.Body)
	require.NoError(t, readErr)
	assert.Equal(t, body, string(reread))
}

func TestMCP_NoContentType_InspectsAsJSON(t *testing.T) {
	p, _ := NewMCPToolPolicy(&MCPToolPolicyConfig{
		AllowedTools: []string{"get_events"},
	})

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_repo"}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(body))
	// No Content-Type header — should still inspect.

	result, err := p.CheckRequest(req)
	require.NoError(t, err)
	assert.True(t, result.Denied)
	assert.Equal(t, "delete_repo", result.ToolName)
}

// --- Batch tests ---

func TestMCP_Batch_AllAllowed(t *testing.T) {
	p, _ := NewMCPToolPolicy(&MCPToolPolicyConfig{
		AllowedTools: []string{"get_events", "list_calendars"},
	})

	body := `[
		{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_events"}},
		{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_calendars"}}
	]`
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")

	result, err := p.CheckRequest(req)
	require.NoError(t, err)
	assert.False(t, result.Denied)
}

func TestMCP_Batch_OneDenied_RejectAll(t *testing.T) {
	p, _ := NewMCPToolPolicy(&MCPToolPolicyConfig{
		AllowedTools: []string{"get_events"},
	})

	body := `[
		{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_events"}},
		{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"delete_event"}}
	]`
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")

	result, err := p.CheckRequest(req)
	require.NoError(t, err)
	assert.True(t, result.Denied)
	assert.Equal(t, "delete_event", result.ToolName)
	assert.Equal(t, "2", string(result.RequestID))
}

func TestMCP_Batch_MixedMethods(t *testing.T) {
	p, _ := NewMCPToolPolicy(&MCPToolPolicyConfig{
		AllowedTools: []string{"get_events"},
	})

	body := `[
		{"jsonrpc":"2.0","id":1,"method":"initialize"},
		{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_events"}},
		{"jsonrpc":"2.0","id":3,"method":"tools/list"}
	]`
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")

	result, err := p.CheckRequest(req)
	require.NoError(t, err)
	assert.False(t, result.Denied)
}

func TestMCP_Batch_Empty(t *testing.T) {
	p, _ := NewMCPToolPolicy(&MCPToolPolicyConfig{
		AllowedTools: []string{"get_events"},
	})

	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString("[]"))
	req.Header.Set("Content-Type", "application/json")

	result, err := p.CheckRequest(req)
	require.NoError(t, err)
	assert.False(t, result.Denied)
}

// --- FilterToolsListResponse tests ---

func TestFilterToolsList_Allowlist(t *testing.T) {
	p, _ := NewMCPToolPolicy(&MCPToolPolicyConfig{
		AllowedTools: []string{"get_events", "list_calendars"},
	})

	body := `{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"get_events","description":"Get calendar events"},{"name":"delete_event","description":"Delete an event"},{"name":"list_calendars","description":"List calendars"},{"name":"send_message","description":"Send a message"}]}}`

	fr, err := p.FilterToolsListResponse([]byte(body), "application/json")
	require.NoError(t, err)
	assert.Equal(t, []string{"get_events", "delete_event", "list_calendars", "send_message"}, fr.AllTools)
	assert.Equal(t, []string{"get_events", "list_calendars"}, fr.AllowedTools)

	// Parse filtered response and verify only allowed tools remain.
	var resp map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(fr.Body, &resp))
	var result map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(resp["result"], &result))
	var tools []map[string]interface{}
	require.NoError(t, json.Unmarshal(result["tools"], &tools))
	assert.Len(t, tools, 2)
	assert.Equal(t, "get_events", tools[0]["name"])
	assert.Equal(t, "list_calendars", tools[1]["name"])
	// Verify descriptions are preserved.
	assert.Equal(t, "Get calendar events", tools[0]["description"])
}

func TestFilterToolsList_Denylist(t *testing.T) {
	p, _ := NewMCPToolPolicy(&MCPToolPolicyConfig{
		DeniedTools: []string{"delete_event", "send_message"},
	})

	body := `{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"get_events"},{"name":"delete_event"},{"name":"list_calendars"},{"name":"send_message"}]}}`

	fr, err := p.FilterToolsListResponse([]byte(body), "application/json")
	require.NoError(t, err)
	assert.Equal(t, []string{"get_events", "delete_event", "list_calendars", "send_message"}, fr.AllTools)
	assert.Equal(t, []string{"get_events", "list_calendars"}, fr.AllowedTools)

	var resp map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(fr.Body, &resp))
	var result map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(resp["result"], &result))
	var tools []map[string]interface{}
	require.NoError(t, json.Unmarshal(result["tools"], &tools))
	assert.Len(t, tools, 2)
}

func TestFilterToolsList_Passthrough(t *testing.T) {
	// No rules = pass-through. All tools returned, names still extracted.
	p, _ := NewMCPToolPolicy(&MCPToolPolicyConfig{})

	body := `{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"get_events"},{"name":"delete_event"}]}}`

	fr, err := p.FilterToolsListResponse([]byte(body), "application/json")
	require.NoError(t, err)
	assert.Equal(t, []string{"get_events", "delete_event"}, fr.AllTools)
	assert.Equal(t, []string{"get_events", "delete_event"}, fr.AllowedTools)
	assert.NotEmpty(t, fr.Body)
}

func TestFilterToolsList_EmptyToolsArray(t *testing.T) {
	p, _ := NewMCPToolPolicy(&MCPToolPolicyConfig{
		AllowedTools: []string{"get_events"},
	})

	body := `{"jsonrpc":"2.0","id":2,"result":{"tools":[]}}`

	fr, err := p.FilterToolsListResponse([]byte(body), "application/json")
	require.NoError(t, err)
	assert.Empty(t, fr.AllTools)
	assert.Empty(t, fr.AllowedTools)
	assert.Contains(t, string(fr.Body), `"tools":[]`)
}

func TestFilterToolsList_SSE(t *testing.T) {
	p, _ := NewMCPToolPolicy(&MCPToolPolicyConfig{
		AllowedTools: []string{"get_events"},
	})

	body := "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"tools\":[{\"name\":\"get_events\"},{\"name\":\"delete_event\"}]}}\n\n"

	fr, err := p.FilterToolsListResponse([]byte(body), "text/event-stream")
	require.NoError(t, err)
	assert.Equal(t, []string{"get_events", "delete_event"}, fr.AllTools)
	assert.Equal(t, []string{"get_events"}, fr.AllowedTools)
	assert.Contains(t, string(fr.Body), "event: message")
	assert.Contains(t, string(fr.Body), "get_events")
	assert.NotContains(t, string(fr.Body), "delete_event")
}

func TestFilterToolsList_NilPolicy(t *testing.T) {
	var p *MCPToolPolicy
	body := `{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"anything"}]}}`

	fr, err := p.FilterToolsListResponse([]byte(body), "application/json")
	require.NoError(t, err)
	assert.Nil(t, fr.AllTools)
	assert.Nil(t, fr.AllowedTools)
	assert.Equal(t, body, string(fr.Body))
}

func TestFilterToolsList_SSE_JSONFallback(t *testing.T) {
	// Server sends bare JSON with SSE Content-Type (no data: framing).
	p, _ := NewMCPToolPolicy(&MCPToolPolicyConfig{
		AllowedTools: []string{"get_events"},
	})

	body := `{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"get_events"},{"name":"delete_event"}]}}`
	fr, err := p.FilterToolsListResponse([]byte(body), "text/event-stream")
	require.NoError(t, err)
	assert.Equal(t, []string{"get_events", "delete_event"}, fr.AllTools)
	assert.Equal(t, []string{"get_events"}, fr.AllowedTools)
	assert.Contains(t, string(fr.Body), "get_events")
	assert.NotContains(t, string(fr.Body), "delete_event")
}

func TestFilterToolsList_SSE_CharsetParam(t *testing.T) {
	p, _ := NewMCPToolPolicy(&MCPToolPolicyConfig{
		AllowedTools: []string{"get_events"},
	})

	body := "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"tools\":[{\"name\":\"get_events\"},{\"name\":\"delete_event\"}]}}\n\n"
	fr, err := p.FilterToolsListResponse([]byte(body), "text/event-stream; charset=utf-8")
	require.NoError(t, err)
	assert.Equal(t, []string{"get_events", "delete_event"}, fr.AllTools)
	assert.Equal(t, []string{"get_events"}, fr.AllowedTools)
}

// --- mcpToolFilterReader unit tests ---

func TestMCPToolFilterReader_BasicSSE(t *testing.T) {
	p, _ := NewMCPToolPolicy(&MCPToolPolicyConfig{
		AllowedTools: []string{"get_events", "list_calendars"},
	})

	sseData := "event: message\ndata: " +
		`{"jsonrpc":"2.0","id":2,"result":{"tools":[` +
		`{"name":"get_events"},{"name":"delete_event"},{"name":"list_calendars"}` +
		`]}}` + "\n\n"

	logger := devNullLogger()
	r := newMCPToolFilterReader(io.NopCloser(bytes.NewReader([]byte(sseData))), p, logger, "/mcp")

	out, err := io.ReadAll(r)
	require.NoError(t, err)

	assert.Contains(t, string(out), "get_events")
	assert.Contains(t, string(out), "list_calendars")
	assert.NotContains(t, string(out), "delete_event")
}

func TestMCPToolFilterReader_CRLF(t *testing.T) {
	p, _ := NewMCPToolPolicy(&MCPToolPolicyConfig{
		AllowedTools: []string{"get_events"},
	})

	sseData := "event: message\r\ndata: " +
		`{"jsonrpc":"2.0","id":2,"result":{"tools":[` +
		`{"name":"get_events"},{"name":"delete_event"}` +
		`]}}` + "\r\n\r\n"

	logger := devNullLogger()
	r := newMCPToolFilterReader(io.NopCloser(bytes.NewReader([]byte(sseData))), p, logger, "/mcp")

	out, err := io.ReadAll(r)
	require.NoError(t, err)

	assert.Contains(t, string(out), "get_events")
	assert.NotContains(t, string(out), "delete_event")
}

func TestMCPToolFilterReader_BareJSON(t *testing.T) {
	// JSON without SSE framing — fallback path.
	p, _ := NewMCPToolPolicy(&MCPToolPolicyConfig{
		AllowedTools: []string{"get_events"},
	})

	body := `{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"get_events"},{"name":"delete_event"}]}}`

	logger := devNullLogger()
	r := newMCPToolFilterReader(io.NopCloser(bytes.NewReader([]byte(body))), p, logger, "/mcp")

	out, err := io.ReadAll(r)
	require.NoError(t, err)

	assert.Contains(t, string(out), "get_events")
	assert.NotContains(t, string(out), "delete_event")
}

func TestMCPToolFilterReader_MultipleEvents(t *testing.T) {
	p, _ := NewMCPToolPolicy(&MCPToolPolicyConfig{
		AllowedTools: []string{"get_events"},
	})

	sseData := "event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n\n" +
		"event: message\ndata: " +
		`{"jsonrpc":"2.0","id":2,"result":{"tools":[` +
		`{"name":"get_events"},{"name":"delete_event"}` +
		`]}}` + "\n\n"

	logger := devNullLogger()
	r := newMCPToolFilterReader(io.NopCloser(bytes.NewReader([]byte(sseData))), p, logger, "/mcp")

	out, err := io.ReadAll(r)
	require.NoError(t, err)

	assert.Contains(t, string(out), "get_events")
	assert.NotContains(t, string(out), "delete_event")
	assert.Contains(t, string(out), "notifications/initialized")
}

func TestMCPToolFilterReader_PassthroughNonTools(t *testing.T) {
	// Non-tools SSE events should pass through unmodified.
	p, _ := NewMCPToolPolicy(&MCPToolPolicyConfig{
		AllowedTools: []string{"get_events"},
	})

	sseData := "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"capabilities\":{}}}\n\n"

	logger := devNullLogger()
	r := newMCPToolFilterReader(io.NopCloser(bytes.NewReader([]byte(sseData))), p, logger, "/mcp")

	out, err := io.ReadAll(r)
	require.NoError(t, err)

	assert.Contains(t, string(out), "capabilities")
}

func TestMCPToolFilterReader_SmallReadBuffer(t *testing.T) {
	// Read with a very small buffer to test buffered output handling.
	p, _ := NewMCPToolPolicy(&MCPToolPolicyConfig{
		AllowedTools: []string{"get_events"},
	})

	sseData := "event: message\ndata: " +
		`{"jsonrpc":"2.0","id":2,"result":{"tools":[` +
		`{"name":"get_events"},{"name":"delete_event"}` +
		`]}}` + "\n\n"

	logger := devNullLogger()
	r := newMCPToolFilterReader(io.NopCloser(bytes.NewReader([]byte(sseData))), p, logger, "/mcp")

	// Read byte by byte.
	var result bytes.Buffer
	buf := make([]byte, 1)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			result.Write(buf[:n])
		}
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
	}

	assert.Contains(t, result.String(), "get_events")
	assert.NotContains(t, result.String(), "delete_event")
}

// --- Glob pattern tests ---

func TestNewMCPToolPolicy_GlobAllowed(t *testing.T) {
	p, err := NewMCPToolPolicy(&MCPToolPolicyConfig{
		AllowedTools: []string{"calendar_*", "drive_get_*", "exact_tool"},
	})
	require.NoError(t, err)
	require.NotNil(t, p)
	assert.Len(t, p.allowedPatterns, 2)
	assert.Len(t, p.allowedExact, 1)
}

func TestNewMCPToolPolicy_GlobDenied(t *testing.T) {
	p, err := NewMCPToolPolicy(&MCPToolPolicyConfig{
		DeniedTools: []string{"*_delete", "*_remove", "specific_tool"},
	})
	require.NoError(t, err)
	require.NotNil(t, p)
	assert.Len(t, p.deniedPatterns, 2)
	assert.Len(t, p.deniedExact, 1)
}

func TestNewMCPToolPolicy_InvalidGlob(t *testing.T) {
	_, err := NewMCPToolPolicy(&MCPToolPolicyConfig{
		AllowedTools: []string{"[invalid"},
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid glob pattern")
}

func TestMCP_GlobAllowlist_Permits(t *testing.T) {
	p, _ := NewMCPToolPolicy(&MCPToolPolicyConfig{
		AllowedTools: []string{"calendar_*", "drive_get_*"},
	})

	tests := []struct {
		tool    string
		allowed bool
	}{
		{"calendar_list_events", true},
		{"calendar_create_event", true},
		{"drive_get_file", true},
		{"drive_get_permissions", true},
		{"drive_delete_file", false},   // doesn't match drive_get_*
		{"gmail_send_message", false},   // doesn't match any pattern
	}

	for _, tt := range tests {
		body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + tt.tool + `"}}`
		req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")

		result, err := p.CheckRequest(req)
		require.NoError(t, err, "tool %s", tt.tool)
		if tt.allowed {
			assert.False(t, result.Denied, "tool %s should be allowed", tt.tool)
		} else {
			assert.True(t, result.Denied, "tool %s should be denied", tt.tool)
		}
	}
}

func TestMCP_GlobDenylist_Blocks(t *testing.T) {
	p, _ := NewMCPToolPolicy(&MCPToolPolicyConfig{
		DeniedTools: []string{"*_delete", "*_remove", "admin_*"},
	})

	tests := []struct {
		tool    string
		denied  bool
	}{
		{"calendar_delete", true},
		{"drive_delete", true},
		{"file_remove", true},
		{"admin_reset", true},
		{"admin_config", true},
		{"calendar_list_events", false},
		{"drive_get_file", false},
		{"gmail_send", false},
	}

	for _, tt := range tests {
		body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + tt.tool + `"}}`
		req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")

		result, err := p.CheckRequest(req)
		require.NoError(t, err, "tool %s", tt.tool)
		if tt.denied {
			assert.True(t, result.Denied, "tool %s should be denied", tt.tool)
		} else {
			assert.False(t, result.Denied, "tool %s should be allowed", tt.tool)
		}
	}
}

func TestMCP_GlobMixedWithExact(t *testing.T) {
	// Mix of exact and glob entries in the same list.
	p, _ := NewMCPToolPolicy(&MCPToolPolicyConfig{
		AllowedTools: []string{"get_events", "calendar_*", "drive_list_files"},
	})

	tests := []struct {
		tool    string
		allowed bool
	}{
		{"get_events", true},          // exact match
		{"calendar_create", true},     // glob match
		{"drive_list_files", true},    // exact match
		{"drive_delete_files", false}, // no match
	}

	for _, tt := range tests {
		body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + tt.tool + `"}}`
		req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")

		result, err := p.CheckRequest(req)
		require.NoError(t, err, "tool %s", tt.tool)
		if tt.allowed {
			assert.False(t, result.Denied, "tool %s should be allowed", tt.tool)
		} else {
			assert.True(t, result.Denied, "tool %s should be denied", tt.tool)
		}
	}
}

func TestMCP_GlobFilterToolsList(t *testing.T) {
	// Verify that glob patterns also work for response filtering.
	p, _ := NewMCPToolPolicy(&MCPToolPolicyConfig{
		AllowedTools: []string{"calendar_*"},
	})

	body := `{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"calendar_list"},{"name":"calendar_create"},{"name":"drive_delete"},{"name":"gmail_send"}]}}`

	fr, err := p.FilterToolsListResponse([]byte(body), "application/json")
	require.NoError(t, err)
	assert.Equal(t, []string{"calendar_list", "calendar_create", "drive_delete", "gmail_send"}, fr.AllTools)
	assert.Equal(t, []string{"calendar_list", "calendar_create"}, fr.AllowedTools)
}

func TestMCP_GlobQuestionMark(t *testing.T) {
	// ? matches exactly one character.
	p, _ := NewMCPToolPolicy(&MCPToolPolicyConfig{
		DeniedTools: []string{"tool_?"},
	})

	assert.True(t, p.isToolDenied("tool_a"))
	assert.True(t, p.isToolDenied("tool_1"))
	assert.False(t, p.isToolDenied("tool_ab")) // two chars, doesn't match ?
	assert.False(t, p.isToolDenied("tool_"))    // zero chars, doesn't match ?
}

func TestMCP_GlobCharClass(t *testing.T) {
	// [abc] matches one character from the set.
	p, _ := NewMCPToolPolicy(&MCPToolPolicyConfig{
		DeniedTools: []string{"action_[dr]emove"},
	})

	assert.True(t, p.isToolDenied("action_remove"))
	assert.True(t, p.isToolDenied("action_demove"))
	assert.False(t, p.isToolDenied("action_bemove"))
}

func TestMCP_HasToolRules_Globs(t *testing.T) {
	// Glob-only policy should report hasToolRules.
	p, _ := NewMCPToolPolicy(&MCPToolPolicyConfig{
		DeniedTools: []string{"*_delete"},
	})
	assert.True(t, p.hasToolRules())

	// Empty policy should not.
	p2, _ := NewMCPToolPolicy(&MCPToolPolicyConfig{})
	assert.False(t, p2.hasToolRules())
}

// --- WriteJSONRPCError tests ---

func TestWriteJSONRPCError(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteJSONRPCError(rec, json.RawMessage("3"), -32600, "tool not allowed", http.StatusForbidden)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))

	var resp jsonRPCErrorResp
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, "2.0", resp.JSONRPC)
	assert.Equal(t, "3", string(resp.ID))
	assert.Equal(t, -32600, resp.Error.Code)
	assert.Equal(t, "tool not allowed", resp.Error.Message)
}

func TestWriteJSONRPCError_NilID(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteJSONRPCError(rec, nil, -32600, "error", http.StatusForbidden)

	var resp jsonRPCErrorResp
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, "null", string(resp.ID))
}
