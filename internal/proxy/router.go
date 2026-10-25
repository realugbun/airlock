package proxy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/http/httputil"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/realugbun/airlock/internal/auth"
	"github.com/realugbun/airlock/internal/middleware"
	airlocklog "github.com/realugbun/airlock/pkg/log"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	otelmetric "go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/time/rate"
)

var proxyTracer = otel.Tracer("github.com/realugbun/airlock")

// stripForwardingTransport wraps a RoundTripper and removes X-Forwarded-*
// headers that httputil.ReverseProxy adds after the Director runs.
type stripForwardingTransport struct {
	base http.RoundTripper
}

func (t *stripForwardingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Del("X-Forwarded-For")
	req.Header.Del("X-Forwarded-Host")
	req.Header.Del("X-Forwarded-Proto")
	return t.base.RoundTrip(req)
}

// Route defines a single proxy route.
type Route struct {
	PathPrefix           string
	StripPrefix          string
	Upstream             *url.URL
	Auth                 auth.AuthProvider
	Access               *AccessPolicy
	Limiter              *rate.Limiter
	StripResponseHeaders []string
	Timeout              time.Duration
	IdleTimeout          time.Duration
	StripAgentAuth       bool
	StripForwardHeaders  bool
	ExtraHeaders         map[string]string
	MCPRules             *MCPToolPolicy
	proxy                *httputil.ReverseProxy
}

// RouterConfig holds router settings.
type RouterConfig struct {
	AgentID string
	Logger  *slog.Logger
}

// Router matches incoming requests to routes and proxies them upstream.
// Routes can be swapped at runtime via SetRoutes for config reload.
type Router struct {
	mu               sync.RWMutex
	routes           []*Route
	agentID          string
	logger           *slog.Logger
	requestCounter   otelmetric.Int64Counter
	durationHisto    otelmetric.Float64Histogram
	rateLimitCounter otelmetric.Int64Counter
	authRefreshCount otelmetric.Int64Counter
	mcpDeniedCounter otelmetric.Int64Counter
}

// NewRouter creates a new router.
func NewRouter(cfg RouterConfig) *Router {
	meter := otel.Meter("github.com/realugbun/airlock")

	requestCounter, _ := meter.Int64Counter("gateway.requests",
		otelmetric.WithDescription("Total requests by route and status"))
	durationHisto, _ := meter.Float64Histogram("gateway.request.duration",
		otelmetric.WithDescription("Request duration by route and method"),
		otelmetric.WithUnit("ms"))
	rateLimitCounter, _ := meter.Int64Counter("gateway.rate_limit.rejected",
		otelmetric.WithDescription("Rate limit rejections by route"))
	authRefreshCount, _ := meter.Int64Counter("gateway.auth.refreshes",
		otelmetric.WithDescription("Auth token refresh events"))
	mcpDeniedCounter, _ := meter.Int64Counter("gateway.mcp.tool_denied",
		otelmetric.WithDescription("MCP tool call denials by route and tool"))

	return &Router{
		agentID:          cfg.AgentID,
		logger:           cfg.Logger,
		requestCounter:   requestCounter,
		durationHisto:    durationHisto,
		rateLimitCounter: rateLimitCounter,
		authRefreshCount: authRefreshCount,
		mcpDeniedCounter: mcpDeniedCounter,
	}
}

// AddRoute registers a route. The reverse proxy is created automatically.
func (rt *Router) AddRoute(route *Route) {
	initRouteProxy(route, rt.logger)
	rt.mu.Lock()
	rt.routes = append(rt.routes, route)
	rt.mu.Unlock()
}

// SetRoutes atomically replaces all routes. In-flight requests on old routes
// complete normally; new requests use the new routes.
func (rt *Router) SetRoutes(routes []*Route) {
	for _, route := range routes {
		initRouteProxy(route, rt.logger)
	}
	rt.mu.Lock()
	rt.routes = routes
	rt.mu.Unlock()
}

// redactKey is the context key for credential values to redact from responses.
type redactKey struct{}

func withRedactValues(ctx context.Context, values []string) context.Context {
	return context.WithValue(ctx, redactKey{}, values)
}

func redactValuesFromContext(ctx context.Context) []string {
	if v, ok := ctx.Value(redactKey{}).([]string); ok {
		return v
	}
	return nil
}

func initRouteProxy(route *Route, logger *slog.Logger) {
	upstream := route.Upstream
	stripPrefix := route.StripPrefix
	stripHeaders := route.StripResponseHeaders
	idleTimeout := route.IdleTimeout
	routePrefix := route.PathPrefix

	// Use a custom transport instead of http.DefaultTransport to avoid
	// ForceAttemptHTTP2 which breaks plain HTTP upstreams (returns 502).
	transport := &http.Transport{
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:  10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	stripFwd := route.StripForwardHeaders
	var baseTransport http.RoundTripper = otelhttp.NewTransport(transport)
	if stripFwd {
		baseTransport = &stripForwardingTransport{base: baseTransport}
	}
	route.proxy = &httputil.ReverseProxy{
		// Director is deprecated in favour of Rewrite as of Go 1.26. Migrating is
		// not a drop-in change: Rewrite does not populate X-Forwarded-For the way
		// Director does, which interacts directly with the strip_forwarding_headers
		// route option, so it needs its own change with dedicated tests.
		//nolint:staticcheck // SA1019: Director -> Rewrite migration handled separately
		Director: func(req *http.Request) {
			req.URL.Scheme = upstream.Scheme
			req.URL.Host = upstream.Host
			req.Host = upstream.Host
			if stripPrefix != "" {
				req.URL.Path = strings.TrimPrefix(req.URL.Path, stripPrefix)
				if req.URL.Path == "" {
					req.URL.Path = "/"
				}
			}
		},
		Transport: baseTransport,
		ModifyResponse: func(resp *http.Response) error {
			redactValues := redactValuesFromContext(resp.Request.Context())

			// Fail closed if the body reached us still encoded. Redaction is
			// exact-string matching over plaintext: scanning compressed bytes
			// finds nothing, so the credential would pass through to the agent
			// silently. The Go transport strips Content-Encoding when it
			// transparently gunzips, so a non-identity value here means the body
			// was NOT decoded — e.g. the upstream answered br/zstd despite
			// negotiation, or a Range/HEAD request suppressed the transport's
			// automatic gzip handling.
			if len(redactValues) > 0 {
				if enc := strings.TrimSpace(resp.Header.Get("Content-Encoding")); enc != "" && !strings.EqualFold(enc, "identity") {
					return fmt.Errorf("refusing to forward %q-encoded response while credential redaction is active", enc)
				}
			}

			// Wrap body with idle timeout reader if configured.
			// Layered under the redacting reader so idle monitoring
			// tracks raw upstream bytes, not buffered/redacted output.
			if idleTimeout > 0 {
				if cancelFn := idleCancelFromContext(resp.Request.Context()); cancelFn != nil {
					resp.Body = newIdleTimeoutReader(resp.Body, idleTimeout, cancelFn)
				}
			}

			// Filter tools/list responses if MCP rules are configured.
			mcpFiltered := false
			if mcpInfo := mcpInfoFromContext(resp.Request.Context()); mcpInfo != nil && mcpInfo.Method == "tools/list" {
				ct := resp.Header.Get("Content-Type")

				if strings.HasPrefix(ct, "text/event-stream") {
					// SSE: stream events through a filter to avoid io.ReadAll
					// blocking on long-lived connections.
					resp.Body = newMCPToolFilterReader(resp.Body, mcpInfo.Policy, logger, routePrefix)
					resp.ContentLength = -1
					resp.Header.Del("Content-Length")
				} else {
					// JSON: ReadAll is safe (server closes connection after response).
					body, readErr := io.ReadAll(resp.Body)
					_ = resp.Body.Close()
					if readErr != nil {
						resp.Body = io.NopCloser(bytes.NewReader(nil))
					} else {
						fr, filterErr := mcpInfo.Policy.FilterToolsListResponse(body, ct)
						if filterErr == nil && fr.AllTools != nil {
							logger.Info("MCP tools discovered",
								"route", routePrefix,
								"upstream_tools", fr.AllTools,
								"allowed_tools", fr.AllowedTools,
								"upstream_count", len(fr.AllTools),
								"allowed_count", len(fr.AllowedTools),
							)
							resp.Body = io.NopCloser(bytes.NewReader(fr.Body))
							resp.ContentLength = int64(len(fr.Body))
							resp.Header.Set("Content-Length", strconv.Itoa(len(fr.Body)))
						} else {
							resp.Body = io.NopCloser(bytes.NewReader(body))
						}
					}
				}
				mcpFiltered = true
			}

			// SSE transport fallback: the tools/list response may arrive on
			// a long-lived GET stream that doesn't carry mcpInfo (which is
			// only set when the POST body contains a tools/list method).
			// Apply the filter to all SSE responses on MCP-filtered routes.
			// The filter passes non-tools events through unchanged, so
			// overhead is negligible.
			if !mcpFiltered && route.MCPRules != nil && route.MCPRules.hasToolRules() &&
				strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
				resp.Body = newMCPToolFilterReader(resp.Body, route.MCPRules, logger, routePrefix)
				resp.ContentLength = -1
				resp.Header.Del("Content-Length")
			}

			// Redact credential values from response headers.
			if len(redactValues) > 0 {
				redactHeaderValues(resp.Header, redactValues)
			}

			// Strip configured response headers.
			for _, h := range stripHeaders {
				resp.Header.Del(h)
			}

			// Wrap response body with a redacting reader.
			// SSE streams use an event-boundary-aware reader that
			// flushes on \n\n instead of using a carry buffer (which
			// starves small SSE events). Non-SSE uses the standard
			// carry-buffer reader for cross-chunk token detection.
			if len(redactValues) > 0 {
				isSSE := false
				if ct := resp.Header.Get("Content-Type"); ct != "" {
					if baseCT, _, _ := mime.ParseMediaType(ct); baseCT == "text/event-stream" {
						isSSE = true
					}
				}
				if isSSE {
					resp.Body = newSSERedactingReader(resp.Body, redactValues)
				} else {
					resp.Body = newRedactingReader(resp.Body, redactValues)
				}
				resp.ContentLength = -1
				resp.Header.Del("Content-Length")

				// Trailers, declared or not, are filled in when the upstream
				// body reaches EOF and copied to the agent after the body.
				// Redact them at that point.
				resp.Body = &trailerRedactingBody{ReadCloser: resp.Body, resp: resp, secrets: redactValues}
			}

			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if r.Context().Err() != nil {
				http.Error(w, "Gateway Timeout", http.StatusGatewayTimeout)
				return
			}
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
		},
	}
}

func (rt *Router) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/healthz" {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
		return
	}

	// Reject encoded path separators (%2f, %5c) to prevent interpretation
	// mismatches between the policy (which sees decoded r.URL.Path) and
	// upstreams (which may interpret the raw encoding differently).
	// Use RawPath when set; fall back to EscapedPath() to catch edge cases
	// where RawPath is empty (e.g., %5C uppercase matches Go's re-encoding).
	if containsEncodedPathSep(r.URL.RawPath, r.URL.EscapedPath()) {
		rt.logger.Warn("rejected request with encoded path separator",
			"path", r.URL.Path,
			"remote", r.RemoteAddr,
		)
		http.Error(w, "Bad Request: encoded path separators not allowed", http.StatusBadRequest)
		return
	}

	route := rt.matchRoute(r.URL.Path)
	if route == nil {
		http.NotFound(w, r)
		return
	}

	rt.handleRoute(route, w, r)
}

// containsEncodedPathSep checks for %2f or %5c (case-insensitive) in encoded paths.
// rawPath is r.URL.RawPath (set when encoding differs from decoded path).
// escapedPath is r.URL.EscapedPath() (always available, catches edge cases like %5C).
func containsEncodedPathSep(rawPath, escapedPath string) bool {
	check := rawPath
	if check == "" {
		check = escapedPath
	}
	if check == "" {
		return false
	}
	lower := strings.ToLower(check)
	return strings.Contains(lower, "%2f") || strings.Contains(lower, "%5c")
}

func (rt *Router) matchRoute(path string) *Route {
	rt.mu.RLock()
	routes := rt.routes
	rt.mu.RUnlock()

	for _, route := range routes {
		if strings.HasPrefix(path, route.PathPrefix) {
			return route
		}
	}
	return nil
}

func (rt *Router) handleRoute(route *Route, w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	correlationID := airlocklog.CorrelationIDFromContext(ctx)

	targetPath := strings.TrimPrefix(r.URL.Path, route.StripPrefix)
	if targetPath == "" {
		targetPath = "/"
	}

	// Start OTel span
	ctx, span := proxyTracer.Start(ctx, "proxy.request",
		trace.WithAttributes(
			attribute.String("route", route.PathPrefix),
			attribute.String("method", r.Method),
			attribute.String("target_path", targetPath),
			attribute.String("correlation_id", correlationID),
		),
	)
	defer span.End()
	r = r.WithContext(ctx)

	rl := middleware.RequestLogFromContext(ctx)
	if rl != nil {
		rl.Route = route.PathPrefix
		rl.TargetPath = targetPath
	}

	// Access policy check (method + path)
	if !route.Access.Allowed(r.Method, targetPath) {
		if rl != nil {
			rl.Message = "blocked by access policy"
		}
		span.SetAttributes(attribute.String("status", "blocked"))
		rt.requestCounter.Add(ctx, 1,
			otelmetric.WithAttributes(
				attribute.String("route", route.PathPrefix),
				attribute.String("status", "blocked"),
			))
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// Rate limit check
	if route.Limiter != nil && !route.Limiter.Allow() {
		if rl != nil {
			rl.Message = "rate limit exceeded"
		}
		span.SetAttributes(attribute.String("status", "rate_limited"))
		rt.rateLimitCounter.Add(ctx, 1,
			otelmetric.WithAttributes(attribute.String("route", route.PathPrefix)))
		rt.requestCounter.Add(ctx, 1,
			otelmetric.WithAttributes(
				attribute.String("route", route.PathPrefix),
				attribute.String("status", "rate_limited"),
			))
		http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
		return
	}

	// MCP tool-level access control.
	if route.MCPRules != nil {
		mcpResult, mcpErr := route.MCPRules.CheckRequest(r)
		if mcpErr != nil {
			rt.rejectMCPRequest(ctx, w, rl, span, route, correlationID, mcpErr)
			return
		}
		// Store MCP info in context for ModifyResponse to use.
		if mcpResult.Method != "" {
			ctx = withMCPInfo(ctx, &mcpRequestInfo{
				Method: mcpResult.Method,
				Policy: route.MCPRules,
			})
		}
		if mcpResult.Denied {
			if rl != nil {
				rl.Message = "blocked by MCP tool policy"
			}
			span.SetAttributes(
				attribute.String("status", "mcp_denied"),
				attribute.String("mcp.tool", mcpResult.ToolName),
			)
			rt.mcpDeniedCounter.Add(ctx, 1,
				otelmetric.WithAttributes(
					attribute.String("route", route.PathPrefix),
					attribute.String("tool", mcpResult.ToolName),
				))
			rt.requestCounter.Add(ctx, 1,
				otelmetric.WithAttributes(
					attribute.String("route", route.PathPrefix),
					attribute.String("status", "mcp_denied"),
				))
			WriteJSONRPCError(w, mcpResult.RequestID, -32600,
				fmt.Sprintf("tool %q is not allowed", mcpResult.ToolName),
				http.StatusForbidden)
			return
		}
	}

	// Remove hop-by-hop headers before injecting credentials. Otherwise an
	// agent can send "Connection: Authorization" and ReverseProxy deletes
	// the injected header after the Director has run.
	removeHopByHopHeaders(r.Header)

	// Strip agent-supplied auth headers before injecting real credentials.
	if route.StripAgentAuth {
		r.Header.Del("Authorization")
		r.Header.Del("x-api-key")
		r.Header.Del("X-Api-Key")
	}

	// Auth injection — capture credential values for response redaction.
	redactValues, err := route.Auth.AddAuth(ctx, r)
	if err != nil {
		if rl != nil {
			rl.Message = "failed to inject auth"
		}
		rt.logger.Error("auth injection failed",
			"correlation_id", correlationID,
			"route", route.PathPrefix,
			"error", err.Error(),
		)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Inject extra static headers.
	for key, value := range route.ExtraHeaders {
		r.Header.Set(key, value)
	}

	// Store redact values in context for ModifyResponse to use.
	if len(redactValues) > 0 {
		ctx = withRedactValues(ctx, redactValues)
		// ReverseProxy forwards 1xx responses (e.g. 103 Early Hints) as soon
		// as they arrive, before ModifyResponse can redact their headers.
		// Drop them on credentialed routes.
		w = &informationalSuppressingWriter{ResponseWriter: w}
		// Response redaction operates on the decoded body. If the upstream
		// compresses the response (Content-Encoding: gzip/br/zstd), the
		// redacting readers would (a) scan compressed bytes and silently miss
		// the secrets, and (b) corrupt the framing — the SSE reader flushes on
		// \n\n boundaries that occur randomly in a binary stream — which reaches
		// the agent as a "ZlibError"/invalid-compressed-data decode failure.
		// Drop the agent's Accept-Encoding so the upstream returns a body the
		// Go transport hands back decoded; redaction then sees plaintext and the
		// agent receives an identity-encoded response.
		r.Header.Del("Accept-Encoding")
		// Range/If-Range defeat redaction two ways: they suppress the Go
		// transport's automatic gzip negotiation (so the body arrives encoded),
		// and byte-range slicing lets an agent reassemble a credential from
		// fragments that individually contain no complete match.
		r.Header.Del("Range")
		r.Header.Del("If-Range")
	}

	// Apply request timeouts.
	if route.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, route.Timeout)
		defer cancel()
	}
	if route.IdleTimeout > 0 {
		var idleCancel context.CancelFunc
		ctx, idleCancel = withIdleCancel(ctx)
		defer idleCancel()
	}
	r = r.WithContext(ctx)

	// Inject agent headers
	if rt.agentID != "" {
		r.Header.Set(middleware.AgentIDHeader, rt.agentID)
	}
	r.Header.Set(middleware.CorrelationHeader, correlationID)

	if rl != nil {
		rl.Message = "proxied request"
	}
	span.SetAttributes(attribute.String("status", "proxied"))
	rt.requestCounter.Add(ctx, 1,
		otelmetric.WithAttributes(
			attribute.String("route", route.PathPrefix),
			attribute.String("status", "proxied"),
		))

	route.proxy.ServeHTTP(w, r)
}

// rejectMCPRequest writes the response for a request whose MCP body could not
// be inspected. Policy rejections carry their own status; anything else is a
// failure to read the request body.
func (rt *Router) rejectMCPRequest(ctx context.Context, w http.ResponseWriter, rl *middleware.RequestLog, span trace.Span, route *Route, correlationID string, err error) {
	status := http.StatusBadRequest
	msg := "Bad Request: could not read request body"
	var reqErr *MCPRequestError
	if errors.As(err, &reqErr) {
		status = reqErr.Status
		msg = http.StatusText(status) + ": " + reqErr.Reason
	}
	if rl != nil {
		rl.Message = "MCP request rejected"
	}
	span.SetAttributes(attribute.String("status", "mcp_rejected"))
	rt.requestCounter.Add(ctx, 1,
		otelmetric.WithAttributes(
			attribute.String("route", route.PathPrefix),
			attribute.String("status", "mcp_rejected"),
		))
	rt.logger.Warn("MCP request rejected",
		"correlation_id", correlationID,
		"route", route.PathPrefix,
		"status", status,
		"error", err.Error(),
	)
	http.Error(w, msg, status)
}

// hopByHopHeaders are the standard hop-by-hop headers removed by
// httputil.ReverseProxy, plus Proxy-Connection.
var hopByHopHeaders = []string{
	"Connection",
	"Proxy-Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

// removeHopByHopHeaders deletes the Connection header, every header it
// nominates, and the standard hop-by-hop headers. Like ReverseProxy, it
// keeps "Te: trailers" and an Upgrade request, which ReverseProxy re-adds
// itself and which cannot nominate anything once rebuilt here.
func removeHopByHopHeaders(h http.Header) {
	upgrade := ""
	if headerValuesContainToken(h["Connection"], "upgrade") {
		upgrade = h.Get("Upgrade")
	}
	teTrailers := headerValuesContainToken(h["Te"], "trailers")

	for _, v := range h["Connection"] {
		for _, f := range strings.Split(v, ",") {
			if f = textproto.TrimString(f); f != "" {
				h.Del(f)
			}
		}
	}
	for _, name := range hopByHopHeaders {
		h.Del(name)
	}

	if teTrailers {
		h.Set("Te", "trailers")
	}
	if upgrade != "" {
		h.Set("Connection", "Upgrade")
		h.Set("Upgrade", upgrade)
	}
}

func headerValuesContainToken(values []string, token string) bool {
	for _, v := range values {
		for _, f := range strings.Split(v, ",") {
			if strings.EqualFold(textproto.TrimString(f), token) {
				return true
			}
		}
	}
	return false
}

// trailerRedactingBody redacts the response trailers once the body has been
// read to the end, which is when the transport populates them.
type trailerRedactingBody struct {
	io.ReadCloser
	resp    *http.Response
	secrets []string
	done    bool
}

func (b *trailerRedactingBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err != nil {
		b.redact()
	}
	return n, err
}

func (b *trailerRedactingBody) Close() error {
	err := b.ReadCloser.Close()
	b.redact()
	return err
}

func (b *trailerRedactingBody) redact() {
	if b.done {
		return
	}
	b.done = true
	if len(b.resp.Trailer) > 0 {
		redactHeaderValues(b.resp.Trailer, b.secrets)
	}
}

// informationalSuppressingWriter drops 1xx informational responses other
// than 101 Switching Protocols.
type informationalSuppressingWriter struct {
	http.ResponseWriter
}

func (w *informationalSuppressingWriter) WriteHeader(code int) {
	if code >= 100 && code < 200 && code != http.StatusSwitchingProtocols {
		return
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *informationalSuppressingWriter) Flush() {
	_ = http.NewResponseController(w.ResponseWriter).Flush()
}

func (w *informationalSuppressingWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}
