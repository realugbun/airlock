package proxy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/realugbun/airlock/internal/auth"
	"github.com/realugbun/airlock/internal/middleware"
	airlocklog "github.com/realugbun/airlock/pkg/log"
	utls "github.com/refraction-networking/utls"
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
	TLSFingerprint       string
	MCPRules             *MCPToolPolicy
	proxy                *httputil.ReverseProxy
	directClient         *http.Client       // used instead of proxy when useDirectProxy is true
	directTransport      http.RoundTripper  // the otelhttp-wrapped transport for directClient
	useDirectProxy       bool               // true when TLS fingerprint requires bypassing httputil.ReverseProxy
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

// utlsClientHelloID maps a tls_fingerprint config value to a uTLS ClientHelloID.
// Returns nil for empty/"go" (use default Go TLS).
func utlsClientHelloID(name string) *utls.ClientHelloID {
	switch name {
	case "chrome":
		id := utls.HelloChrome_Auto
		return &id
	case "firefox":
		id := utls.HelloFirefox_Auto
		return &id
	case "random":
		id := utls.HelloRandomized
		return &id
	default:
		return nil
	}
}

func initRouteProxy(route *Route, logger *slog.Logger) {
	upstream := route.Upstream
	stripPrefix := route.StripPrefix
	stripHeaders := route.StripResponseHeaders
	idleTimeout := route.IdleTimeout
	routePrefix := route.PathPrefix

	// Enable HTTP/2 for HTTPS upstreams (needed for Cloudflare-protected
	// sites that fingerprint the TLS ClientHello). Plain HTTP upstreams
	// must stay on HTTP/1.1 — ForceAttemptHTTP2 returns 502 for them.
	useHTTP2 := upstream.Scheme == "https"
	transport := &http.Transport{
		ForceAttemptHTTP2:     useHTTP2,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:  10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	// When a TLS fingerprint is configured, use uTLS to present a
	// browser-like ClientHello instead of Go's default fingerprint.
	// This bypasses Cloudflare-style bot detection on upstreams.
	//
	// We use HelloCustom with the browser's spec but strip h2 from
	// ALPN, forcing HTTP/1.1. This avoids Go's HTTP/2 SETTINGS frame
	// fingerprint (which Cloudflare also detects) while keeping the
	// browser TLS ClientHello fingerprint intact.
	if helloID := utlsClientHelloID(route.TLSFingerprint); helloID != nil && upstream.Scheme == "https" {
		fingerprint := *helloID
		transport.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialer := &net.Dialer{Timeout: 10 * time.Second}
			tcpConn, err := dialer.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				host = addr
			}
			// Get the browser spec and replace h2 with http/1.1 in ALPN.
			spec, specErr := utls.UTLSIdToSpec(fingerprint)
			if specErr != nil {
				_ = tcpConn.Close()
				return nil, fmt.Errorf("utls spec: %w", specErr)
			}
			for i, ext := range spec.Extensions {
				if alpn, ok := ext.(*utls.ALPNExtension); ok {
					alpn.AlpnProtocols = []string{"http/1.1"}
					spec.Extensions[i] = alpn
				}
			}
			utlsConn := utls.UClient(tcpConn, &utls.Config{
				ServerName:         host,
				InsecureSkipVerify: false,
			}, utls.HelloCustom)
			if err := utlsConn.ApplyPreset(&spec); err != nil {
				_ = tcpConn.Close()
				return nil, fmt.Errorf("utls apply preset: %w", err)
			}
			if err := utlsConn.HandshakeContext(ctx); err != nil {
				_ = tcpConn.Close()
				return nil, err
			}
			return utlsConn, nil
		}
		transport.TLSHandshakeTimeout = 0
		transport.ForceAttemptHTTP2 = false
	}

	stripFwd := route.StripForwardHeaders
	var baseTransport http.RoundTripper = otelhttp.NewTransport(transport)
	if stripFwd {
		baseTransport = &stripForwardingTransport{base: baseTransport}
	}

	// For routes with a TLS fingerprint on HTTPS upstreams, use a direct
	// http.Client instead of httputil.ReverseProxy. ReverseProxy modifies
	// HTTP/2 framing (SETTINGS, HEADERS) in ways that Cloudflare's bot
	// detection catches. A plain http.Client.Do() with the same
	// http2.Transport + uTLS preserves the browser-like fingerprint.
	if utlsClientHelloID(route.TLSFingerprint) != nil && upstream.Scheme == "https" {
		route.useDirectProxy = true
		// Use the raw transport without otelhttp wrapper for fingerprinted
		// routes. The otelhttp wrapper adds traceparent/tracestate headers
		// that can contribute to bot detection fingerprinting.
		route.directTransport = transport
		route.directClient = &http.Client{
			Transport: transport,
			// Don't follow redirects — proxy should return them as-is.
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}

	route.proxy = &httputil.ReverseProxy{
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
			// Join the upstream base path with the request path.
			// e.g. upstream=/backend-api/codex + request=/responses = /backend-api/codex/responses
			if upstream.Path != "" && upstream.Path != "/" {
				req.URL.Path = strings.TrimRight(upstream.Path, "/") + req.URL.Path
			}
		},
		Transport: baseTransport,
		ModifyResponse: func(resp *http.Response) error {
			redactValues := redactValuesFromContext(resp.Request.Context())

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

// hopByHopHeaders are HTTP/1.1 hop-by-hop headers that must not be forwarded.
var hopByHopHeaders = map[string]bool{
	"Connection":          true,
	"Keep-Alive":          true,
	"Proxy-Authenticate":  true,
	"Proxy-Authorization": true,
	"Te":                  true,
	"Trailer":             true,
	"Transfer-Encoding":   true,
	"Upgrade":             true,
}

// serveDirectProxy handles a request by making a direct http.Client.Do() call
// to the upstream, bypassing httputil.ReverseProxy. This preserves the HTTP/2
// framing generated by http2.Transport + uTLS, which is critical for passing
// Cloudflare's TLS/HTTP2 fingerprinting checks.
func (rt *Router) serveDirectProxy(route *Route, w http.ResponseWriter, r *http.Request) {
	upstream := route.Upstream

	// Build the upstream URL.
	targetPath := r.URL.Path
	if route.StripPrefix != "" {
		targetPath = strings.TrimPrefix(targetPath, route.StripPrefix)
		if targetPath == "" {
			targetPath = "/"
		}
	}
	upstreamURL := *upstream
	// Join the upstream base path with the target path.
	// e.g. upstream=/backend-api/codex + target=/responses = /backend-api/codex/responses
	if upstream.Path != "" && upstream.Path != "/" {
		upstreamURL.Path = strings.TrimRight(upstream.Path, "/") + targetPath
	} else {
		upstreamURL.Path = targetPath
	}
	upstreamURL.RawQuery = r.URL.RawQuery

	// Create the outbound request with the same context (carries timeout, cancel, etc.).
	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, upstreamURL.String(), r.Body)
	if err != nil {
		rt.logger.Error("failed to create upstream request",
			"error", err.Error(),
			"route", route.PathPrefix,
		)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Copy headers, skipping hop-by-hop headers.
	for key, values := range r.Header {
		if hopByHopHeaders[http.CanonicalHeaderKey(key)] {
			continue
		}
		for _, v := range values {
			outReq.Header.Add(key, v)
		}
	}
	outReq.Host = upstream.Host

	// Make the request.
	resp, err := route.directClient.Do(outReq)
	if err != nil {
		if r.Context().Err() != nil {
			http.Error(w, "Gateway Timeout", http.StatusGatewayTimeout)
			return
		}
		rt.logger.Error("upstream request failed",
			"error", err.Error(),
			"route", route.PathPrefix,
		)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Apply the same response modifications as ModifyResponse in the ReverseProxy path.
	redactValues := redactValuesFromContext(r.Context())

	// Wrap body with idle timeout reader if configured.
	body := resp.Body
	if route.IdleTimeout > 0 {
		if cancelFn := idleCancelFromContext(r.Context()); cancelFn != nil {
			body = newIdleTimeoutReader(body, route.IdleTimeout, cancelFn)
		}
	}

	// MCP tools/list filtering.
	mcpFiltered := false
	if mcpInfo := mcpInfoFromContext(r.Context()); mcpInfo != nil && mcpInfo.Method == "tools/list" {
		ct := resp.Header.Get("Content-Type")
		if strings.HasPrefix(ct, "text/event-stream") {
			body = newMCPToolFilterReader(body, mcpInfo.Policy, rt.logger, route.PathPrefix)
			resp.Header.Del("Content-Length")
		} else {
			rawBody, readErr := io.ReadAll(body)
			body.Close()
			if readErr != nil {
				body = io.NopCloser(bytes.NewReader(nil))
			} else {
				fr, filterErr := mcpInfo.Policy.FilterToolsListResponse(rawBody, ct)
				if filterErr == nil && fr.AllTools != nil {
					rt.logger.Info("MCP tools discovered",
						"route", route.PathPrefix,
						"upstream_tools", fr.AllTools,
						"allowed_tools", fr.AllowedTools,
						"upstream_count", len(fr.AllTools),
						"allowed_count", len(fr.AllowedTools),
					)
					body = io.NopCloser(bytes.NewReader(fr.Body))
					resp.Header.Set("Content-Length", strconv.Itoa(len(fr.Body)))
				} else {
					body = io.NopCloser(bytes.NewReader(rawBody))
				}
			}
		}
		mcpFiltered = true
	}

	// SSE transport fallback for MCP-filtered routes.
	if !mcpFiltered && route.MCPRules != nil && route.MCPRules.hasToolRules() &&
		strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		body = newMCPToolFilterReader(body, route.MCPRules, rt.logger, route.PathPrefix)
		resp.Header.Del("Content-Length")
	}

	// Redact credential values from response headers.
	if len(redactValues) > 0 {
		redactHeaderValues(resp.Header, redactValues)
	}

	// Strip configured response headers.
	for _, h := range route.StripResponseHeaders {
		resp.Header.Del(h)
	}

	// Wrap response body with a redacting reader.
	if len(redactValues) > 0 {
		isSSE := false
		if ct := resp.Header.Get("Content-Type"); ct != "" {
			if baseCT, _, _ := mime.ParseMediaType(ct); baseCT == "text/event-stream" {
				isSSE = true
			}
		}
		if isSSE {
			body = newSSERedactingReader(body, redactValues)
		} else {
			body = newRedactingReader(body, redactValues)
		}
		resp.Header.Del("Content-Length")
	}

	// Copy response headers to the client.
	for key, values := range resp.Header {
		for _, v := range values {
			w.Header().Add(key, v)
		}
	}
	w.WriteHeader(resp.StatusCode)

	// Stream the response body, flushing for SSE.
	if f, ok := w.(http.Flusher); ok {
		buf := make([]byte, 32*1024)
		for {
			n, readErr := body.Read(buf)
			if n > 0 {
				_, writeErr := w.Write(buf[:n])
				if writeErr != nil {
					return
				}
				f.Flush()
			}
			if readErr != nil {
				return
			}
		}
	} else {
		_, _ = io.Copy(w, body)
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
			if rl != nil {
				rl.Message = "MCP body inspection failed"
			}
			rt.logger.Error("MCP body inspection failed",
				"correlation_id", correlationID,
				"route", route.PathPrefix,
				"error", mcpErr.Error(),
			)
			http.Error(w, "Bad Request", http.StatusBadRequest)
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

	if route.useDirectProxy {
		rt.logger.Info("using direct proxy path", "route", route.PathPrefix, "tls_fingerprint", route.TLSFingerprint)
		rt.serveDirectProxy(route, w, r)
	} else {
		route.proxy.ServeHTTP(w, r)
	}
}
