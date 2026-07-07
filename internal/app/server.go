package app

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/DeliciousBuding/mcp-gateway/internal/buildinfo"
	"github.com/DeliciousBuding/mcp-gateway/internal/grok"
	"github.com/DeliciousBuding/mcp-gateway/internal/store"
)

const protocolVersion = "2025-06-18"

var errBodyTooLarge = errors.New("request body too large")

var durationBuckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}

type Server struct {
	cfg           Config
	mux           *http.ServeMux
	store         *store.Store
	tools         map[string]Tool
	apiKeys       map[string]agentIdentity
	limiter       *rateLimiter
	upstreamC     chan struct{}
	log           *slog.Logger
	cleanupCancel context.CancelFunc
	cleanupWG     sync.WaitGroup
	metrics       gatewayMetrics
}

type gatewayMetrics struct {
	mu            sync.Mutex
	httpRequests  map[metricKey]*atomic.Int64
	rpcRequests   map[metricKey]*atomic.Int64
	toolCalls     map[metricKey]*atomic.Int64
	cacheRequests map[metricKey]*atomic.Int64
	httpDuration  map[metricKey]*durationHistogram
	toolDuration  map[metricKey]*durationHistogram
}

type metricKey struct {
	A string
	B string
	C string
}

type durationHistogram struct {
	buckets   []*atomic.Int64
	sumMicros atomic.Int64
	count     atomic.Int64
}

type agentIdentity struct {
	ID     string
	Scopes map[string]struct{}
	Scoped bool
}

type Tool interface {
	Definition() ToolDefinition
	Call(context.Context, map[string]any) (ToolCallResult, error)
}

type ToolDefinition struct {
	Name         string          `json:"name"`
	Title        string          `json:"title,omitempty"`
	Description  string          `json:"description"`
	InputSchema  map[string]any  `json:"inputSchema"`
	OutputSchema map[string]any  `json:"outputSchema,omitempty"`
	Annotations  ToolAnnotations `json:"annotations,omitempty"`
	Scopes       []string        `json:"-"`
}

type ToolAnnotations struct {
	ReadOnlyHint    bool `json:"readOnlyHint"`
	DestructiveHint bool `json:"destructiveHint"`
	IdempotentHint  bool `json:"idempotentHint"`
	OpenWorldHint   bool `json:"openWorldHint"`
}

type ToolCallResult struct {
	Text        string
	SourceCnt   int
	Structured  any
	IsError     bool
	ContentType string
	CacheResult string
}

func NewServer(cfg Config) (*Server, error) {
	cfg = cfg.normalized()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	st, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return nil, err
	}
	s := &Server{
		cfg:       cfg,
		mux:       http.NewServeMux(),
		store:     st,
		tools:     make(map[string]Tool),
		apiKeys:   make(map[string]agentIdentity, len(cfg.APIKeys)),
		limiter:   newRateLimiter(cfg.RateLimitPerMin),
		upstreamC: make(chan struct{}, cfg.MaxConcurrency),
		log:       cfg.Logger,
		metrics: gatewayMetrics{
			httpRequests:  make(map[metricKey]*atomic.Int64),
			rpcRequests:   make(map[metricKey]*atomic.Int64),
			toolCalls:     make(map[metricKey]*atomic.Int64),
			cacheRequests: make(map[metricKey]*atomic.Int64),
			httpDuration:  make(map[metricKey]*durationHistogram),
			toolDuration:  make(map[metricKey]*durationHistogram),
		},
	}
	if s.log == nil {
		s.log = slog.Default()
	}
	for _, key := range cfg.APIKeys {
		token, identity, ok := parseAPIKeyEntry(key)
		if ok {
			s.apiKeys[token] = identity
		}
	}
	if !cfg.GrokDisabled {
		grokClient := grok.NewClient(grok.Config{
			APIURL:           cfg.GrokAPIURL,
			APIKey:           cfg.GrokAPIKey,
			DefaultModel:     cfg.GrokDefaultModel,
			Timeout:          cfg.UpstreamTimeout,
			MaxResponseBytes: cfg.GrokMaxResponseBytes,
		})
		s.RegisterTool(newGrokSearchTool("grok_search", "Search the web through the configured Grok upstream and return an answer with sources.", grokClient, st, cfg.CacheTTL, cfg.GrokMaxQueryBytes, false, false))
		s.RegisterTool(newGrokSearchTool("grok_extract", "Extract structured JSON from web context through the configured Grok upstream.", grokClient, st, cfg.CacheTTL, cfg.GrokMaxQueryBytes, true, false))
		s.RegisterTool(newGrokSearchTool("grok_sources", "Return only sources discovered by the configured Grok upstream.", grokClient, st, cfg.CacheTTL, cfg.GrokMaxQueryBytes, false, true))
	}
	if _, err := s.prune(context.Background()); err != nil {
		_ = st.Close()
		return nil, err
	}
	s.startCleanupJanitor()
	s.routes()
	return s, nil
}

func (s *Server) RegisterTool(tool Tool) {
	s.tools[tool.Definition().Name] = tool
}

func (s *Server) Close(ctx context.Context) error {
	if s.cleanupCancel != nil {
		s.cleanupCancel()
	}
	doneCleanup := make(chan struct{}, 1)
	go func() {
		s.cleanupWG.Wait()
		doneCleanup <- struct{}{}
	}()
	select {
	case <-doneCleanup:
	case <-ctx.Done():
		return ctx.Err()
	}
	done := make(chan error, 1)
	go func() { done <- s.store.Close() }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Server) startCleanupJanitor() {
	if s.cfg.CleanupInterval <= 0 {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.cleanupCancel = cancel
	s.cleanupWG.Add(1)
	go func() {
		defer s.cleanupWG.Done()
		ticker := time.NewTicker(s.cfg.CleanupInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if result, err := s.prune(ctx); err != nil {
					s.log.Warn("cleanup prune failed", "error", err)
				} else if result.CacheRowsDeleted > 0 || result.AuditRowsDeleted > 0 {
					s.log.Debug("cleanup prune completed", "cache_rows", result.CacheRowsDeleted, "audit_rows", result.AuditRowsDeleted)
				}
			case <-ctx.Done():
				return
			}
		}
	}()
}

func (s *Server) prune(ctx context.Context) (store.PruneResult, error) {
	pruneCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return s.store.Prune(pruneCtx, store.PruneOptions{
		Now:            time.Now().UTC(),
		AuditRetention: s.cfg.AuditRetention,
	})
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	requestID := requestIDFromHeader(r.Header.Get("X-Request-Id"))
	w.Header().Set("X-Request-Id", requestID)
	ww := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	start := time.Now()
	ctx := context.WithValue(r.Context(), requestIDKey{}, requestID)
	defer func() {
		if recovered := recover(); recovered != nil {
			ww.status = http.StatusInternalServerError
			if !ww.wrote {
				writeJSON(ww, http.StatusInternalServerError, map[string]any{
					"error":      "internal server error",
					"request_id": requestID,
				})
			}
			s.metrics.incHTTP(r.URL.Path, r.Method, http.StatusInternalServerError)
			s.log.Error("http_panic_recovered", "request_id", requestID, "method", r.Method, "route", r.URL.Path)
		}
		attrs := []any{
			"request_id", requestID,
			"method", r.Method,
			"route", r.URL.Path,
			"status", ww.status,
			"duration_ms", time.Since(start).Milliseconds(),
		}
		if ww.agentID != "" {
			attrs = append(attrs, "agent_id", ww.agentID)
		}
		s.log.Info("http_request", attrs...)
	}()
	s.mux.ServeHTTP(ww, r.WithContext(ctx))
}

func (s *Server) routes() {
	s.mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		setSecurityHeaders(w)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "service": "mcp-gateway"})
	})
	s.mux.HandleFunc("/ready", func(w http.ResponseWriter, r *http.Request) {
		setSecurityHeaders(w)
		ctx, cancel := context.WithTimeout(r.Context(), 500*time.Millisecond)
		defer cancel()
		if err := s.store.Ping(ctx); err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "service": "mcp-gateway", "database": "down"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "service": "mcp-gateway", "database": "ok"})
	})
	s.mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.ProtectMetrics {
			if _, ok := s.authenticateRequest(r); !ok {
				s.writeUnauthorized(w)
				return
			}
		}
		setSecurityHeaders(w)
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		_, _ = fmt.Fprintf(w, "# HELP mcp_gateway_build_info Static build information for the gateway.\n")
		_, _ = fmt.Fprintf(w, "# TYPE mcp_gateway_build_info gauge\n")
		_, _ = fmt.Fprintf(w, "mcp_gateway_build_info{service=\"mcp-gateway\",version=%q,commit=%q,date=%q} 1\n", buildinfo.Version, buildinfo.Commit, buildinfo.Date)
		_, _ = fmt.Fprintf(w, "# HELP mcp_gateway_tools_registered Number of registered MCP tools.\n")
		_, _ = fmt.Fprintf(w, "# TYPE mcp_gateway_tools_registered gauge\n")
		_, _ = fmt.Fprintf(w, "mcp_gateway_tools_registered %d\n", len(s.tools))
		_, _ = fmt.Fprintf(w, "# HELP mcp_gateway_upstream_inflight Number of in-flight upstream tool calls.\n")
		_, _ = fmt.Fprintf(w, "# TYPE mcp_gateway_upstream_inflight gauge\n")
		_, _ = fmt.Fprintf(w, "mcp_gateway_upstream_inflight %d\n", len(s.upstreamC))
		s.writeMetrics(w)
	})
	s.mux.HandleFunc("/.well-known/oauth-protected-resource", s.handleOAuthProtectedResourceMetadata)
	s.mux.HandleFunc("/.well-known/oauth-protected-resource/", s.handleOAuthProtectedResourceMetadata)
	s.mux.HandleFunc("/mcp", s.trackHTTP("/mcp", s.withSecurity(s.auth(s.handleMCP))))
}

func (s *Server) trackHTTP(route string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ww := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		start := time.Now()
		next(ww, r)
		s.metrics.incHTTP(route, r.Method, ww.status)
		s.metrics.observeHTTP(route, r.Method, ww.status, time.Since(start))
	}
}

type statusRecorder struct {
	http.ResponseWriter
	status  int
	agentID string
	wrote   bool
}

func (w *statusRecorder) WriteHeader(status int) {
	if w.wrote {
		return
	}
	w.status = status
	w.wrote = true
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusRecorder) Write(b []byte) (int, error) {
	if !w.wrote {
		w.WriteHeader(w.status)
	}
	return w.ResponseWriter.Write(b)
}

func (w *statusRecorder) setAgentID(agentID string) {
	w.agentID = agentID
	if next, ok := w.ResponseWriter.(interface{ setAgentID(string) }); ok {
		next.setAgentID(agentID)
	}
}

func (s *Server) handleOAuthProtectedResourceMetadata(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w)
	metadataPath := s.protectedResourceMetadataPath()
	if r.URL.Path != "/.well-known/oauth-protected-resource" && r.URL.Path != metadataPath {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	body := map[string]any{
		"resource":             s.resourceURL(),
		"mcp_protocol_version": protocolVersion,
		"bearer_methods_supported": []string{
			"header",
		},
	}
	if len(s.cfg.AuthorizationServers) > 0 {
		body["authorization_servers"] = s.cfg.AuthorizationServers
	}
	writeJSON(w, http.StatusOK, body)
}

func (s *Server) withSecurity(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setSecurityHeaders(w)
		if !s.allowOrigin(w, r) {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "origin not allowed"})
			return
		}
		if r.Method == http.MethodOptions {
			w.Header().Set("Allow", "POST")
			w.Header().Set("Access-Control-Allow-Methods", "POST")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Accept, MCP-Protocol-Version, X-Request-Id, Mcp-Session-Id")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next(w, r)
	}
}

func setSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
}

func (s *Server) allowOrigin(w http.ResponseWriter, r *http.Request) bool {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return true
	}
	w.Header().Add("Vary", "Origin")
	if len(s.cfg.AllowedOrigins) == 0 {
		return false
	}
	for _, allowed := range s.cfg.AllowedOrigins {
		allowed = strings.TrimSpace(allowed)
		if allowed == "*" || strings.EqualFold(allowed, origin) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			return true
		}
	}
	return false
}

func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		agent, ok := s.authenticateRequest(r)
		if !ok {
			s.writeUnauthorized(w)
			return
		}
		if recorder, ok := w.(interface{ setAgentID(string) }); ok {
			recorder.setAgentID(agent.ID)
		}
		if allowed, retryAfter := s.limiter.Allow(agent.ID); !allowed {
			w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(retryAfter.Seconds()))))
			writeJSON(w, http.StatusTooManyRequests, map[string]any{"error": "rate limit exceeded"})
			return
		}
		ctx := context.WithValue(r.Context(), agentKey{}, agent)
		next(w, r.WithContext(ctx))
	}
}

func (s *Server) authenticateRequest(r *http.Request) (agentIdentity, bool) {
	token, ok := bearerToken(r.Header.Get("Authorization"))
	if !ok {
		return agentIdentity{}, false
	}
	return s.lookupAgent(token)
}

func bearerToken(header string) (string, bool) {
	parts := strings.Fields(header)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", false
	}
	return parts[1], true
}

func (s *Server) writeUnauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer resource_metadata="%s"`, s.protectedResourceMetadataURL()))
	writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "missing or invalid bearer token"})
}

func (s *Server) lookupAgent(token string) (agentIdentity, bool) {
	if len(s.apiKeys) == 0 {
		return agentIdentity{ID: "anonymous"}, true
	}
	for key, id := range s.apiKeys {
		if subtle.ConstantTimeCompare([]byte(token), []byte(key)) == 1 {
			return id, true
		}
	}
	return agentIdentity{}, false
}

func (s *Server) resourceURL() string {
	if strings.TrimSpace(s.cfg.PublicBaseURL) != "" {
		return strings.TrimRight(s.cfg.PublicBaseURL, "/")
	}
	return "http://" + s.cfg.Addr + "/mcp"
}

func (s *Server) protectedResourceMetadataURL() string {
	resource := s.resourceURL()
	u, err := url.Parse(resource)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "/.well-known/oauth-protected-resource"
	}
	u.Path = s.protectedResourceMetadataPath()
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

func (s *Server) protectedResourceMetadataPath() string {
	const metadataPath = "/.well-known/oauth-protected-resource"
	resource := s.resourceURL()
	u, err := url.Parse(resource)
	if err != nil {
		return metadataPath
	}
	resourcePath := strings.TrimLeft(u.Path, "/")
	if resourcePath == "" {
		return metadataPath
	}
	return metadataPath + "/" + resourcePath
}

func (s *Server) handleMCP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("MCP-Protocol-Version", protocolVersion)
	if r.Method == http.MethodGet {
		w.Header().Set("Allow", "POST")
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "streaming GET is disabled"})
		return
	}
	if r.Method == http.MethodDelete {
		w.Header().Set("Allow", "POST")
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "session termination is not supported in stateless mode"})
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	if !isSupportedProtocolVersion(r.Header.Get("MCP-Protocol-Version")) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "unsupported MCP protocol version"})
		return
	}
	if !isJSONContentType(r.Header.Get("Content-Type")) {
		writeJSON(w, http.StatusUnsupportedMediaType, map[string]any{"error": "content type must be application/json"})
		return
	}
	if !acceptsMCPPost(r.Header.Values("Accept")) {
		writeJSON(w, http.StatusNotAcceptable, map[string]any{"error": "accept must allow application/json and text/event-stream"})
		return
	}
	raw, err := s.readLimitedBody(w, r)
	if err != nil {
		if errors.Is(err, errBodyTooLarge) {
			writeJSON(w, http.StatusRequestEntityTooLarge, map[string]any{"error": "request body too large"})
			return
		}
		writeRPC(w, nil, nil, rpcError{-32700, "parse error"})
		return
	}
	if bytes.HasPrefix(bytes.TrimSpace(raw), []byte("[")) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "JSON-RPC batch messages are not supported"})
		return
	}
	var req rpcRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		writeRPC(w, nil, nil, rpcError{-32700, "parse error"})
		return
	}
	if req.JSONRPC != "2.0" || strings.TrimSpace(req.Method) == "" {
		writeRPC(w, req.ID, nil, rpcError{-32600, "invalid request"})
		return
	}
	if req.HasID && !isValidRPCID(req.ID) {
		writeRPC(w, nil, nil, rpcError{-32600, "invalid request"})
		return
	}
	if !req.HasID {
		if req.Method == "notifications/initialized" {
			s.metrics.incRPC("notifications/initialized", "ok")
		} else {
			s.metrics.incRPC("notification", "accepted")
		}
		w.WriteHeader(http.StatusAccepted)
		return
	}
	switch req.Method {
	case "initialize":
		s.handleInitialize(w, req)
	case "ping":
		s.metrics.incRPC(req.Method, "ok")
		writeRPC(w, req.ID, map[string]any{}, rpcError{})
	case "notifications/initialized":
		s.metrics.incRPC(req.Method, "error")
		writeRPC(w, req.ID, nil, rpcError{-32600, "invalid request"})
	case "tools/list":
		tools := make([]ToolDefinition, 0, len(s.tools))
		agent, _ := r.Context().Value(agentKey{}).(agentIdentity)
		for _, tool := range s.tools {
			def := tool.Definition()
			if agent.canUse(def) {
				tools = append(tools, def)
			}
		}
		s.metrics.incRPC(req.Method, "ok")
		writeRPC(w, req.ID, map[string]any{"tools": tools}, rpcError{})
	case "tools/call":
		s.handleToolCall(w, r, req)
	default:
		s.metrics.incRPC(req.Method, "error")
		writeRPC(w, req.ID, nil, rpcError{-32601, "method not found"})
	}
}

func (s *Server) handleInitialize(w http.ResponseWriter, req rpcRequest) {
	var params struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	if req.Params != nil {
		raw, _ := json.Marshal(req.Params)
		if err := json.Unmarshal(raw, &params); err != nil || strings.TrimSpace(params.ProtocolVersion) == "" {
			s.metrics.incRPC(req.Method, "error")
			writeRPC(w, req.ID, nil, rpcError{-32602, "invalid params"})
			return
		}
	}
	s.metrics.incRPC(req.Method, "ok")
	writeRPC(w, req.ID, map[string]any{
		"protocolVersion": protocolVersion,
		"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
		"serverInfo":      map[string]any{"name": "mcp-gateway", "version": buildinfo.Version},
	}, rpcError{})
}

func (s *Server) handleToolCall(w http.ResponseWriter, r *http.Request, req rpcRequest) {
	paramObj, ok := req.Params.(map[string]any)
	if !ok {
		s.metrics.incRPC(req.Method, "error")
		writeRPC(w, req.ID, nil, rpcError{-32602, "invalid params"})
		return
	}
	if args, ok := paramObj["arguments"]; ok {
		if _, ok := args.(map[string]any); !ok {
			s.metrics.incRPC(req.Method, "error")
			writeRPC(w, req.ID, nil, rpcError{-32602, "invalid params"})
			return
		}
	}
	var params struct {
		Name      string         `json:"name"`
		Arguments map[string]any `json:"arguments"`
	}
	raw, _ := json.Marshal(req.Params)
	if err := json.Unmarshal(raw, &params); err != nil || strings.TrimSpace(params.Name) == "" {
		s.metrics.incRPC(req.Method, "error")
		writeRPC(w, req.ID, nil, rpcError{-32602, "invalid params"})
		return
	}
	params.Name = strings.TrimSpace(params.Name)
	if params.Arguments == nil {
		params.Arguments = map[string]any{}
	}
	tool, ok := s.tools[params.Name]
	if !ok {
		s.metrics.incRPC(req.Method, "error")
		writeRPC(w, req.ID, nil, rpcError{-32602, "unknown tool"})
		return
	}
	agent, _ := r.Context().Value(agentKey{}).(agentIdentity)
	if !agent.canUse(tool.Definition()) {
		s.metrics.incRPC(req.Method, "forbidden")
		s.metrics.incTool(params.Name, "forbidden")
		writeRPC(w, req.ID, nil, rpcError{-32001, "forbidden"})
		return
	}

	start := time.Now()
	status := "ok"
	errText := ""
	sourceCnt := 0
	remoteAddr := ""
	if s.cfg.AuditRemoteAddr {
		remoteAddr = r.RemoteAddr
	}
	requestID, _ := r.Context().Value(requestIDKey{}).(string)
	defer func() {
		auditCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = s.store.RecordToolCall(auditCtx, store.ToolCall{
			AgentID:    agent.ID,
			RequestID:  requestID,
			ToolName:   params.Name,
			Status:     status,
			LatencyMS:  time.Since(start).Milliseconds(),
			SourceCnt:  sourceCnt,
			ErrorText:  errText,
			RemoteAddr: remoteAddr,
		})
	}()

	select {
	case s.upstreamC <- struct{}{}:
		defer func() { <-s.upstreamC }()
	case <-r.Context().Done():
		s.metrics.incRPC(req.Method, "error")
		s.metrics.incTool(params.Name, "error")
		status = "error"
		errText = "request canceled"
		s.metrics.observeTool(params.Name, status, time.Since(start))
		writeRPC(w, req.ID, nil, rpcError{-32000, "request canceled"})
		return
	}
	result, err := callToolSafely(r.Context(), tool, params.Arguments)
	sourceCnt = result.SourceCnt
	if err != nil {
		s.metrics.incRPC(req.Method, "error")
		s.metrics.incTool(params.Name, "error")
		status = "error"
		errText = err.Error()
		s.metrics.observeTool(params.Name, status, time.Since(start))
		writeRPC(w, req.ID, map[string]any{
			"content": []map[string]any{{"type": "text", "text": err.Error()}},
			"isError": true,
		}, rpcError{})
		return
	}
	s.metrics.incRPC(req.Method, "ok")
	s.metrics.incTool(params.Name, "ok")
	s.metrics.observeTool(params.Name, status, time.Since(start))
	if result.CacheResult != "" {
		s.metrics.incCache(params.Name, result.CacheResult)
	}
	writeRPC(w, req.ID, map[string]any{
		"content":           []map[string]any{{"type": "text", "text": result.Text}},
		"structuredContent": result.Structured,
		"isError":           result.IsError,
	}, rpcError{})
}

func callToolSafely(ctx context.Context, tool Tool, args map[string]any) (result ToolCallResult, err error) {
	defer func() {
		if recover() != nil {
			result = ToolCallResult{}
			err = errors.New("tool execution failed")
		}
	}()
	return tool.Call(ctx, args)
}

func (s *Server) writeMetrics(w io.Writer) {
	_, _ = fmt.Fprintf(w, "# HELP mcp_gateway_http_requests_total Total HTTP requests by route, method, and status.\n")
	_, _ = fmt.Fprintf(w, "# TYPE mcp_gateway_http_requests_total counter\n")
	for _, sample := range s.metrics.snapshotHTTP() {
		_, _ = fmt.Fprintf(w, "mcp_gateway_http_requests_total{route=%q,method=%q,status=%q} %d\n", sample.Key.A, sample.Key.B, sample.Key.C, sample.Value)
	}
	_, _ = fmt.Fprintf(w, "# HELP mcp_gateway_http_request_duration_seconds HTTP request duration by route, method, and status.\n")
	_, _ = fmt.Fprintf(w, "# TYPE mcp_gateway_http_request_duration_seconds histogram\n")
	for _, sample := range s.metrics.snapshotHTTPDuration() {
		writeDurationHistogram(w, "mcp_gateway_http_request_duration_seconds", []string{"route", "method", "status"}, []string{sample.Key.A, sample.Key.B, sample.Key.C}, sample)
	}
	_, _ = fmt.Fprintf(w, "# HELP mcp_gateway_rpc_requests_total Total MCP JSON-RPC requests by method and status.\n")
	_, _ = fmt.Fprintf(w, "# TYPE mcp_gateway_rpc_requests_total counter\n")
	for _, sample := range s.metrics.snapshotRPC() {
		_, _ = fmt.Fprintf(w, "mcp_gateway_rpc_requests_total{method=%q,status=%q} %d\n", sample.Key.A, sample.Key.B, sample.Value)
	}
	_, _ = fmt.Fprintf(w, "# HELP mcp_gateway_tool_calls_total Total MCP tool calls by tool and status.\n")
	_, _ = fmt.Fprintf(w, "# TYPE mcp_gateway_tool_calls_total counter\n")
	for _, sample := range s.metrics.snapshotTool() {
		_, _ = fmt.Fprintf(w, "mcp_gateway_tool_calls_total{tool=%q,status=%q} %d\n", sample.Key.A, sample.Key.B, sample.Value)
	}
	_, _ = fmt.Fprintf(w, "# HELP mcp_gateway_tool_call_duration_seconds MCP tool call duration by tool and status.\n")
	_, _ = fmt.Fprintf(w, "# TYPE mcp_gateway_tool_call_duration_seconds histogram\n")
	for _, sample := range s.metrics.snapshotToolDuration() {
		writeDurationHistogram(w, "mcp_gateway_tool_call_duration_seconds", []string{"tool", "status"}, []string{sample.Key.A, sample.Key.B}, sample)
	}
	_, _ = fmt.Fprintf(w, "# HELP mcp_gateway_cache_requests_total Total tool cache requests by tool and result.\n")
	_, _ = fmt.Fprintf(w, "# TYPE mcp_gateway_cache_requests_total counter\n")
	for _, sample := range s.metrics.snapshotCache() {
		_, _ = fmt.Fprintf(w, "mcp_gateway_cache_requests_total{tool=%q,result=%q} %d\n", sample.Key.A, sample.Key.B, sample.Value)
	}
}

type metricSample struct {
	Key   metricKey
	Value int64
}

type histogramSample struct {
	Key       metricKey
	Buckets   []int64
	SumMicros int64
	Count     int64
}

func (m *gatewayMetrics) incHTTP(route, method string, status int) {
	m.inc(m.httpRequests, metricKey{A: route, B: method, C: strconv.Itoa(status)})
}

func (m *gatewayMetrics) incRPC(method, status string) {
	m.inc(m.rpcRequests, metricKey{A: method, B: status})
}

func (m *gatewayMetrics) incTool(tool, status string) {
	m.inc(m.toolCalls, metricKey{A: tool, B: status})
}

func (m *gatewayMetrics) incCache(tool, result string) {
	m.inc(m.cacheRequests, metricKey{A: tool, B: result})
}

func (m *gatewayMetrics) observeHTTP(route, method string, status int, d time.Duration) {
	m.observe(m.httpDuration, metricKey{A: route, B: method, C: strconv.Itoa(status)}, d)
}

func (m *gatewayMetrics) observeTool(tool, status string, d time.Duration) {
	m.observe(m.toolDuration, metricKey{A: tool, B: status}, d)
}

func (m *gatewayMetrics) inc(samples map[metricKey]*atomic.Int64, key metricKey) {
	m.mu.Lock()
	counter := samples[key]
	if counter == nil {
		counter = &atomic.Int64{}
		samples[key] = counter
	}
	m.mu.Unlock()
	counter.Add(1)
}

func (m *gatewayMetrics) observe(samples map[metricKey]*durationHistogram, key metricKey, d time.Duration) {
	seconds := d.Seconds()
	m.mu.Lock()
	h := samples[key]
	if h == nil {
		h = newDurationHistogram()
		samples[key] = h
	}
	m.mu.Unlock()
	for i, bucket := range durationBuckets {
		if seconds <= bucket {
			h.buckets[i].Add(1)
		}
	}
	h.buckets[len(durationBuckets)].Add(1)
	h.sumMicros.Add(d.Microseconds())
	h.count.Add(1)
}

func newDurationHistogram() *durationHistogram {
	h := &durationHistogram{buckets: make([]*atomic.Int64, len(durationBuckets)+1)}
	for i := range h.buckets {
		h.buckets[i] = &atomic.Int64{}
	}
	return h
}

func (m *gatewayMetrics) snapshotHTTP() []metricSample {
	return m.snapshot(m.httpRequests)
}

func (m *gatewayMetrics) snapshotRPC() []metricSample {
	return m.snapshot(m.rpcRequests)
}

func (m *gatewayMetrics) snapshotTool() []metricSample {
	return m.snapshot(m.toolCalls)
}

func (m *gatewayMetrics) snapshotCache() []metricSample {
	return m.snapshot(m.cacheRequests)
}

func (m *gatewayMetrics) snapshotHTTPDuration() []histogramSample {
	return m.snapshotHistogram(m.httpDuration)
}

func (m *gatewayMetrics) snapshotToolDuration() []histogramSample {
	return m.snapshotHistogram(m.toolDuration)
}

func (m *gatewayMetrics) snapshot(samples map[metricKey]*atomic.Int64) []metricSample {
	m.mu.Lock()
	out := make([]metricSample, 0, len(samples))
	for key, counter := range samples {
		out = append(out, metricSample{Key: key, Value: counter.Load()})
	}
	m.mu.Unlock()
	return out
}

func (m *gatewayMetrics) snapshotHistogram(samples map[metricKey]*durationHistogram) []histogramSample {
	m.mu.Lock()
	out := make([]histogramSample, 0, len(samples))
	for key, histogram := range samples {
		buckets := make([]int64, len(histogram.buckets))
		for i, bucket := range histogram.buckets {
			buckets[i] = bucket.Load()
		}
		out = append(out, histogramSample{
			Key:       key,
			Buckets:   buckets,
			SumMicros: histogram.sumMicros.Load(),
			Count:     histogram.count.Load(),
		})
	}
	m.mu.Unlock()
	return out
}

func writeDurationHistogram(w io.Writer, name string, labelNames []string, labelValues []string, sample histogramSample) {
	for i, upperBound := range durationBuckets {
		_, _ = fmt.Fprintf(w, "%s_bucket{%sle=%q} %d\n", name, histogramLabels(labelNames, labelValues), strconv.FormatFloat(upperBound, 'g', -1, 64), sample.Buckets[i])
	}
	_, _ = fmt.Fprintf(w, "%s_bucket{%sle=\"+Inf\"} %d\n", name, histogramLabels(labelNames, labelValues), sample.Buckets[len(durationBuckets)])
	_, _ = fmt.Fprintf(w, "%s_sum{%s} %.6f\n", name, strings.TrimSuffix(histogramLabels(labelNames, labelValues), ","), float64(sample.SumMicros)/1_000_000)
	_, _ = fmt.Fprintf(w, "%s_count{%s} %d\n", name, strings.TrimSuffix(histogramLabels(labelNames, labelValues), ","), sample.Count)
}

func histogramLabels(names []string, values []string) string {
	var b strings.Builder
	for i := range names {
		_, _ = fmt.Fprintf(&b, "%s=%q,", names[i], values[i])
	}
	return b.String()
}

type rpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      any    `json:"id,omitempty"`
	HasID   bool   `json:"-"`
	Method  string `json:"method"`
	Params  any    `json:"params,omitempty"`
}

func (r *rpcRequest) UnmarshalJSON(data []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	var raw struct {
		JSONRPC string `json:"jsonrpc"`
		Method  string `json:"method"`
		Params  any    `json:"params,omitempty"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	r.JSONRPC = raw.JSONRPC
	r.Method = raw.Method
	r.Params = raw.Params
	if idRaw, ok := fields["id"]; ok {
		r.HasID = true
		decoder := json.NewDecoder(bytes.NewReader(idRaw))
		decoder.UseNumber()
		if err := decoder.Decode(&r.ID); err != nil {
			return err
		}
	}
	return nil
}

func isValidRPCID(id any) bool {
	switch v := id.(type) {
	case string:
		return true
	case json.Number:
		if strings.ContainsAny(v.String(), ".eE") {
			return false
		}
		_, err := strconv.ParseInt(v.String(), 10, 64)
		return err == nil
	default:
		return false
	}
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func writeRPC(w http.ResponseWriter, id any, result any, rpcErr rpcError) {
	resp := map[string]any{"jsonrpc": "2.0", "id": id}
	if rpcErr.Code != 0 {
		resp["error"] = rpcErr
	} else {
		resp["result"] = result
	}
	writeJSON(w, http.StatusOK, resp)
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

type agentKey struct{}
type requestIDKey struct{}

func requestIDFromHeader(value string) string {
	value = strings.TrimSpace(value)
	if isValidRequestID(value) {
		return value
	}
	var b [16]byte
	if _, err := rand.Read(b[:]); err == nil {
		return hex.EncodeToString(b[:])
	}
	return fmt.Sprintf("%032x", time.Now().UnixNano())
}

func isValidRequestID(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if r < 33 || r > 126 {
			return false
		}
	}
	return true
}

func agentID(token string) string {
	sum := sha256.Sum256([]byte(token))
	return "agent:" + hex.EncodeToString(sum[:])[:16]
}

func parseAPIKeyEntry(entry string) (string, agentIdentity, bool) {
	entry = strings.TrimSpace(entry)
	if entry == "" {
		return "", agentIdentity{}, false
	}
	token := entry
	scopeExpr := ""
	if before, after, ok := strings.Cut(entry, "="); ok {
		token = strings.TrimSpace(before)
		scopeExpr = strings.TrimSpace(after)
	}
	if token == "" {
		return "", agentIdentity{}, false
	}
	identity := agentIdentity{ID: agentID(token)}
	if scopeExpr != "" {
		identity.Scoped = true
		identity.Scopes = parseScopes(scopeExpr)
	}
	return token, identity, true
}

func parseScopes(expr string) map[string]struct{} {
	scopes := make(map[string]struct{})
	for _, part := range strings.FieldsFunc(expr, func(r rune) bool {
		return r == '|' || r == ';' || r == ' '
	}) {
		if scope := strings.TrimSpace(part); scope != "" {
			scopes[scope] = struct{}{}
		}
	}
	return scopes
}

func (a agentIdentity) canUse(def ToolDefinition) bool {
	if !a.Scoped {
		return true
	}
	if _, ok := a.Scopes["*"]; ok {
		return true
	}
	if _, ok := a.Scopes["tool:"+def.Name]; ok {
		return true
	}
	for _, scope := range def.Scopes {
		if _, ok := a.Scopes[scope]; ok {
			return true
		}
	}
	return false
}

func isJSONContentType(contentType string) bool {
	mediaType, _, err := mime.ParseMediaType(contentType)
	return err == nil && mediaType == "application/json"
}

func isSupportedProtocolVersion(value string) bool {
	value = strings.TrimSpace(value)
	return value == "" || value == protocolVersion
}

func (s *Server) readLimitedBody(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	defer r.Body.Close()
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, s.cfg.MaxBodyBytes))
	var maxErr *http.MaxBytesError
	if errors.As(err, &maxErr) {
		return nil, errBodyTooLarge
	}
	return raw, err
}

func acceptsMCPPost(values []string) bool {
	if len(values) == 0 {
		return false
	}
	acceptsJSON := false
	acceptsSSE := false
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			mediaType, _, err := mime.ParseMediaType(strings.TrimSpace(part))
			if err != nil {
				continue
			}
			switch mediaType {
			case "*/*":
				acceptsJSON = true
				acceptsSSE = true
			case "application/*":
				acceptsJSON = true
			case "text/*":
				acceptsSSE = true
			case "application/json":
				acceptsJSON = true
			case "text/event-stream":
				acceptsSSE = true
			}
		}
	}
	return acceptsJSON && acceptsSSE
}

type rateLimiter struct {
	mu       sync.Mutex
	limit    int
	window   time.Duration
	counters map[string]rateCounter
}

type rateCounter struct {
	reset time.Time
	used  int
}

func newRateLimiter(limit int) *rateLimiter {
	return &rateLimiter{limit: limit, window: time.Minute, counters: map[string]rateCounter{}}
}

func (l *rateLimiter) Allow(key string) (bool, time.Duration) {
	if l.limit <= 0 {
		return true, 0
	}
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	c := l.counters[key]
	if c.reset.IsZero() || now.After(c.reset) {
		c = rateCounter{reset: now.Add(l.window)}
	}
	if c.used >= l.limit {
		l.counters[key] = c
		return false, time.Until(c.reset)
	}
	c.used++
	l.counters[key] = c
	return true, 0
}

type grokSearchTool struct {
	name        string
	description string
	client      interface {
		Search(context.Context, grok.SearchRequest) (grok.SearchResponse, error)
	}
	cache         *store.Store
	cacheTTL      time.Duration
	maxQueryBytes int
	jsonMode      bool
	sourcesOnly   bool
}

func newGrokSearchTool(name, description string, client interface {
	Search(context.Context, grok.SearchRequest) (grok.SearchResponse, error)
}, cache *store.Store, cacheTTL time.Duration, maxQueryBytes int, jsonMode, sourcesOnly bool) *grokSearchTool {
	return &grokSearchTool{name: name, description: description, client: client, cache: cache, cacheTTL: cacheTTL, maxQueryBytes: maxQueryBytes, jsonMode: jsonMode, sourcesOnly: sourcesOnly}
}

func (t *grokSearchTool) Definition() ToolDefinition {
	return ToolDefinition{
		Name:        t.name,
		Title:       toolTitle(t.name),
		Description: t.description,
		InputSchema: map[string]any{
			"type":     "object",
			"required": []string{"query"},
			"properties": map[string]any{
				"query":      map[string]any{"type": "string", "description": "Full natural-language research brief. Include what to find, context, and desired output.", "maxLength": t.maxQueryBytes},
				"model":      map[string]any{"type": "string"},
				"max_tokens": map[string]any{"type": "integer", "minimum": 1, "maximum": 8192},
				"use_cache":  map[string]any{"type": "boolean", "description": "Use short-lived SQLite response cache. Defaults to true."},
			},
		},
		OutputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"sources": map[string]any{"type": "array", "items": map[string]any{"type": "object"}},
				"model":   map[string]any{"type": "string"},
				"cached":  map[string]any{"type": "boolean"},
			},
		},
		Scopes: []string{"provider:grok", "tool:" + t.name},
		Annotations: ToolAnnotations{
			ReadOnlyHint:    true,
			DestructiveHint: false,
			IdempotentHint:  true,
			OpenWorldHint:   true,
		},
	}
}

func toolTitle(name string) string {
	switch name {
	case "grok_search":
		return "Grok Search"
	case "grok_extract":
		return "Grok Extract"
	case "grok_sources":
		return "Grok Sources"
	default:
		return name
	}
}

func (t *grokSearchTool) Call(ctx context.Context, args map[string]any) (ToolCallResult, error) {
	query, _ := args["query"].(string)
	if strings.TrimSpace(query) == "" {
		return ToolCallResult{}, errors.New("query is required")
	}
	if len([]byte(strings.TrimSpace(query))) > t.maxQueryBytes {
		return ToolCallResult{}, fmt.Errorf("query exceeds max query size of %d bytes", t.maxQueryBytes)
	}
	model, _ := args["model"].(string)
	maxTokens := 0
	if rawMaxTokens, ok := args["max_tokens"]; ok {
		var err error
		maxTokens, err = maxTokensFromAny(rawMaxTokens)
		if err != nil {
			return ToolCallResult{}, err
		}
	}
	useCache := true
	if v, ok := args["use_cache"].(bool); ok {
		useCache = v
	}
	cacheKey := t.cacheKey(query, model, maxTokens)
	if useCache && t.cacheTTL > 0 {
		if entry, ok, err := t.cache.GetCache(ctx, cacheKey); err == nil && ok {
			return ToolCallResult{Text: entry.Value, SourceCnt: entry.SourceCnt, Structured: map[string]any{"cached": true}, CacheResult: "hit"}, nil
		}
	}
	res, err := t.client.Search(ctx, grok.SearchRequest{Query: query, Model: model, MaxTokens: maxTokens, JSONMode: t.jsonMode})
	if err != nil {
		return ToolCallResult{}, err
	}
	structured := map[string]any{"sources": res.Sources, "model": res.Model}
	text := res.Content
	if t.sourcesOnly {
		b, err := json.MarshalIndent(res.Sources, "", "  ")
		if err != nil {
			return ToolCallResult{}, fmt.Errorf("marshal sources: %w", err)
		}
		text = string(b)
	}
	if len(res.Sources) > 0 && !t.sourcesOnly {
		text += "\n\nSources:"
		for i, src := range res.Sources {
			if src.URL != "" {
				title := src.Title
				if title == "" {
					title = src.URL
				}
				text += fmt.Sprintf("\n[%d] %s - %s", i+1, title, src.URL)
			}
		}
	}
	if useCache && t.cacheTTL > 0 {
		_ = t.cache.SetCache(ctx, cacheKey, store.CacheEntry{
			Value:     text,
			SourceCnt: len(res.Sources),
			ExpiresAt: time.Now().Add(t.cacheTTL),
		})
	}
	cacheResult := ""
	if useCache && t.cacheTTL > 0 {
		cacheResult = "miss"
	}
	return ToolCallResult{Text: text, SourceCnt: len(res.Sources), Structured: structured, CacheResult: cacheResult}, nil
}

func (t *grokSearchTool) cacheKey(query, model string, maxTokens int) string {
	raw := fmt.Sprintf("%s\x00%t\x00%t\x00%s\x00%d\x00%s", t.name, t.jsonMode, t.sourcesOnly, model, maxTokens, strings.TrimSpace(query))
	sum := sha256.Sum256([]byte(raw))
	return "grok:" + hex.EncodeToString(sum[:])
}

func maxTokensFromAny(v any) (int, error) {
	const maxAllowedTokens = 8192
	n, ok := intFromAny(v)
	if !ok {
		return 0, errors.New("max_tokens must be an integer between 1 and 8192")
	}
	if n < 1 || n > maxAllowedTokens {
		return 0, errors.New("max_tokens must be between 1 and 8192")
	}
	return n, nil
}

func intFromAny(v any) (int, bool) {
	switch n := v.(type) {
	case float64:
		if math.Trunc(n) != n {
			return 0, false
		}
		return int(n), true
	case int:
		return n, true
	case json.Number:
		i, err := n.Int64()
		if err != nil {
			return 0, false
		}
		return int(i), true
	default:
		return 0, false
	}
}
