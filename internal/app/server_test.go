package app_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DeliciousBuding/mcp-gateway/internal/app"
)

func TestServerRejectsMissingBearerToken(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, nil)
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	wantChallenge := `Bearer resource_metadata="http://example.invalid/.well-known/oauth-protected-resource"`
	if got := rec.Header().Get("WWW-Authenticate"); got != wantChallenge {
		t.Fatalf("WWW-Authenticate = %q, want %q", got, wantChallenge)
	}
}

func TestOAuthProtectedResourceMetadata(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, &app.Config{
		Addr:                 "127.0.0.1:0",
		PublicBaseURL:        "https://mcp.example.com/mcp",
		DatabaseURL:          filepath.Join(t.TempDir(), "audit.db"),
		GrokAPIURL:           "http://127.0.0.1:1",
		GrokAPIKey:           "upstream-key",
		GrokDefaultModel:     "grok-test",
		APIKeys:              []string{"test-token"},
		AuthorizationServers: []string{"https://auth.example.com"},
		UpstreamTimeout:      time.Second,
		MaxConcurrency:       4,
		RateLimitPerMin:      60,
	})
	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil)
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	body := decodeObject(t, rec.Body.Bytes())
	if body["resource"] != "https://mcp.example.com/mcp" {
		t.Fatalf("resource = %v", body["resource"])
	}
	authServers := body["authorization_servers"].([]any)
	if len(authServers) != 1 || authServers[0] != "https://auth.example.com" {
		t.Fatalf("authorization_servers = %#v", authServers)
	}
	if body["mcp_protocol_version"] != "2025-06-18" {
		t.Fatalf("mcp_protocol_version = %v", body["mcp_protocol_version"])
	}
}

func TestReadyChecksSQLite(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, nil)
	req := httptest.NewRequest(http.MethodGet, "/ready", nil)
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	body := decodeObject(t, rec.Body.Bytes())
	if body["database"] != "ok" {
		t.Fatalf("database = %v, want ok", body["database"])
	}
}

func TestAccessLogIncludesRequestIDAndAgentWithoutSecrets(t *testing.T) {
	var logs bytes.Buffer
	srv := newTestServer(t, &app.Config{
		Addr:             "127.0.0.1:0",
		PublicBaseURL:    "http://example.invalid",
		DatabaseURL:      filepath.Join(t.TempDir(), "audit.db"),
		GrokAPIURL:       "http://127.0.0.1:1",
		GrokAPIKey:       "upstream-key",
		GrokDefaultModel: "grok-test",
		APIKeys:          []string{"test-token"},
		UpstreamTimeout:  time.Second,
		MaxConcurrency:   4,
		RateLimitPerMin:  60,
		Logger:           slog.New(slog.NewJSONHandler(&logs, nil)),
	})
	req := newMCPRequest(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	req.Header.Set("X-Request-Id", "req-test-123")
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if got := rec.Header().Get("X-Request-Id"); got != "req-test-123" {
		t.Fatalf("X-Request-Id = %q, want req-test-123", got)
	}
	logText := logs.String()
	for _, want := range []string{
		`"msg":"http_request"`,
		`"request_id":"req-test-123"`,
		`"method":"POST"`,
		`"route":"/mcp"`,
		`"status":200`,
		`"agent_id":"agent:`,
	} {
		if !bytes.Contains([]byte(logText), []byte(want)) {
			t.Fatalf("access log missing %q in %s", want, logText)
		}
	}
	if bytes.Contains([]byte(logText), []byte("test-token")) || bytes.Contains([]byte(logText), []byte("Authorization")) {
		t.Fatalf("access log leaked auth material: %s", logText)
	}
}

func TestAccessLogGeneratesRequestIDWhenMissing(t *testing.T) {
	var logs bytes.Buffer
	srv := newTestServer(t, &app.Config{
		Addr:             "127.0.0.1:0",
		PublicBaseURL:    "http://example.invalid",
		DatabaseURL:      filepath.Join(t.TempDir(), "audit.db"),
		GrokAPIURL:       "http://127.0.0.1:1",
		GrokAPIKey:       "upstream-key",
		GrokDefaultModel: "grok-test",
		APIKeys:          []string{"test-token"},
		UpstreamTimeout:  time.Second,
		MaxConcurrency:   4,
		RateLimitPerMin:  60,
		Logger:           slog.New(slog.NewJSONHandler(&logs, nil)),
	})
	req := newMCPRequest(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	requestID := rec.Header().Get("X-Request-Id")
	if len(requestID) != 32 {
		t.Fatalf("generated request id length = %d value %q", len(requestID), requestID)
	}
	if !bytes.Contains(logs.Bytes(), []byte(`"request_id":"`+requestID+`"`)) {
		t.Fatalf("access log did not include generated request id %q in %s", requestID, logs.String())
	}
}

func TestPanicRecoveryReturnsStableErrorAndMetrics(t *testing.T) {
	var logs bytes.Buffer
	srv, err := app.NewServer(app.Config{
		Addr:             "127.0.0.1:0",
		PublicBaseURL:    "http://example.invalid",
		DatabaseURL:      filepath.Join(t.TempDir(), "audit.db"),
		GrokAPIURL:       "http://127.0.0.1:1",
		GrokAPIKey:       "upstream-key",
		GrokDefaultModel: "grok-test",
		APIKeys:          []string{"test-token"},
		UpstreamTimeout:  time.Second,
		MaxConcurrency:   4,
		RateLimitPerMin:  60,
		Logger:           slog.New(slog.NewJSONHandler(&logs, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close(context.Background()) })
	srv.RegisterTool(panicTool{})

	req := newMCPRequest(`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"panic_tool","arguments":{"query":"secret prompt"}}}`)
	req.Header.Set("X-Request-Id", "req-panic-123")
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("X-Request-Id"); got != "req-panic-123" {
		t.Fatalf("X-Request-Id = %q, want req-panic-123", got)
	}
	body := decodeObject(t, rec.Body.Bytes())
	if body["error"] != "internal server error" || body["request_id"] != "req-panic-123" {
		t.Fatalf("unexpected body: %#v", body)
	}
	logText := logs.String()
	for _, want := range []string{
		`"msg":"http_request"`,
		`"request_id":"req-panic-123"`,
		`"status":500`,
	} {
		if !bytes.Contains([]byte(logText), []byte(want)) {
			t.Fatalf("access log missing %q in %s", want, logText)
		}
	}
	for _, leaked := range []string{"boom", "secret prompt", "test-token"} {
		if bytes.Contains([]byte(logText), []byte(leaked)) {
			t.Fatalf("access log leaked %q: %s", leaked, logText)
		}
	}

	metricsReq := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	metricsRec := httptest.NewRecorder()
	srv.ServeHTTP(metricsRec, metricsReq)
	wantMetric := `mcp_gateway_http_requests_total{route="/mcp",method="POST",status="500"} 1`
	if !bytes.Contains(metricsRec.Body.Bytes(), []byte(wantMetric)) {
		t.Fatalf("metrics missing %q in:\n%s", wantMetric, metricsRec.Body.String())
	}
}

func TestMetricsExposesOperationalCounters(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, nil)
	_ = doMCP(t, srv, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/plain; version=0.0.4" {
		t.Fatalf("Content-Type = %q", ct)
	}
	for _, want := range []string{
		`mcp_gateway_build_info{service="mcp-gateway",version="dev",commit="none",date="unknown"} 1`,
		`mcp_gateway_tools_registered 3`,
		`mcp_gateway_upstream_inflight 0`,
		`mcp_gateway_http_requests_total{route="/mcp",method="POST",status="200"} 1`,
		`mcp_gateway_http_request_duration_seconds_bucket{route="/mcp",method="POST",status="200",le="+Inf"} 1`,
		`mcp_gateway_http_request_duration_seconds_count{route="/mcp",method="POST",status="200"} 1`,
		`mcp_gateway_rpc_requests_total{method="tools/list",status="ok"} 1`,
	} {
		if !bytes.Contains(rec.Body.Bytes(), []byte(want)) {
			t.Fatalf("metrics missing %q in:\n%s", want, rec.Body.String())
		}
	}
}

func TestMetricsCountsUnauthorizedRequests(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, nil)
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	want := `mcp_gateway_http_requests_total{route="/mcp",method="POST",status="401"} 1`
	if !bytes.Contains(rec.Body.Bytes(), []byte(want)) {
		t.Fatalf("metrics missing %q in:\n%s", want, rec.Body.String())
	}
}

func TestMetricsCountsToolCallsAndCacheResults(t *testing.T) {
	t.Parallel()

	var upstreamCalls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []any{
				map[string]any{
					"message": map[string]any{"content": "cached answer"},
				},
			},
			"search_sources": []any{
				map[string]any{"title": "Example", "url": "https://example.com"},
			},
		})
	}))
	t.Cleanup(upstream.Close)

	dbPath := filepath.Join(t.TempDir(), "audit.db")
	srv := newTestServer(t, &app.Config{
		Addr:             "127.0.0.1:0",
		PublicBaseURL:    "http://example.invalid",
		DatabaseURL:      dbPath,
		GrokAPIURL:       upstream.URL,
		GrokAPIKey:       "upstream-key",
		GrokDefaultModel: "grok-test",
		APIKeys:          []string{"test-token"},
		CacheTTL:         time.Minute,
		UpstreamTimeout:  time.Second,
		MaxConcurrency:   4,
		RateLimitPerMin:  60,
	})
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"grok_search","arguments":{"query":"cache metric test SECRET_CACHE_QUERY"}}}`
	first := doMCP(t, srv, body)
	if first.Code != http.StatusOK {
		t.Fatalf("first status = %d body=%s", first.Code, first.Body.String())
	}
	second := doMCP(t, srv, body)
	if second.Code != http.StatusOK {
		t.Fatalf("second status = %d body=%s", second.Code, second.Body.String())
	}
	if got := upstreamCalls.Load(); got != 1 {
		t.Fatalf("upstream calls = %d, want 1", got)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var cacheKey string
	if err := db.QueryRowContext(context.Background(), `select cache_key from response_cache limit 1`).Scan(&cacheKey); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains([]byte(cacheKey), []byte("SECRET_CACHE_QUERY")) || bytes.Contains([]byte(cacheKey), []byte("cache metric test")) {
		t.Fatalf("cache key leaked query text: %q", cacheKey)
	}

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	for _, want := range []string{
		`mcp_gateway_tool_calls_total{tool="grok_search",status="ok"} 2`,
		`mcp_gateway_tool_call_duration_seconds_bucket{tool="grok_search",status="ok",le="+Inf"} 2`,
		`mcp_gateway_tool_call_duration_seconds_count{tool="grok_search",status="ok"} 2`,
		`mcp_gateway_cache_requests_total{tool="grok_search",result="miss"} 1`,
		`mcp_gateway_cache_requests_total{tool="grok_search",result="hit"} 1`,
	} {
		if !bytes.Contains(rec.Body.Bytes(), []byte(want)) {
			t.Fatalf("metrics missing %q in:\n%s", want, rec.Body.String())
		}
	}
}

func TestMetricsCanRequireBearerToken(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, &app.Config{
		Addr:             "127.0.0.1:0",
		PublicBaseURL:    "http://example.invalid",
		DatabaseURL:      filepath.Join(t.TempDir(), "audit.db"),
		GrokAPIURL:       "http://127.0.0.1:1",
		GrokAPIKey:       "upstream-key",
		GrokDefaultModel: "grok-test",
		APIKeys:          []string{"test-token"},
		ProtectMetrics:   true,
		UpstreamTimeout:  time.Second,
		MaxConcurrency:   4,
		RateLimitPerMin:  60,
	})
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status without token = %d body=%s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status with token = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestToolsListReturnsGrokTools(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, nil)
	rec := doMCP(t, srv, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	body := decodeObject(t, rec.Body.Bytes())
	tools := body["result"].(map[string]any)["tools"].([]any)
	names := make(map[string]bool, len(tools))
	for _, item := range tools {
		tool := item.(map[string]any)
		names[tool["name"].(string)] = true
		if tool["title"] == "" {
			t.Fatalf("tool missing title: %#v", tool)
		}
		if _, ok := tool["outputSchema"].(map[string]any); !ok {
			t.Fatalf("tool missing outputSchema: %#v", tool)
		}
		annotations, ok := tool["annotations"].(map[string]any)
		if !ok {
			t.Fatalf("tool missing annotations: %#v", tool)
		}
		if annotations["readOnlyHint"] != true || annotations["destructiveHint"] != false || annotations["openWorldHint"] != true {
			t.Fatalf("unexpected annotations for %s: %#v", tool["name"], annotations)
		}
	}
	for _, name := range []string{"grok_search", "grok_extract", "grok_sources"} {
		if !names[name] {
			t.Fatalf("missing tool %q in %#v", name, names)
		}
	}
}

func TestGrokProviderCanBeDisabledWithoutUpstreamConfig(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, &app.Config{
		Addr:            "127.0.0.1:0",
		PublicBaseURL:   "http://example.invalid",
		DatabaseURL:     filepath.Join(t.TempDir(), "audit.db"),
		APIKeys:         []string{"test-token"},
		UpstreamTimeout: time.Second,
		MaxConcurrency:  4,
		RateLimitPerMin: 60,
		GrokDisabled:    true,
	})
	rec := doMCP(t, srv, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	body := decodeObject(t, rec.Body.Bytes())
	tools := body["result"].(map[string]any)["tools"].([]any)
	if len(tools) != 0 {
		t.Fatalf("tools = %#v, want none when Grok is disabled", tools)
	}
}

func TestScopedAPIKeyFiltersToolsList(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, &app.Config{
		Addr:             "127.0.0.1:0",
		PublicBaseURL:    "http://example.invalid",
		DatabaseURL:      filepath.Join(t.TempDir(), "audit.db"),
		GrokAPIURL:       "http://127.0.0.1:1",
		GrokAPIKey:       "upstream-key",
		GrokDefaultModel: "grok-test",
		APIKeys:          []string{"search-token=tool:grok_search"},
		UpstreamTimeout:  time.Second,
		MaxConcurrency:   4,
		RateLimitPerMin:  60,
	})
	req := newMCPRequestWithToken("search-token", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	body := decodeObject(t, rec.Body.Bytes())
	tools := body["result"].(map[string]any)["tools"].([]any)
	if len(tools) != 1 {
		t.Fatalf("tool count = %d, want 1: %#v", len(tools), tools)
	}
	tool := tools[0].(map[string]any)
	if tool["name"] != "grok_search" {
		t.Fatalf("tool name = %v, want grok_search", tool["name"])
	}
}

func TestScopedAPIKeyRejectsUnauthorizedToolCall(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, &app.Config{
		Addr:             "127.0.0.1:0",
		PublicBaseURL:    "http://example.invalid",
		DatabaseURL:      filepath.Join(t.TempDir(), "audit.db"),
		GrokAPIURL:       "http://127.0.0.1:1",
		GrokAPIKey:       "upstream-key",
		GrokDefaultModel: "grok-test",
		APIKeys:          []string{"search-token=tool:grok_search"},
		UpstreamTimeout:  time.Second,
		MaxConcurrency:   4,
		RateLimitPerMin:  60,
	})
	req := newMCPRequestWithToken("search-token", `{
		"jsonrpc":"2.0",
		"id":2,
		"method":"tools/call",
		"params":{"name":"grok_extract","arguments":{"query":"extract this"}}
	}`)
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	body := decodeObject(t, rec.Body.Bytes())
	errObj, ok := body["error"].(map[string]any)
	if !ok {
		t.Fatalf("missing error in %s", rec.Body.String())
	}
	if errObj["code"] != float64(-32001) {
		t.Fatalf("error code = %v, want -32001", errObj["code"])
	}
}

func TestScopedAPIKeyProviderScopeAllowsProviderTools(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, &app.Config{
		Addr:             "127.0.0.1:0",
		PublicBaseURL:    "http://example.invalid",
		DatabaseURL:      filepath.Join(t.TempDir(), "audit.db"),
		GrokAPIURL:       "http://127.0.0.1:1",
		GrokAPIKey:       "upstream-key",
		GrokDefaultModel: "grok-test",
		APIKeys:          []string{"grok-token=provider:grok"},
		UpstreamTimeout:  time.Second,
		MaxConcurrency:   4,
		RateLimitPerMin:  60,
	})
	req := newMCPRequestWithToken("grok-token", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	body := decodeObject(t, rec.Body.Bytes())
	tools := body["result"].(map[string]any)["tools"].([]any)
	if len(tools) != 3 {
		t.Fatalf("tool count = %d, want 3: %#v", len(tools), tools)
	}
}

func TestRejectsDuplicateAPIKeys(t *testing.T) {
	t.Parallel()

	srv, err := app.NewServer(app.Config{
		Addr:             "127.0.0.1:0",
		PublicBaseURL:    "http://example.invalid",
		DatabaseURL:      filepath.Join(t.TempDir(), "audit.db"),
		GrokAPIURL:       "http://127.0.0.1:1",
		GrokAPIKey:       "upstream-key",
		GrokDefaultModel: "grok-test",
		APIKeys:          []string{"same-token=tool:grok_search", "same-token=tool:grok_extract"},
		UpstreamTimeout:  time.Second,
		MaxConcurrency:   4,
		RateLimitPerMin:  60,
	})
	if err == nil {
		_ = srv.Close(context.Background())
		t.Fatal("NewServer succeeded with duplicate API keys")
	}
}

func TestRejectsEmptyScopedAPIKey(t *testing.T) {
	t.Parallel()

	srv, err := app.NewServer(app.Config{
		Addr:             "127.0.0.1:0",
		PublicBaseURL:    "http://example.invalid",
		DatabaseURL:      filepath.Join(t.TempDir(), "audit.db"),
		GrokAPIURL:       "http://127.0.0.1:1",
		GrokAPIKey:       "upstream-key",
		GrokDefaultModel: "grok-test",
		APIKeys:          []string{"empty-scope-token="},
		UpstreamTimeout:  time.Second,
		MaxConcurrency:   4,
		RateLimitPerMin:  60,
	})
	if err == nil {
		_ = srv.Close(context.Background())
		t.Fatal("NewServer succeeded with empty scoped API key")
	}
}

func TestRejectsMalformedScopedAPIKey(t *testing.T) {
	t.Parallel()

	srv, err := app.NewServer(app.Config{
		Addr:             "127.0.0.1:0",
		PublicBaseURL:    "http://example.invalid",
		DatabaseURL:      filepath.Join(t.TempDir(), "audit.db"),
		GrokAPIURL:       "http://127.0.0.1:1",
		GrokAPIKey:       "upstream-key",
		GrokDefaultModel: "grok-test",
		APIKeys:          []string{"bad-scope-token=tool:grok_search|"},
		UpstreamTimeout:  time.Second,
		MaxConcurrency:   4,
		RateLimitPerMin:  60,
	})
	if err == nil {
		_ = srv.Close(context.Background())
		t.Fatal("NewServer succeeded with malformed scoped API key")
	}
}

func TestRejectsBlankBearerToken(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, nil)
	req := newMCPRequest(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	req.Header.Set("Authorization", "Bearer ")
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestPublicBaseURLRequiresAPIKeys(t *testing.T) {
	t.Parallel()

	srv, err := app.NewServer(app.Config{
		Addr:             "127.0.0.1:0",
		PublicBaseURL:    "https://mcp.example.com/mcp",
		DatabaseURL:      filepath.Join(t.TempDir(), "audit.db"),
		GrokAPIURL:       "http://127.0.0.1:1",
		GrokAPIKey:       "upstream-key",
		GrokDefaultModel: "grok-test",
		UpstreamTimeout:  time.Second,
		MaxConcurrency:   4,
		RateLimitPerMin:  60,
	})
	if err == nil {
		_ = srv.Close(context.Background())
		t.Fatal("NewServer succeeded without API keys for public base URL")
	}
}

func TestRejectsInvalidPublicBaseURL(t *testing.T) {
	t.Parallel()

	srv, err := app.NewServer(app.Config{
		Addr:             "127.0.0.1:0",
		PublicBaseURL:    "ftp://mcp.example.com/mcp",
		DatabaseURL:      filepath.Join(t.TempDir(), "audit.db"),
		GrokAPIURL:       "http://127.0.0.1:1",
		GrokAPIKey:       "upstream-key",
		GrokDefaultModel: "grok-test",
		APIKeys:          []string{"test-token"},
		UpstreamTimeout:  time.Second,
		MaxConcurrency:   4,
		RateLimitPerMin:  60,
	})
	if err == nil {
		_ = srv.Close(context.Background())
		t.Fatal("NewServer succeeded with invalid public base URL")
	}
}

func TestRejectsInvalidGrokAPIURL(t *testing.T) {
	t.Parallel()

	for _, rawURL := range []string{"", "ftp://api.example.invalid/v1/chat/completions", "://bad"} {
		t.Run(rawURL, func(t *testing.T) {
			srv, err := app.NewServer(app.Config{
				Addr:             "127.0.0.1:0",
				PublicBaseURL:    "http://example.invalid",
				DatabaseURL:      filepath.Join(t.TempDir(), "audit.db"),
				GrokAPIURL:       rawURL,
				GrokAPIKey:       "upstream-key",
				GrokDefaultModel: "grok-test",
				APIKeys:          []string{"test-token"},
				UpstreamTimeout:  time.Second,
				MaxConcurrency:   4,
				RateLimitPerMin:  60,
			})
			if err == nil {
				_ = srv.Close(context.Background())
				t.Fatalf("NewServer succeeded with Grok API URL %q", rawURL)
			}
		})
	}
}

func TestRejectsInvalidAllowedOrigin(t *testing.T) {
	t.Parallel()

	srv, err := app.NewServer(app.Config{
		Addr:             "127.0.0.1:0",
		PublicBaseURL:    "http://example.invalid",
		DatabaseURL:      filepath.Join(t.TempDir(), "audit.db"),
		GrokAPIURL:       "http://127.0.0.1:1",
		GrokAPIKey:       "upstream-key",
		GrokDefaultModel: "grok-test",
		APIKeys:          []string{"test-token"},
		AllowedOrigins:   []string{"ftp://example.invalid"},
		UpstreamTimeout:  time.Second,
		MaxConcurrency:   4,
		RateLimitPerMin:  60,
	})
	if err == nil {
		_ = srv.Close(context.Background())
		t.Fatal("NewServer succeeded with invalid allowed origin")
	}
}

func TestRejectsInvalidAuthorizationServer(t *testing.T) {
	t.Parallel()

	srv, err := app.NewServer(app.Config{
		Addr:                 "127.0.0.1:0",
		PublicBaseURL:        "http://example.invalid",
		DatabaseURL:          filepath.Join(t.TempDir(), "audit.db"),
		GrokAPIURL:           "http://127.0.0.1:1",
		GrokAPIKey:           "upstream-key",
		GrokDefaultModel:     "grok-test",
		APIKeys:              []string{"test-token"},
		AuthorizationServers: []string{"auth.example.com"},
		UpstreamTimeout:      time.Second,
		MaxConcurrency:       4,
		RateLimitPerMin:      60,
	})
	if err == nil {
		_ = srv.Close(context.Background())
		t.Fatal("NewServer succeeded with invalid authorization server")
	}
}

func TestInitializeReturnsToolsCapability(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, nil)
	rec := doMCP(t, srv, `{"jsonrpc":"2.0","id":1,"method":"initialize"}`)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("MCP-Protocol-Version"); got != "2025-06-18" {
		t.Fatalf("MCP-Protocol-Version = %q", got)
	}
	body := decodeObject(t, rec.Body.Bytes())
	result := body["result"].(map[string]any)
	if result["protocolVersion"] != "2025-06-18" {
		t.Fatalf("protocolVersion = %v", result["protocolVersion"])
	}
	capabilities := result["capabilities"].(map[string]any)
	tools := capabilities["tools"].(map[string]any)
	if tools["listChanged"] != false {
		t.Fatalf("tools.listChanged = %v, want false", tools["listChanged"])
	}
	serverInfo := result["serverInfo"].(map[string]any)
	if serverInfo["name"] != "mcp-gateway" {
		t.Fatalf("serverInfo.name = %v", serverInfo["name"])
	}
	if serverInfo["version"] != "dev" {
		t.Fatalf("serverInfo.version = %v", serverInfo["version"])
	}
}

func TestPingReturnsEmptyResult(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, nil)
	rec := doMCP(t, srv, `{"jsonrpc":"2.0","id":1,"method":"ping"}`)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	body := decodeObject(t, rec.Body.Bytes())
	result, ok := body["result"].(map[string]any)
	if !ok || len(result) != 0 {
		t.Fatalf("result = %#v, want empty object", body["result"])
	}

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	metrics := httptest.NewRecorder()
	srv.ServeHTTP(metrics, req)
	want := `mcp_gateway_rpc_requests_total{method="ping",status="ok"} 1`
	if !bytes.Contains(metrics.Body.Bytes(), []byte(want)) {
		t.Fatalf("metrics missing %q in:\n%s", want, metrics.Body.String())
	}
}

func TestRejectsUnsupportedProtocolVersionHeader(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, nil)
	req := newMCPRequest(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	req.Header.Set("MCP-Protocol-Version", "2099-01-01")
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestRejectsInvalidJSONRPCEnvelope(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, nil)
	for _, tc := range []struct {
		name string
		body string
		code int
	}{
		{name: "batch not supported", body: `[{"jsonrpc":"2.0","id":1,"method":"tools/list"}]`, code: http.StatusBadRequest},
		{name: "missing method", body: `{"jsonrpc":"2.0","id":1}`, code: http.StatusOK},
		{name: "wrong jsonrpc", body: `{"jsonrpc":"1.0","id":1,"method":"tools/list"}`, code: http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := newMCPRequest(tc.body)
			rec := httptest.NewRecorder()
			srv.ServeHTTP(rec, req)
			if rec.Code != tc.code {
				t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
			}
			if tc.code == http.StatusOK {
				body := decodeObject(t, rec.Body.Bytes())
				errObj, ok := body["error"].(map[string]any)
				if !ok || errObj["code"] == nil {
					t.Fatalf("missing JSON-RPC error in %s", rec.Body.String())
				}
			}
		})
	}
}

func TestNotificationReturnsAcceptedWithoutBody(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, nil)
	rec := doMCP(t, srv, `{"jsonrpc":"2.0","method":"notifications/initialized"}`)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	if rec.Body.Len() != 0 {
		t.Fatalf("body = %q, want empty", rec.Body.String())
	}
}

func TestJSONRPCNotificationWithoutIDReturnsNoBody(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, nil)
	rec := doMCP(t, srv, `{"jsonrpc":"2.0","method":"unknown/notification"}`)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	if rec.Body.Len() != 0 {
		t.Fatalf("body = %q, want empty", rec.Body.String())
	}

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	metrics := httptest.NewRecorder()
	srv.ServeHTTP(metrics, req)
	want := `mcp_gateway_rpc_requests_total{method="notification",status="accepted"} 1`
	if !bytes.Contains(metrics.Body.Bytes(), []byte(want)) {
		t.Fatalf("metrics missing %q in:\n%s", want, metrics.Body.String())
	}
	if bytes.Contains(metrics.Body.Bytes(), []byte("unknown/notification")) {
		t.Fatalf("metrics should not expose arbitrary notification method names:\n%s", metrics.Body.String())
	}
}

func TestJSONRPCNullIDIsStillARequest(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, nil)
	rec := doMCP(t, srv, `{"jsonrpc":"2.0","id":null,"method":"unknown/request"}`)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	body := decodeObject(t, rec.Body.Bytes())
	errObj, ok := body["error"].(map[string]any)
	if !ok {
		t.Fatalf("missing error in %s", rec.Body.String())
	}
	if errObj["code"] != float64(-32601) {
		t.Fatalf("error code = %v, want -32601", errObj["code"])
	}
	if _, ok := body["id"]; !ok {
		t.Fatalf("response omitted explicit null id: %s", rec.Body.String())
	}
}

func TestStreamableHTTPHeaderValidation(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, nil)

	t.Run("wrong content type", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
		req.Header.Set("Authorization", "Bearer test-token")
		req.Header.Set("Content-Type", "text/plain")
		req.Header.Set("Accept", "application/json, text/event-stream")
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnsupportedMediaType {
			t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("missing event stream accept", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
		req.Header.Set("Authorization", "Bearer test-token")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotAcceptable {
			t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
		}
	})
}

func TestMCPRejectsBodyLargerThanConfiguredLimit(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, &app.Config{
		Addr:             "127.0.0.1:0",
		PublicBaseURL:    "http://example.invalid",
		DatabaseURL:      filepath.Join(t.TempDir(), "audit.db"),
		GrokAPIURL:       "http://127.0.0.1:1",
		GrokAPIKey:       "upstream-key",
		GrokDefaultModel: "grok-test",
		APIKeys:          []string{"test-token"},
		UpstreamTimeout:  time.Second,
		MaxConcurrency:   4,
		RateLimitPerMin:  60,
		MaxBodyBytes:     32,
	})
	req := newMCPRequest(`{"jsonrpc":"2.0","id":1,"method":"tools/list","padding":"this pushes the request over the configured limit"}`)
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	body := decodeObject(t, rec.Body.Bytes())
	if body["error"] != "request body too large" {
		t.Fatalf("body = %#v", body)
	}

	metricsReq := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	metricsRec := httptest.NewRecorder()
	srv.ServeHTTP(metricsRec, metricsReq)
	want := `mcp_gateway_http_requests_total{route="/mcp",method="POST",status="413"} 1`
	if !bytes.Contains(metricsRec.Body.Bytes(), []byte(want)) {
		t.Fatalf("metrics missing %q in:\n%s", want, metricsRec.Body.String())
	}
}

func TestMCPGetReturnsMethodNotAllowedWhenStreamingDisabled(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, nil)
	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	if allow := rec.Header().Get("Allow"); allow != "POST" {
		t.Fatalf("Allow = %q, want POST", allow)
	}
}

func TestMCPDeleteReturnsMethodNotAllowedWhenSessionsDisabled(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, nil)
	req := httptest.NewRequest(http.MethodDelete, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	if allow := rec.Header().Get("Allow"); allow != "POST" {
		t.Fatalf("Allow = %q, want POST", allow)
	}
}

func TestOptionsDoesNotRequireAuth(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, nil)
	req := httptest.NewRequest(http.MethodOptions, "/mcp", nil)
	req.Header.Set("Origin", "http://example.invalid")
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestOriginAllowlistRejectsUntrustedOrigin(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, &app.Config{
		Addr:             "127.0.0.1:0",
		PublicBaseURL:    "https://mcp.example.com",
		DatabaseURL:      filepath.Join(t.TempDir(), "audit.db"),
		GrokAPIURL:       "http://127.0.0.1:1",
		GrokAPIKey:       "upstream-key",
		GrokDefaultModel: "grok-test",
		APIKeys:          []string{"test-token"},
		AllowedOrigins:   []string{"https://agents.example.com"},
		UpstreamTimeout:  time.Second,
		MaxConcurrency:   4,
		RateLimitPerMin:  60,
	})
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	req.Header.Set("Authorization", "Bearer test-token")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Origin", "https://evil.example")
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestOriginRequiresExplicitAllowlistWhenPresent(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, &app.Config{
		Addr:             "127.0.0.1:0",
		DatabaseURL:      filepath.Join(t.TempDir(), "audit.db"),
		GrokAPIURL:       "http://127.0.0.1:1",
		GrokAPIKey:       "upstream-key",
		GrokDefaultModel: "grok-test",
		APIKeys:          []string{"test-token"},
		UpstreamTimeout:  time.Second,
		MaxConcurrency:   4,
		RateLimitPerMin:  60,
	})
	req := newMCPRequest(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	req.Header.Set("Origin", "https://browser.example")
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestRequestsWithoutOriginDoNotRequireAllowlist(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, &app.Config{
		Addr:             "127.0.0.1:0",
		DatabaseURL:      filepath.Join(t.TempDir(), "audit.db"),
		GrokAPIURL:       "http://127.0.0.1:1",
		GrokAPIKey:       "upstream-key",
		GrokDefaultModel: "grok-test",
		APIKeys:          []string{"test-token"},
		UpstreamTimeout:  time.Second,
		MaxConcurrency:   4,
		RateLimitPerMin:  60,
	})
	rec := doMCP(t, srv, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestPublicBaseURLBecomesDefaultAllowedOrigin(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, &app.Config{
		Addr:             "127.0.0.1:0",
		PublicBaseURL:    "https://mcp.example.com/mcp",
		DatabaseURL:      filepath.Join(t.TempDir(), "audit.db"),
		GrokAPIURL:       "http://127.0.0.1:1",
		GrokAPIKey:       "upstream-key",
		GrokDefaultModel: "grok-test",
		APIKeys:          []string{"test-token"},
		UpstreamTimeout:  time.Second,
		MaxConcurrency:   4,
		RateLimitPerMin:  60,
	})
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	req.Header.Set("Authorization", "Bearer test-token")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Origin", "https://evil.example")
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	req.Header.Set("Authorization", "Bearer test-token")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Origin", "https://mcp.example.com")
	rec = httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestServerPrunesOldAuditRowsOnStartup(t *testing.T) {
	t.Parallel()

	dbPath := filepath.Join(t.TempDir(), "startup-prune.db")
	st, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	st.Close()

	initial, err := app.NewServer(app.Config{
		Addr:             "127.0.0.1:0",
		PublicBaseURL:    "http://example.invalid",
		DatabaseURL:      dbPath,
		GrokAPIURL:       "http://127.0.0.1:1",
		GrokAPIKey:       "upstream-key",
		GrokDefaultModel: "grok-test",
		APIKeys:          []string{"test-token"},
		UpstreamTimeout:  time.Second,
		MaxConcurrency:   4,
		RateLimitPerMin:  60,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := initial.Close(context.Background()); err != nil {
		t.Fatal(err)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	oldTS := time.Now().UTC().Add(-48 * time.Hour).Format(time.RFC3339Nano)
	newTS := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339Nano)
	if _, err := db.ExecContext(context.Background(), `insert into tool_calls (ts, agent_id, tool_name, status, latency_ms, source_count) values (?, 'agent:old', 'grok_search', 'ok', 1, 0), (?, 'agent:new', 'grok_search', 'ok', 1, 0)`, oldTS, newTS); err != nil {
		t.Fatal(err)
	}

	srv, err := app.NewServer(app.Config{
		Addr:             "127.0.0.1:0",
		PublicBaseURL:    "http://example.invalid",
		DatabaseURL:      dbPath,
		GrokAPIURL:       "http://127.0.0.1:1",
		GrokAPIKey:       "upstream-key",
		GrokDefaultModel: "grok-test",
		APIKeys:          []string{"test-token"},
		AuditRetention:   24 * time.Hour,
		CleanupInterval:  0,
		UpstreamTimeout:  time.Second,
		MaxConcurrency:   4,
		RateLimitPerMin:  60,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close(context.Background()) })

	var oldCount int
	if err := db.QueryRowContext(context.Background(), `select count(*) from tool_calls where agent_id='agent:old'`).Scan(&oldCount); err != nil {
		t.Fatal(err)
	}
	if oldCount != 0 {
		t.Fatalf("old audit rows = %d, want 0", oldCount)
	}
	var newCount int
	if err := db.QueryRowContext(context.Background(), `select count(*) from tool_calls where agent_id='agent:new'`).Scan(&newCount); err != nil {
		t.Fatal(err)
	}
	if newCount != 1 {
		t.Fatalf("new audit rows = %d, want 1", newCount)
	}
}

func TestGrokSearchToolCallsUpstreamAndStoresAudit(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer upstream-key" {
			t.Fatalf("Authorization = %q", got)
		}
		var req map[string]any
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatal(err)
		}
		if req["model"] != "grok-test" {
			t.Fatalf("model = %v", req["model"])
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []any{
				map[string]any{
					"message": map[string]any{"content": "answer with [1](https://example.com)"},
				},
			},
			"search_sources": []any{
				map[string]any{"title": "Example", "url": "https://example.com"},
			},
		})
	}))
	t.Cleanup(upstream.Close)

	dbPath := filepath.Join(t.TempDir(), "audit.db")
	srv := newTestServer(t, &app.Config{
		Addr:             "127.0.0.1:0",
		PublicBaseURL:    "http://example.invalid",
		DatabaseURL:      dbPath,
		GrokAPIURL:       upstream.URL,
		GrokAPIKey:       "upstream-key",
		GrokDefaultModel: "grok-test",
		APIKeys:          []string{"test-token"},
		UpstreamTimeout:  2 * time.Second,
		MaxConcurrency:   4,
		RateLimitPerMin:  60,
	})

	req := newMCPRequest(`{
		"jsonrpc":"2.0",
		"id":2,
		"method":"tools/call",
		"params":{
			"name":"grok_search",
			"arguments":{
				"query":"Find the current MCP Streamable HTTP best practice. Explain why it matters and list sources.",
				"max_tokens":512
			}
		}
	}`)
	req.Header.Set("X-Request-Id", "req-tool-call-123")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	body := decodeObject(t, rec.Body.Bytes())
	result := body["result"].(map[string]any)
	content := result["content"].([]any)
	text := content[0].(map[string]any)["text"].(string)
	if !bytes.Contains([]byte(text), []byte("answer with")) || !bytes.Contains([]byte(text), []byte("https://example.com")) {
		t.Fatalf("unexpected tool text: %s", text)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var requestID string
	if err := db.QueryRowContext(context.Background(), `select request_id from tool_calls where tool_name='grok_search' and status='ok'`).Scan(&requestID); err != nil {
		t.Fatal(err)
	}
	if requestID != "req-tool-call-123" {
		t.Fatalf("request_id = %q, want req-tool-call-123", requestID)
	}
}

func newTestServer(t *testing.T, cfg *app.Config) http.Handler {
	t.Helper()
	if cfg == nil {
		cfg = &app.Config{
			Addr:             "127.0.0.1:0",
			PublicBaseURL:    "http://example.invalid",
			DatabaseURL:      filepath.Join(t.TempDir(), "audit.db"),
			GrokAPIURL:       "http://127.0.0.1:1",
			GrokAPIKey:       "upstream-key",
			GrokDefaultModel: "grok-test",
			APIKeys:          []string{"test-token"},
			UpstreamTimeout:  time.Second,
			MaxConcurrency:   4,
			RateLimitPerMin:  60,
		}
	}
	srv, err := app.NewServer(*cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close(context.Background()) })
	return srv
}

func doMCP(t *testing.T, srv http.Handler, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := newMCPRequest(body)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	return rec
}

func newMCPRequest(body string) *http.Request {
	return newMCPRequestWithToken("test-token", body)
}

func newMCPRequestWithToken(token, body string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	return req
}

func decodeObject(t *testing.T, data []byte) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("decode %s: %v", string(data), err)
	}
	return out
}

type panicTool struct{}

func (panicTool) Definition() app.ToolDefinition {
	return app.ToolDefinition{
		Name:        "panic_tool",
		Description: "panic test tool",
		InputSchema: map[string]any{
			"type": "object",
		},
		Scopes: []string{"tool:panic_tool"},
	}
}

func (panicTool) Call(context.Context, map[string]any) (app.ToolCallResult, error) {
	panic("boom")
}
