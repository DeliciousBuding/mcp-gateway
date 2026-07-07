package grok_test

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DeliciousBuding/mcp-gateway/internal/grok"
)

func TestClientParsesOpenAICompatibleSearchSources(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []any{map[string]any{"message": map[string]any{"content": "ok"}}},
			"search_sources": []any{
				map[string]any{"title": "Source", "url": "https://example.com"},
			},
		})
	}))
	t.Cleanup(upstream.Close)

	client := grok.NewClient(grok.Config{
		APIURL:       upstream.URL,
		APIKey:       "key",
		DefaultModel: "grok-test",
		Timeout:      time.Second,
	})
	res, err := client.Search(context.Background(), grok.SearchRequest{
		Query:     "Find current MCP Streamable HTTP guidance. Include why it matters and cite sources.",
		MaxTokens: 128,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Content != "ok" {
		t.Fatalf("content = %q", res.Content)
	}
	if len(res.Sources) != 1 || res.Sources[0].URL != "https://example.com" {
		t.Fatalf("sources = %#v", res.Sources)
	}
}

func TestClientRetriesTransientUpstreamFailure(t *testing.T) {
	t.Parallel()

	var calls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			http.Error(w, "temporary failure", http.StatusBadGateway)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []any{map[string]any{"message": map[string]any{"content": "ok after retry"}}},
		})
	}))
	t.Cleanup(upstream.Close)

	client := grok.NewClient(grok.Config{
		APIURL:       upstream.URL,
		DefaultModel: "grok-test",
		Timeout:      time.Second,
		MaxRetries:   1,
	})
	res, err := client.Search(context.Background(), grok.SearchRequest{
		Query:     "Retry this transient upstream failure and return the successful answer.",
		MaxTokens: 128,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Content != "ok after retry" {
		t.Fatalf("content = %q", res.Content)
	}
	if calls.Load() != 2 {
		t.Fatalf("calls = %d, want 2", calls.Load())
	}
}

func TestClientFallsBackToNextModelAfterUpstreamFailure(t *testing.T) {
	t.Parallel()

	var models []string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatal(err)
		}
		model := req["model"].(string)
		models = append(models, model)
		if model == "primary-model" {
			http.Error(w, "primary model unavailable", http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []any{map[string]any{"message": map[string]any{"content": "fallback answer"}}},
		})
	}))
	t.Cleanup(upstream.Close)

	client := grok.NewClient(grok.Config{
		APIURL:       upstream.URL,
		DefaultModel: "primary-model",
		Timeout:      time.Second,
		MaxRetries:   0,
	})
	res, err := client.Search(context.Background(), grok.SearchRequest{
		Query:          "Use fallback if the primary model is unavailable.",
		FallbackModels: []string{"fallback-model"},
		MaxTokens:      128,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Content != "fallback answer" || res.Model != "fallback-model" {
		t.Fatalf("response = %#v", res)
	}
	if strings.Join(models, ",") != "primary-model,fallback-model" {
		t.Fatalf("models = %#v", models)
	}
}

func TestClientRedactsNon2xxUpstreamBody(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `provider echoed SECRET_PROMPT_BODY and internal details`, http.StatusBadGateway)
	}))
	t.Cleanup(upstream.Close)

	client := grok.NewClient(grok.Config{
		APIURL:       upstream.URL,
		DefaultModel: "grok-test",
		Timeout:      time.Second,
	})
	_, err := client.Search(context.Background(), grok.SearchRequest{
		Query:     "SECRET_PROMPT_BODY",
		MaxTokens: 128,
	})
	if err == nil {
		t.Fatal("expected upstream error")
	}
	text := err.Error()
	if !strings.Contains(text, "502") {
		t.Fatalf("error = %q, want status code", text)
	}
	if strings.Contains(text, "SECRET_PROMPT_BODY") || strings.Contains(text, "internal details") {
		t.Fatalf("error leaked upstream body: %q", text)
	}
}

func TestClientRedactsTransportErrorURL(t *testing.T) {
	t.Parallel()

	client := grok.NewClient(grok.Config{
		APIURL:       "http://127.0.0.1:1/SECRET_PROVIDER_PATH",
		DefaultModel: "grok-test",
		Timeout:      500 * time.Millisecond,
	})
	_, err := client.Search(context.Background(), grok.SearchRequest{
		Query:     "transport failure test",
		MaxTokens: 128,
	})
	if err == nil {
		t.Fatal("expected transport error")
	}
	text := err.Error()
	if !strings.Contains(text, "grok upstream request failed") {
		t.Fatalf("error = %q, want stable transport error", text)
	}
	if strings.Contains(text, "SECRET_PROVIDER_PATH") || strings.Contains(text, "127.0.0.1") {
		t.Fatalf("error leaked upstream URL details: %q", text)
	}
}

func TestClientRejectsOversizedUpstreamResponse(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"SECRET_OVERSIZED_RESPONSE_BODY_SHOULD_NOT_LEAK"}}]}`))
	}))
	t.Cleanup(upstream.Close)

	client := grok.NewClient(grok.Config{
		APIURL:           upstream.URL,
		DefaultModel:     "grok-test",
		Timeout:          time.Second,
		MaxResponseBytes: 32,
	})
	_, err := client.Search(context.Background(), grok.SearchRequest{
		Query:     "oversized response test",
		MaxTokens: 128,
	})
	if err == nil {
		t.Fatal("expected oversized response error")
	}
	text := err.Error()
	if !strings.Contains(text, "grok upstream response too large") {
		t.Fatalf("error = %q, want oversized response error", text)
	}
	if strings.Contains(text, "SECRET_OVERSIZED_RESPONSE_BODY_SHOULD_NOT_LEAK") {
		t.Fatalf("error leaked response body: %q", text)
	}
}

func TestClientHandlesMaxInt64ResponseLimit(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"ok"}}]}`))
	}))
	t.Cleanup(upstream.Close)

	client := grok.NewClient(grok.Config{
		APIURL:           upstream.URL,
		DefaultModel:     "grok-test",
		Timeout:          time.Second,
		MaxResponseBytes: math.MaxInt64,
	})
	res, err := client.Search(context.Background(), grok.SearchRequest{
		Query:     "max int64 response limit test",
		MaxTokens: 128,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Content != "ok" {
		t.Fatalf("content = %q", res.Content)
	}
}
