package grok_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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
