package grok_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
