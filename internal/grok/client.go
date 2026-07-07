package grok

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"strings"
	"time"
)

const defaultSystemPrompt = "You are a web search assistant with access to real-time search. For every claim, cite sources inline as [N](url). Be accurate, concise, and factual. Use the user's language."

type Config struct {
	APIURL           string
	APIKey           string
	DefaultModel     string
	Timeout          time.Duration
	MaxResponseBytes int64
	MaxRetries       int
}

type Client struct {
	cfg  Config
	http *http.Client
}

type SearchRequest struct {
	Query          string
	Model          string
	FallbackModels []string
	MaxTokens      int
	JSONMode       bool
}

type SearchResponse struct {
	Content string
	Sources []Source
	Model   string
}

type Source struct {
	Title string `json:"title,omitempty"`
	URL   string `json:"url,omitempty"`
	Type  string `json:"type,omitempty"`
}

func NewClient(cfg Config) *Client {
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	if cfg.MaxResponseBytes <= 0 {
		cfg.MaxResponseBytes = 4 << 20
	}
	if cfg.MaxRetries < 0 {
		cfg.MaxRetries = 0
	}
	return &Client{
		cfg: cfg,
		http: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				Proxy:                 http.ProxyFromEnvironment,
				DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
				MaxIdleConns:          128,
				MaxIdleConnsPerHost:   32,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
				ForceAttemptHTTP2:     true,
			},
		},
	}
}

func (c *Client) Search(ctx context.Context, req SearchRequest) (SearchResponse, error) {
	if strings.TrimSpace(req.Query) == "" {
		return SearchResponse{}, errors.New("query is required")
	}
	if c.cfg.APIURL == "" {
		return SearchResponse{}, errors.New("grok api url is required")
	}
	models := c.searchModels(req)
	maxTokens := req.MaxTokens
	if maxTokens <= 0 {
		maxTokens = 2048
	}

	var lastErr error
	for _, model := range models {
		for attempt := 0; attempt <= c.cfg.MaxRetries; attempt++ {
			res, err := c.searchOnce(ctx, req, model, maxTokens)
			if err == nil {
				return res, nil
			}
			lastErr = err
			if !isRetryableUpstreamError(err) || attempt == c.cfg.MaxRetries || ctx.Err() != nil {
				break
			}
			if err := sleepWithContext(ctx, retryBackoff(attempt)); err != nil {
				return SearchResponse{}, errors.New("grok upstream request failed")
			}
		}
		if !isFallbackableUpstreamError(lastErr) {
			return SearchResponse{}, lastErr
		}
	}
	if lastErr != nil {
		return SearchResponse{}, lastErr
	}
	return SearchResponse{}, errors.New("grok upstream request failed")
}

func (c *Client) searchModels(req SearchRequest) []string {
	models := make([]string, 0, 1+len(req.FallbackModels))
	model := strings.TrimSpace(req.Model)
	if model == "" {
		model = strings.TrimSpace(c.cfg.DefaultModel)
	}
	if model == "" {
		model = "grok-4.3-fast"
	}
	models = append(models, model)
	seen := map[string]struct{}{model: struct{}{}}
	for _, fallback := range req.FallbackModels {
		fallback = strings.TrimSpace(fallback)
		if fallback == "" {
			continue
		}
		if _, ok := seen[fallback]; ok {
			continue
		}
		models = append(models, fallback)
		seen[fallback] = struct{}{}
	}
	return models
}

func (c *Client) searchOnce(ctx context.Context, req SearchRequest, model string, maxTokens int) (SearchResponse, error) {
	body, err := json.Marshal(searchPayload(req, model, maxTokens))
	if err != nil {
		return SearchResponse{}, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.APIURL, bytes.NewReader(body))
	if err != nil {
		return SearchResponse{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("User-Agent", "mcp-gateway/0.1")
	if c.cfg.APIKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.cfg.APIKey)
	}

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return SearchResponse{}, errUpstreamRequestFailed
	}
	defer resp.Body.Close()
	readLimit := c.cfg.MaxResponseBytes + 1
	if c.cfg.MaxResponseBytes == math.MaxInt64 {
		readLimit = math.MaxInt64
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, readLimit))
	if err != nil {
		return SearchResponse{}, err
	}
	if int64(len(raw)) > c.cfg.MaxResponseBytes {
		return SearchResponse{}, fmt.Errorf("grok upstream response too large (max_bytes=%d)", c.cfg.MaxResponseBytes)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return SearchResponse{}, upstreamStatusError{status: resp.StatusCode, bodyBytes: len(raw)}
	}

	var decoded struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		SearchSources []Source `json:"search_sources"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return SearchResponse{}, err
	}
	if len(decoded.Choices) == 0 {
		return SearchResponse{}, errors.New("grok upstream returned no choices")
	}
	return SearchResponse{
		Content: decoded.Choices[0].Message.Content,
		Sources: decoded.SearchSources,
		Model:   model,
	}, nil
}

func searchPayload(req SearchRequest, model string, maxTokens int) map[string]any {
	system := defaultSystemPrompt
	if req.JSONMode {
		system += " Return ONLY valid JSON. No markdown, no code block."
	}
	return map[string]any{
		"model": model,
		"messages": []map[string]string{
			{"role": "system", "content": system},
			{"role": "user", "content": req.Query},
		},
		"max_tokens": maxTokens,
		"stream":     false,
	}
}

var errUpstreamRequestFailed = errors.New("grok upstream request failed")

type upstreamStatusError struct {
	status    int
	bodyBytes int
}

func (e upstreamStatusError) Error() string {
	return fmt.Sprintf("grok upstream status %d (body_bytes=%d)", e.status, e.bodyBytes)
}

func isRetryableUpstreamError(err error) bool {
	if errors.Is(err, errUpstreamRequestFailed) {
		return true
	}
	var statusErr upstreamStatusError
	if errors.As(err, &statusErr) {
		switch statusErr.status {
		case http.StatusRequestTimeout, http.StatusTooManyRequests, http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
			return true
		}
	}
	return false
}

func isFallbackableUpstreamError(err error) bool {
	if errors.Is(err, errUpstreamRequestFailed) {
		return true
	}
	var statusErr upstreamStatusError
	return errors.As(err, &statusErr)
}

func retryBackoff(attempt int) time.Duration {
	d := 100 * time.Millisecond
	for i := 0; i < attempt; i++ {
		d *= 2
	}
	if d > 2*time.Second {
		return 2 * time.Second
	}
	return d
}

func sleepWithContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
