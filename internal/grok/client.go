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
}

type Client struct {
	cfg  Config
	http *http.Client
}

type SearchRequest struct {
	Query     string
	Model     string
	MaxTokens int
	JSONMode  bool
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
	model := req.Model
	if model == "" {
		model = c.cfg.DefaultModel
	}
	if model == "" {
		model = "grok-4.3-fast"
	}
	maxTokens := req.MaxTokens
	if maxTokens <= 0 {
		maxTokens = 2048
	}
	system := defaultSystemPrompt
	if req.JSONMode {
		system += " Return ONLY valid JSON. No markdown, no code block."
	}
	payload := map[string]any{
		"model": model,
		"messages": []map[string]string{
			{"role": "system", "content": system},
			{"role": "user", "content": req.Query},
		},
		"max_tokens": maxTokens,
		"stream":     false,
	}
	body, err := json.Marshal(payload)
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
		return SearchResponse{}, errors.New("grok upstream request failed")
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
		return SearchResponse{}, fmt.Errorf("grok upstream status %d (body_bytes=%d)", resp.StatusCode, len(raw))
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
