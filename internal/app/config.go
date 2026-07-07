package app

import (
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"
	"unicode"
)

type Config struct {
	Addr                 string
	PublicBaseURL        string
	DatabaseURL          string
	GrokAPIURL           string
	GrokAPIKey           string
	GrokDefaultModel     string
	GrokMaxQueryBytes    int
	GrokMaxResponseBytes int64
	GrokDisabled         bool
	APIKeys              []string
	AllowedOrigins       []string
	AuthorizationServers []string
	ProtectMetrics       bool
	UpstreamTimeout      time.Duration
	MaxConcurrency       int
	RateLimitPerMin      int
	MaxBodyBytes         int64
	CacheTTL             time.Duration
	AuditRetention       time.Duration
	AuditRemoteAddr      bool
	CleanupInterval      time.Duration
	Logger               *slog.Logger
}

type RedactedConfig struct {
	Addr                     string   `json:"addr"`
	PublicBaseURL            string   `json:"public_base_url,omitempty"`
	DatabaseURL              string   `json:"database_url"`
	GrokEnabled              bool     `json:"grok_enabled"`
	GrokAPIURLConfigured     bool     `json:"grok_api_url_configured"`
	GrokAPIKeyConfigured     bool     `json:"grok_api_key_configured"`
	GrokDefaultModel         string   `json:"grok_default_model,omitempty"`
	GrokMaxQueryBytes        int      `json:"grok_max_query_bytes"`
	GrokMaxResponseBytes     int64    `json:"grok_max_response_bytes"`
	APIKeyCount              int      `json:"api_key_count"`
	ScopedAPIKeyCount        int      `json:"scoped_api_key_count"`
	AllowedOrigins           []string `json:"allowed_origins,omitempty"`
	AuthorizationServerCount int      `json:"authorization_server_count"`
	ProtectMetrics           bool     `json:"protect_metrics"`
	UpstreamTimeout          string   `json:"upstream_timeout"`
	MaxConcurrency           int      `json:"max_concurrency"`
	RateLimitPerMin          int      `json:"rate_limit_per_min"`
	MaxBodyBytes             int64    `json:"max_body_bytes"`
	CacheTTL                 string   `json:"cache_ttl"`
	AuditRetention           string   `json:"audit_retention"`
	AuditRemoteAddr          bool     `json:"audit_remote_addr"`
	CleanupInterval          string   `json:"cleanup_interval"`
	BrowserOriginProtection  bool     `json:"browser_origin_protection"`
}

func CheckConfig(c Config) error {
	c = c.normalized()
	return c.validate()
}

func RedactedEffectiveConfig(c Config) (RedactedConfig, error) {
	c = c.normalized()
	if err := c.validate(); err != nil {
		return RedactedConfig{}, err
	}
	return c.redacted(), nil
}

func (c Config) normalized() Config {
	if c.Addr == "" {
		c.Addr = "127.0.0.1:8787"
	}
	if c.DatabaseURL == "" {
		c.DatabaseURL = "mcp-gateway.db"
	}
	if c.UpstreamTimeout <= 0 {
		c.UpstreamTimeout = 60 * time.Second
	}
	if c.MaxConcurrency <= 0 {
		c.MaxConcurrency = 8
	}
	if c.RateLimitPerMin <= 0 {
		c.RateLimitPerMin = 60
	}
	if c.MaxBodyBytes <= 0 {
		c.MaxBodyBytes = 1 << 20
	}
	if c.GrokMaxQueryBytes <= 0 {
		c.GrokMaxQueryBytes = 32 << 10
	}
	if c.GrokMaxResponseBytes <= 0 {
		c.GrokMaxResponseBytes = 4 << 20
	}
	if c.AuditRetention < 0 {
		c.AuditRetention = 0
	}
	if c.CleanupInterval < 0 {
		c.CleanupInterval = 0
	}
	if len(c.AllowedOrigins) == 0 && c.PublicBaseURL != "" {
		if u, err := url.Parse(c.PublicBaseURL); err == nil && u.Scheme != "" && u.Host != "" {
			c.AllowedOrigins = []string{strings.ToLower(u.Scheme + "://" + u.Host)}
		}
	}
	return c
}

func (c Config) validate() error {
	if err := validateAPIKeys(c.APIKeys); err != nil {
		return err
	}
	if !c.GrokDisabled {
		if err := validateHTTPURL("grok API URL", c.GrokAPIURL); err != nil {
			return err
		}
	}
	if c.PublicBaseURL != "" {
		if err := validateHTTPURL("public base URL", c.PublicBaseURL); err != nil {
			return err
		}
		u, _ := url.Parse(c.PublicBaseURL)
		if u.Scheme == "https" && len(c.APIKeys) == 0 {
			return errors.New("api keys are required when public base URL is HTTPS")
		}
	}
	for _, origin := range c.AllowedOrigins {
		if err := validateOrigin(origin); err != nil {
			return err
		}
	}
	for _, server := range c.AuthorizationServers {
		if err := validateHTTPURL("authorization server", server); err != nil {
			return err
		}
	}
	return nil
}

func (c Config) redacted() RedactedConfig {
	scoped := 0
	for _, entry := range c.APIKeys {
		if strings.Contains(entry, "=") {
			scoped++
		}
	}
	return RedactedConfig{
		Addr:                     c.Addr,
		PublicBaseURL:            c.PublicBaseURL,
		DatabaseURL:              c.DatabaseURL,
		GrokEnabled:              !c.GrokDisabled,
		GrokAPIURLConfigured:     strings.TrimSpace(c.GrokAPIURL) != "",
		GrokAPIKeyConfigured:     strings.TrimSpace(c.GrokAPIKey) != "",
		GrokDefaultModel:         c.GrokDefaultModel,
		GrokMaxQueryBytes:        c.GrokMaxQueryBytes,
		GrokMaxResponseBytes:     c.GrokMaxResponseBytes,
		APIKeyCount:              len(c.APIKeys),
		ScopedAPIKeyCount:        scoped,
		AllowedOrigins:           append([]string(nil), c.AllowedOrigins...),
		AuthorizationServerCount: len(c.AuthorizationServers),
		ProtectMetrics:           c.ProtectMetrics,
		UpstreamTimeout:          c.UpstreamTimeout.String(),
		MaxConcurrency:           c.MaxConcurrency,
		RateLimitPerMin:          c.RateLimitPerMin,
		MaxBodyBytes:             c.MaxBodyBytes,
		CacheTTL:                 c.CacheTTL.String(),
		AuditRetention:           c.AuditRetention.String(),
		AuditRemoteAddr:          c.AuditRemoteAddr,
		CleanupInterval:          c.CleanupInterval.String(),
		BrowserOriginProtection:  true,
	}
}

func validateHTTPURL(label, rawURL string) error {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("invalid %s %q", label, rawURL)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("invalid %s scheme %q", label, u.Scheme)
	}
	return nil
}

func validateOrigin(origin string) error {
	origin = strings.TrimSpace(origin)
	if origin == "" || origin == "*" {
		return nil
	}
	u, err := url.Parse(origin)
	if err != nil || u.Scheme == "" || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("invalid allowed origin %q", origin)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("invalid allowed origin scheme %q", u.Scheme)
	}
	return nil
}

func validateAPIKeys(entries []string) error {
	seen := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		token := entry
		if before, after, ok := strings.Cut(entry, "="); ok {
			token = strings.TrimSpace(before)
			if token == "" {
				return errors.New("api key token cannot be empty")
			}
			if strings.TrimSpace(after) == "" {
				return fmt.Errorf("api key %q has empty scope list", token)
			}
			for _, part := range strings.FieldsFunc(after, func(r rune) bool {
				return r == '|' || r == ';' || r == ' '
			}) {
				scope := strings.TrimSpace(part)
				if scope == "" {
					return fmt.Errorf("api key %q has malformed scope list", token)
				}
				if err := validateAPIKeyScope(scope); err != nil {
					return fmt.Errorf("api key %q has invalid scope %q: %w", token, scope, err)
				}
			}
			if strings.HasSuffix(strings.TrimSpace(after), "|") || strings.HasSuffix(strings.TrimSpace(after), ";") {
				return fmt.Errorf("api key %q has malformed scope list", token)
			}
		}
		if strings.TrimSpace(token) == "" {
			return errors.New("api key token cannot be empty")
		}
		if strings.IndexFunc(token, unicode.IsSpace) >= 0 {
			return fmt.Errorf("api key token %q cannot contain whitespace", token)
		}
		if _, ok := seen[token]; ok {
			return fmt.Errorf("duplicate api key %q", token)
		}
		seen[token] = struct{}{}
	}
	return nil
}

func validateAPIKeyScope(scope string) error {
	if scope == "*" {
		return nil
	}
	if strings.IndexFunc(scope, unicode.IsSpace) >= 0 {
		return errors.New("scope cannot contain whitespace")
	}
	for _, prefix := range []string{"tool:", "provider:"} {
		if strings.HasPrefix(scope, prefix) {
			if strings.TrimSpace(strings.TrimPrefix(scope, prefix)) == "" {
				return errors.New("scope suffix cannot be empty")
			}
			return nil
		}
	}
	return errors.New("scope must be *, tool:<name>, or provider:<name>")
}
