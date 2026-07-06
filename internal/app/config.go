package app

import (
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"
)

type Config struct {
	Addr                 string
	PublicBaseURL        string
	DatabaseURL          string
	GrokAPIURL           string
	GrokAPIKey           string
	GrokDefaultModel     string
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
	CleanupInterval      time.Duration
	Logger               *slog.Logger
}

func CheckConfig(c Config) error {
	c = c.normalized()
	return c.validate()
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
				if strings.TrimSpace(part) == "" {
					return fmt.Errorf("api key %q has malformed scope list", token)
				}
			}
			if strings.HasSuffix(strings.TrimSpace(after), "|") || strings.HasSuffix(strings.TrimSpace(after), ";") {
				return fmt.Errorf("api key %q has malformed scope list", token)
			}
		}
		if strings.TrimSpace(token) == "" {
			return errors.New("api key token cannot be empty")
		}
		if _, ok := seen[token]; ok {
			return fmt.Errorf("duplicate api key %q", token)
		}
		seen[token] = struct{}{}
	}
	return nil
}
