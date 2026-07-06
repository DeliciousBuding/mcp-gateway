package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/DeliciousBuding/mcp-gateway/internal/app"
	"github.com/DeliciousBuding/mcp-gateway/internal/buildinfo"
)

func main() {
	if err := run(); err != nil {
		slog.Error("mcp-gateway stopped", "error", err)
		os.Exit(1)
	}
}

func run() error {
	return runWithArgs(os.Args[1:], nil, os.Stdout)
}

func runWithArgs(args []string, environ map[string]string, stdout io.Writer) error {
	var cfg app.Config
	var apiKeys string
	var allowedOrigins string
	var authorizationServers string
	var logLevel string
	var checkConfig bool
	var printConfig bool
	var showVersion bool
	var grokEnabled bool
	getenv := envGetter(environ)
	flags := flag.NewFlagSet("mcp-gateway", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&cfg.Addr, "addr", getenv("MCP_GATEWAY_ADDR", "127.0.0.1:8787"), "HTTP listen address")
	flags.StringVar(&cfg.PublicBaseURL, "public-base-url", getenv("MCP_GATEWAY_PUBLIC_BASE_URL", ""), "public base URL")
	flags.StringVar(&cfg.DatabaseURL, "database", getenv("MCP_GATEWAY_DATABASE", "mcp-gateway.db"), "SQLite database path")
	flags.StringVar(&cfg.GrokAPIURL, "grok-api-url", getenv("GROK_API_URL", ""), "Grok OpenAI-compatible chat completions URL")
	flags.StringVar(&cfg.GrokAPIKey, "grok-api-key", getenv("GROK_API_KEY", ""), "Grok upstream API key")
	flags.StringVar(&cfg.GrokDefaultModel, "grok-default-model", getenv("GROK_DEFAULT_MODEL", "grok-4.3-fast"), "default Grok model")
	flags.BoolVar(&grokEnabled, "grok-enabled", boolEnv(getenv, "GROK_ENABLED", true), "register built-in Grok tools")
	flags.StringVar(&apiKeys, "api-keys", getenv("MCP_GATEWAY_API_KEYS", ""), "comma-separated bearer tokens")
	flags.StringVar(&allowedOrigins, "allowed-origins", getenv("MCP_GATEWAY_ALLOWED_ORIGINS", ""), "comma-separated allowed browser origins")
	flags.StringVar(&authorizationServers, "authorization-servers", getenv("MCP_GATEWAY_AUTHORIZATION_SERVERS", ""), "comma-separated OAuth authorization server issuer URLs")
	flags.BoolVar(&cfg.ProtectMetrics, "protect-metrics", boolEnv(getenv, "MCP_GATEWAY_PROTECT_METRICS", false), "require bearer auth for /metrics")
	flags.DurationVar(&cfg.UpstreamTimeout, "upstream-timeout", durationEnv(getenv, "MCP_GATEWAY_UPSTREAM_TIMEOUT", 60*time.Second), "upstream request timeout")
	flags.DurationVar(&cfg.CacheTTL, "cache-ttl", durationEnv(getenv, "MCP_GATEWAY_CACHE_TTL", 10*time.Minute), "SQLite response cache TTL; set 0 to disable")
	flags.DurationVar(&cfg.AuditRetention, "audit-retention", durationEnv(getenv, "MCP_GATEWAY_AUDIT_RETENTION", 30*24*time.Hour), "SQLite audit retention; set 0 to keep audit rows")
	flags.BoolVar(&cfg.AuditRemoteAddr, "audit-remote-addr", boolEnv(getenv, "MCP_GATEWAY_AUDIT_REMOTE_ADDR", false), "persist remote address in audit rows")
	flags.DurationVar(&cfg.CleanupInterval, "cleanup-interval", durationEnv(getenv, "MCP_GATEWAY_CLEANUP_INTERVAL", time.Hour), "SQLite cleanup interval; set 0 to disable background cleanup")
	flags.IntVar(&cfg.MaxConcurrency, "max-concurrency", intEnv(getenv, "MCP_GATEWAY_MAX_CONCURRENCY", 8), "max concurrent upstream tool calls")
	flags.IntVar(&cfg.RateLimitPerMin, "rate-limit-per-min", intEnv(getenv, "MCP_GATEWAY_RATE_LIMIT_PER_MIN", 60), "per-token request limit per minute")
	flags.Int64Var(&cfg.MaxBodyBytes, "max-body-bytes", int64Env(getenv, "MCP_GATEWAY_MAX_BODY_BYTES", 1<<20), "max MCP JSON request body bytes")
	flags.StringVar(&logLevel, "log-level", getenv("MCP_GATEWAY_LOG_LEVEL", "info"), "debug|info|warn|error")
	flags.BoolVar(&checkConfig, "check-config", false, "validate configuration and exit without opening the database or listening")
	flags.BoolVar(&printConfig, "print-config", false, "print validated effective configuration with secrets redacted and exit")
	flags.BoolVar(&showVersion, "version", false, "print version and exit")
	if err := flags.Parse(args); err != nil {
		return err
	}

	setupLogger(logLevel)
	if showVersion {
		_, _ = fmt.Fprintln(stdout, buildinfo.String())
		return nil
	}
	cfg.APIKeys = splitCSV(apiKeys)
	cfg.AllowedOrigins = splitCSV(allowedOrigins)
	cfg.AuthorizationServers = splitCSV(authorizationServers)
	cfg.GrokDisabled = !grokEnabled
	if checkConfig {
		if err := app.CheckConfig(cfg); err != nil {
			return err
		}
		_, _ = fmt.Fprintln(stdout, "configuration ok")
		return nil
	}
	if printConfig {
		effective, err := app.RedactedEffectiveConfig(cfg)
		if err != nil {
			return err
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(effective)
	}

	handler, err := app.NewServer(cfg)
	if err != nil {
		return err
	}
	defer handler.Close(context.Background())

	server := &http.Server{
		Addr:              cfg.Addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      cfg.UpstreamTimeout + 10*time.Second,
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}

	errCh := make(chan error, 1)
	go func() {
		slog.Info("mcp-gateway listening", "addr", cfg.Addr)
		errCh <- server.ListenAndServe()
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	select {
	case sig := <-stop:
		slog.Info("shutdown requested", "signal", sig.String())
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}
	return nil
}

func envGetter(environ map[string]string) func(string, string) string {
	return func(key, fallback string) string {
		if environ != nil {
			if v := strings.TrimSpace(environ[key]); v != "" {
				return v
			}
			return fallback
		}
		if v := strings.TrimSpace(os.Getenv(key)); v != "" {
			return v
		}
		return fallback
	}
}

func setupLogger(level string) {
	var slogLevel slog.Level
	switch strings.ToLower(level) {
	case "debug":
		slogLevel = slog.LevelDebug
	case "warn":
		slogLevel = slog.LevelWarn
	case "error":
		slogLevel = slog.LevelError
	default:
		slogLevel = slog.LevelInfo
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slogLevel})))
}

func splitCSV(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if v := strings.TrimSpace(part); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func intEnv(getenv func(string, string) string, key string, fallback int) int {
	var v int
	if _, err := fmt.Sscanf(getenv(key, ""), "%d", &v); err == nil && v > 0 {
		return v
	}
	return fallback
}

func int64Env(getenv func(string, string) string, key string, fallback int64) int64 {
	var v int64
	if _, err := fmt.Sscanf(getenv(key, ""), "%d", &v); err == nil && v > 0 {
		return v
	}
	return fallback
}

func durationEnv(getenv func(string, string) string, key string, fallback time.Duration) time.Duration {
	if v, err := time.ParseDuration(getenv(key, "")); err == nil && v >= 0 {
		return v
	}
	return fallback
}

func boolEnv(getenv func(string, string) string, key string, fallback bool) bool {
	raw := getenv(key, "")
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return fallback
	}
}
