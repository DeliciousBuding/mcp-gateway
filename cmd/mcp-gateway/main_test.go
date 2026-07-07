package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DeliciousBuding/mcp-gateway/internal/buildinfo"
)

func TestCheckConfigValidatesWithoutOpeningDatabase(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "gateway.db")
	var stdout bytes.Buffer

	err := runWithArgs([]string{
		"-check-config",
		"-grok-api-url", "https://grok.example/v1/chat/completions",
		"-database", dbPath,
		"-public-base-url", "https://mcp.example/mcp",
		"-api-keys", "test-token",
	}, map[string]string{}, &stdout)

	if err != nil {
		t.Fatalf("check config failed: %v", err)
	}
	if !strings.Contains(stdout.String(), "configuration ok") {
		t.Fatalf("expected success output, got %q", stdout.String())
	}
	if _, err := filepath.Abs(dbPath); err != nil {
		t.Fatalf("invalid test db path: %v", err)
	}
	if _, err := os.Stat(dbPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("check-config created database file %s", dbPath)
	}
}

func TestCheckConfigReturnsValidationErrors(t *testing.T) {
	var stdout bytes.Buffer

	err := runWithArgs([]string{
		"-check-config",
		"-grok-api-url", "ftp://bad.example/chat",
	}, map[string]string{}, &stdout)

	if err == nil {
		t.Fatal("expected check-config to reject invalid config")
	}
	if !strings.Contains(err.Error(), "invalid grok API URL scheme") {
		t.Fatalf("unexpected error: %v", err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected no success output, got %q", stdout.String())
	}
}

func TestCheckConfigRejectsAPIKeyTokenWithWhitespace(t *testing.T) {
	var stdout bytes.Buffer

	err := runWithArgs([]string{
		"-check-config",
		"-grok-api-url", "https://grok.example/v1/chat/completions",
		"-api-keys", "bad token",
	}, map[string]string{}, &stdout)

	if err == nil {
		t.Fatal("expected check-config to reject whitespace in API key token")
	}
	if !strings.Contains(err.Error(), "cannot contain whitespace") {
		t.Fatalf("unexpected error: %v", err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected no success output, got %q", stdout.String())
	}
}

func TestCheckConfigRejectsInvalidAPIKeyScope(t *testing.T) {
	var stdout bytes.Buffer

	err := runWithArgs([]string{
		"-check-config",
		"-grok-api-url", "https://grok.example/v1/chat/completions",
		"-api-keys", "scoped-token=unknown",
	}, map[string]string{}, &stdout)

	if err == nil {
		t.Fatal("expected check-config to reject invalid API key scope")
	}
	if !strings.Contains(err.Error(), "invalid scope") {
		t.Fatalf("unexpected error: %v", err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected no success output, got %q", stdout.String())
	}
}

func TestCheckConfigRedactsAPIKeyTokenValidationErrors(t *testing.T) {
	var stdout bytes.Buffer

	err := runWithArgs([]string{
		"-check-config",
		"-grok-api-url", "https://grok.example/v1/chat/completions",
		"-api-keys", "super-secret-token=secret-scope",
	}, map[string]string{}, &stdout)

	if err == nil {
		t.Fatal("expected check-config to reject invalid API key scope")
	}
	if strings.Contains(err.Error(), "super-secret-token") || strings.Contains(err.Error(), "secret-scope") {
		t.Fatalf("validation error exposed secret material: %v", err)
	}
	if !strings.Contains(err.Error(), "api key entry 1") || !strings.Contains(err.Error(), "invalid scope 1") {
		t.Fatalf("unexpected error: %v", err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected no success output, got %q", stdout.String())
	}
}

func TestVersionFlagPrintsBuildMetadata(t *testing.T) {
	oldVersion, oldCommit, oldDate := buildinfo.Version, buildinfo.Commit, buildinfo.Date
	buildinfo.Version = "v1.2.3"
	buildinfo.Commit = "abc123"
	buildinfo.Date = "2026-07-07T00:00:00Z"
	t.Cleanup(func() {
		buildinfo.Version, buildinfo.Commit, buildinfo.Date = oldVersion, oldCommit, oldDate
	})
	var stdout bytes.Buffer

	err := runWithArgs([]string{"-version"}, nil, &stdout)

	if err != nil {
		t.Fatalf("version failed: %v", err)
	}
	want := "mcp-gateway v1.2.3 abc123 2026-07-07T00:00:00Z"
	if strings.TrimSpace(stdout.String()) != want {
		t.Fatalf("version output = %q, want %q", strings.TrimSpace(stdout.String()), want)
	}
}

func TestCheckConfigAcceptsMaxBodyBytesFromEnvironment(t *testing.T) {
	var stdout bytes.Buffer

	err := runWithArgs([]string{
		"-check-config",
		"-grok-api-url", "https://grok.example/v1/chat/completions",
		"-api-keys", "test-token",
		"-public-base-url", "https://mcp.example/mcp",
	}, map[string]string{
		"MCP_GATEWAY_MAX_BODY_BYTES": "4096",
	}, &stdout)

	if err != nil {
		t.Fatalf("check config failed: %v", err)
	}
	if !strings.Contains(stdout.String(), "configuration ok") {
		t.Fatalf("expected success output, got %q", stdout.String())
	}
}

func TestCheckConfigRejectsNegativeMaxBodyBytesFromEnvironment(t *testing.T) {
	var stdout bytes.Buffer

	err := runWithArgs([]string{
		"-check-config",
		"-grok-api-url", "https://grok.example/v1/chat/completions",
		"-api-keys", "test-token",
	}, map[string]string{
		"MCP_GATEWAY_MAX_BODY_BYTES": "-1",
	}, &stdout)

	if err == nil {
		t.Fatal("expected check-config to reject negative max body bytes")
	}
	if !strings.Contains(err.Error(), "max body bytes cannot be negative") {
		t.Fatalf("unexpected error: %v", err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected no success output, got %q", stdout.String())
	}
}

func TestCheckConfigAllowsGrokDisabledWithoutUpstreamURL(t *testing.T) {
	var stdout bytes.Buffer

	err := runWithArgs([]string{
		"-check-config",
		"-api-keys", "test-token",
		"-public-base-url", "https://mcp.example/mcp",
	}, map[string]string{
		"GROK_ENABLED": "false",
	}, &stdout)

	if err != nil {
		t.Fatalf("check config failed: %v", err)
	}
	if !strings.Contains(stdout.String(), "configuration ok") {
		t.Fatalf("expected success output, got %q", stdout.String())
	}
}

func TestPrintConfigRedactsSecretsAndDoesNotOpenDatabase(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "gateway.db")
	var stdout bytes.Buffer

	err := runWithArgs([]string{
		"-print-config",
		"-public-base-url", "https://mcp.example.com/mcp",
		"-database", dbPath,
		"-api-keys", "test-token,scoped-token=tool:grok_search|provider:grok",
		"-grok-api-url", "https://private-provider.example/v1/chat/completions",
		"-grok-api-key", "secret-upstream-key",
		"-allowed-origins", "https://agents.example.com",
	}, map[string]string{}, &stdout)

	if err != nil {
		t.Fatalf("print config failed: %v", err)
	}
	raw := stdout.String()
	for _, leaked := range []string{"test-token", "scoped-token", "secret-upstream-key", "private-provider.example"} {
		if strings.Contains(raw, leaked) {
			t.Fatalf("print-config leaked %q in %s", leaked, raw)
		}
	}
	var cfg map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &cfg); err != nil {
		t.Fatalf("print-config did not output JSON: %v\n%s", err, raw)
	}
	if cfg["api_key_count"] != float64(2) {
		t.Fatalf("api_key_count = %v, want 2 in %s", cfg["api_key_count"], raw)
	}
	if cfg["scoped_api_key_count"] != float64(1) {
		t.Fatalf("scoped_api_key_count = %v, want 1 in %s", cfg["scoped_api_key_count"], raw)
	}
	if cfg["grok_api_url_configured"] != true || cfg["grok_api_key_configured"] != true {
		t.Fatalf("grok configured flags missing in %s", raw)
	}
	if cfg["grok_max_query_bytes"] != float64(32768) {
		t.Fatalf("grok_max_query_bytes = %v, want 32768 in %s", cfg["grok_max_query_bytes"], raw)
	}
	if cfg["grok_max_response_bytes"] != float64(4194304) {
		t.Fatalf("grok_max_response_bytes = %v, want 4194304 in %s", cfg["grok_max_response_bytes"], raw)
	}
	if cfg["audit_remote_addr"] != false {
		t.Fatalf("audit_remote_addr = %v, want false in %s", cfg["audit_remote_addr"], raw)
	}
	if _, err := os.Stat(dbPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("print-config created database file %s", dbPath)
	}
}

func TestPrintConfigShowsAuditRemoteAddrOptIn(t *testing.T) {
	var stdout bytes.Buffer

	err := runWithArgs([]string{
		"-print-config",
		"-grok-enabled=false",
		"-api-keys", "test-token",
		"-public-base-url", "https://mcp.example.com/mcp",
	}, map[string]string{
		"MCP_GATEWAY_AUDIT_REMOTE_ADDR": "true",
	}, &stdout)

	if err != nil {
		t.Fatalf("print config failed: %v", err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &cfg); err != nil {
		t.Fatalf("print-config did not output JSON: %v\n%s", err, stdout.String())
	}
	if cfg["audit_remote_addr"] != true {
		t.Fatalf("audit_remote_addr = %v, want true in %s", cfg["audit_remote_addr"], stdout.String())
	}
}

func TestDockerfileDefaultsExposeReachableGateway(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("..", "..", "Dockerfile"))
	if err != nil {
		t.Fatalf("read Dockerfile: %v", err)
	}
	text := string(body)

	if !strings.Contains(text, "ENV MCP_GATEWAY_ADDR=0.0.0.0:8787") {
		t.Fatalf("Dockerfile must bind the container default listener to all interfaces")
	}
	if !strings.Contains(text, "EXPOSE 8787") {
		t.Fatalf("Dockerfile must expose the same port used by MCP_GATEWAY_ADDR")
	}
	if strings.Contains(text, "GROK_API_URL=") || strings.Contains(text, "GROK_API_KEY=") {
		t.Fatalf("Dockerfile must not bake provider URLs or keys into the public image")
	}
}
