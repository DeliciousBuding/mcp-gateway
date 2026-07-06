package main

import (
	"bytes"
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
