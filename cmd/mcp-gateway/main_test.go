package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
