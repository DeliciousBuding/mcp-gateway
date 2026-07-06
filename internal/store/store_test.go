package store_test

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/DeliciousBuding/mcp-gateway/internal/store"
)

func TestStoreCreatesAuditSchemaAndRecordsToolCalls(t *testing.T) {
	t.Parallel()

	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	err = st.RecordToolCall(context.Background(), store.ToolCall{
		AgentID:   "agent:test",
		ToolName:  "test_tool",
		Status:    "ok",
		LatencyMS: 12,
		SourceCnt: 3,
		RequestID: "req-store-test",
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestStorePersistsToolCallRequestID(t *testing.T) {
	t.Parallel()

	dbPath := filepath.Join(t.TempDir(), "audit-request-id.db")
	st, err := store.Open(context.Background(), dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	if err := st.RecordToolCall(context.Background(), store.ToolCall{
		AgentID:   "agent:test",
		ToolName:  "test_tool",
		Status:    "ok",
		RequestID: "req-audit-123",
	}); err != nil {
		t.Fatal(err)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var requestID string
	if err := db.QueryRowContext(context.Background(), `select request_id from tool_calls where tool_name='test_tool'`).Scan(&requestID); err != nil {
		t.Fatal(err)
	}
	if requestID != "req-audit-123" {
		t.Fatalf("request_id = %q, want req-audit-123", requestID)
	}
}

func TestStoreMigratesExistingAuditSchemaForRequestID(t *testing.T) {
	t.Parallel()

	dbPath := filepath.Join(t.TempDir(), "old-audit.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(context.Background(), `
create table tool_calls (
  id integer primary key autoincrement,
  ts text not null,
  agent_id text not null,
  tool_name text not null,
  status text not null,
  latency_ms integer not null,
  source_count integer not null default 0,
  error_text text not null default '',
  remote_addr text not null default ''
)`); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	_ = db.Close()

	st, err := store.Open(context.Background(), dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.RecordToolCall(context.Background(), store.ToolCall{
		AgentID:   "agent:test",
		ToolName:  "test_tool",
		Status:    "ok",
		RequestID: "req-migrated",
	}); err != nil {
		t.Fatal(err)
	}

	db, err = sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var requestID string
	if err := db.QueryRowContext(context.Background(), `select request_id from tool_calls where tool_name='test_tool'`).Scan(&requestID); err != nil {
		t.Fatal(err)
	}
	if requestID != "req-migrated" {
		t.Fatalf("request_id = %q, want req-migrated", requestID)
	}
}

func TestStoreCachesResponsesUntilExpiry(t *testing.T) {
	t.Parallel()

	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "cache.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	if err := st.SetCache(context.Background(), "key", store.CacheEntry{
		Value:     "cached",
		SourceCnt: 2,
		ExpiresAt: time.Now().Add(time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	entry, ok, err := st.GetCache(context.Background(), "key")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || entry.Value != "cached" || entry.SourceCnt != 2 {
		t.Fatalf("entry=%#v ok=%v", entry, ok)
	}
}

func TestStorePrunesExpiredCacheAndOldAuditRows(t *testing.T) {
	t.Parallel()

	dbPath := filepath.Join(t.TempDir(), "prune.db")
	st, err := store.Open(context.Background(), dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	now := time.Date(2026, 7, 6, 12, 0, 0, 0, time.UTC)
	if err := st.SetCache(context.Background(), "expired", store.CacheEntry{
		Value:     "old",
		SourceCnt: 1,
		ExpiresAt: now.Add(-time.Second),
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.SetCache(context.Background(), "live", store.CacheEntry{
		Value:     "new",
		SourceCnt: 2,
		ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.RecordToolCall(context.Background(), store.ToolCall{AgentID: "agent:old", ToolName: "old_tool", Status: "ok"}); err != nil {
		t.Fatal(err)
	}
	if err := st.RecordToolCall(context.Background(), store.ToolCall{AgentID: "agent:new", ToolName: "new_tool", Status: "ok"}); err != nil {
		t.Fatal(err)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.ExecContext(context.Background(), `update tool_calls set ts=? where agent_id='agent:old'`, now.Add(-48*time.Hour).Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(context.Background(), `update tool_calls set ts=? where agent_id='agent:new'`, now.Add(-time.Hour).Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}

	result, err := st.Prune(context.Background(), store.PruneOptions{
		Now:            now,
		AuditRetention: 24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.CacheRowsDeleted != 1 || result.AuditRowsDeleted != 1 {
		t.Fatalf("result=%#v, want one cache and one audit row deleted", result)
	}

	var expiredCount int
	if err := db.QueryRowContext(context.Background(), `select count(*) from response_cache where cache_key='expired'`).Scan(&expiredCount); err != nil {
		t.Fatal(err)
	}
	if expiredCount != 0 {
		t.Fatalf("expired cache rows = %d, want 0", expiredCount)
	}
	var oldAuditCount int
	if err := db.QueryRowContext(context.Background(), `select count(*) from tool_calls where agent_id='agent:old'`).Scan(&oldAuditCount); err != nil {
		t.Fatal(err)
	}
	if oldAuditCount != 0 {
		t.Fatalf("old audit rows = %d, want 0", oldAuditCount)
	}
}
