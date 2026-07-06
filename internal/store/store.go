package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct {
	db *sql.DB
}

type ToolCall struct {
	AgentID    string
	RequestID  string
	ToolName   string
	Status     string
	LatencyMS  int64
	SourceCnt  int
	ErrorText  string
	RemoteAddr string
}

type CacheEntry struct {
	Value     string
	SourceCnt int
	ExpiresAt time.Time
}

type PruneOptions struct {
	Now            time.Time
	AuditRetention time.Duration
}

type PruneResult struct {
	CacheRowsDeleted int64
	AuditRowsDeleted int64
}

func Open(ctx context.Context, databaseURL string) (*Store, error) {
	db, err := sql.Open("sqlite", databaseURL)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.ExecContext(ctx, `pragma journal_mode=WAL; pragma synchronous=NORMAL; pragma busy_timeout=5000;`); err != nil {
		_ = db.Close()
		return nil, err
	}
	if _, err := db.ExecContext(ctx, schema); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := ensureColumn(ctx, db, "tool_calls", "request_id", "text not null default ''"); err != nil {
		_ = db.Close()
		return nil, err
	}
	if _, err := db.ExecContext(ctx, `create index if not exists idx_tool_calls_request_id on tool_calls(request_id);`); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *Store) Ping(ctx context.Context) error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.PingContext(ctx)
}

func (s *Store) RecordToolCall(ctx context.Context, call ToolCall) error {
	if s == nil || s.db == nil {
		return nil
	}
	_, err := s.db.ExecContext(ctx, `
insert into tool_calls (ts, agent_id, request_id, tool_name, status, latency_ms, source_count, error_text, remote_addr)
values (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		time.Now().UTC().Format(time.RFC3339Nano),
		call.AgentID,
		call.RequestID,
		call.ToolName,
		call.Status,
		call.LatencyMS,
		call.SourceCnt,
		call.ErrorText,
		call.RemoteAddr,
	)
	return err
}

func ensureColumn(ctx context.Context, db *sql.DB, table, column, definition string) error {
	rows, err := db.QueryContext(ctx, `pragma table_info(`+table+`)`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name string
		var typ string
		var notNull int
		var defaultValue any
		var pk int
		if err := rows.Scan(&cid, &name, &typ, &notNull, &defaultValue, &pk); err != nil {
			return err
		}
		if name == column {
			return rows.Err()
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `alter table `+table+` add column `+column+` `+definition)
	return err
}

func (s *Store) GetCache(ctx context.Context, key string) (CacheEntry, bool, error) {
	if s == nil || s.db == nil {
		return CacheEntry{}, false, nil
	}
	var entry CacheEntry
	var expiresAt string
	err := s.db.QueryRowContext(ctx, `select value, source_count, expires_at from response_cache where cache_key=?`, key).
		Scan(&entry.Value, &entry.SourceCnt, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return CacheEntry{}, false, nil
	}
	if err != nil {
		return CacheEntry{}, false, err
	}
	ts, err := time.Parse(time.RFC3339Nano, expiresAt)
	if err != nil {
		return CacheEntry{}, false, err
	}
	entry.ExpiresAt = ts
	if time.Now().UTC().After(entry.ExpiresAt) {
		_, _ = s.db.ExecContext(ctx, `delete from response_cache where cache_key=?`, key)
		return CacheEntry{}, false, nil
	}
	return entry, true, nil
}

func (s *Store) SetCache(ctx context.Context, key string, entry CacheEntry) error {
	if s == nil || s.db == nil {
		return nil
	}
	_, err := s.db.ExecContext(ctx, `
insert into response_cache (cache_key, value, source_count, expires_at)
values (?, ?, ?, ?)
on conflict(cache_key) do update set value=excluded.value, source_count=excluded.source_count, expires_at=excluded.expires_at`,
		key,
		entry.Value,
		entry.SourceCnt,
		entry.ExpiresAt.UTC().Format(time.RFC3339Nano),
	)
	return err
}

func (s *Store) Prune(ctx context.Context, opts PruneOptions) (PruneResult, error) {
	if s == nil || s.db == nil {
		return PruneResult{}, nil
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	var result PruneResult
	cacheRes, err := s.db.ExecContext(ctx, `delete from response_cache where expires_at <= ?`, now.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return PruneResult{}, err
	}
	result.CacheRowsDeleted, _ = cacheRes.RowsAffected()
	if opts.AuditRetention > 0 {
		cutoff := now.Add(-opts.AuditRetention).UTC().Format(time.RFC3339Nano)
		auditRes, err := s.db.ExecContext(ctx, `delete from tool_calls where ts < ?`, cutoff)
		if err != nil {
			return PruneResult{}, err
		}
		result.AuditRowsDeleted, _ = auditRes.RowsAffected()
	}
	return result, nil
}

const schema = `
create table if not exists tool_calls (
  id integer primary key autoincrement,
  ts text not null,
  agent_id text not null,
  request_id text not null default '',
  tool_name text not null,
  status text not null,
  latency_ms integer not null,
  source_count integer not null default 0,
  error_text text not null default '',
  remote_addr text not null default ''
);
create index if not exists idx_tool_calls_ts on tool_calls(ts);
create index if not exists idx_tool_calls_tool_status on tool_calls(tool_name, status);
create table if not exists response_cache (
  cache_key text primary key,
  value text not null,
  source_count integer not null default 0,
  expires_at text not null
);
create index if not exists idx_response_cache_expires on response_cache(expires_at);
`
