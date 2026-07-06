# mcp-gateway

Lightweight Go MCP gateway for remote agents.

The gateway exposes MCP Streamable HTTP at `/mcp`, keeps provider logic behind a tool registry, and stores operational audit data in SQLite by default. Grok web search is the first built-in provider; the gateway name and app layer are intentionally provider-neutral.

## Current tools

- `grok_search` - Grok-backed web research with returned sources.
- `grok_extract` - Grok-backed structured extraction.
- `grok_sources` - source-only Grok lookup.

## Run locally

```powershell
Copy-Item env.example .env
# edit .env, then:
Get-Content .env | ForEach-Object {
  if ($_ -match '^\s*([^#][^=]+)=(.*)$') { [Environment]::SetEnvironmentVariable($matches[1], $matches[2], 'Process') }
}
go run ./cmd/mcp-gateway --check-config
go run ./cmd/mcp-gateway
```

Health:

```bash
curl http://127.0.0.1:8787/health
curl http://127.0.0.1:8787/ready
curl -H "Authorization: Bearer $MCP_GATEWAY_API_KEY" http://127.0.0.1:8787/metrics
curl http://127.0.0.1:8787/.well-known/oauth-protected-resource
```

MCP tool list:

```bash
curl -sS http://127.0.0.1:8787/mcp \
  -H "Authorization: Bearer $MCP_GATEWAY_API_KEY" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

## Operations

- Keep the public route on a separate host name such as `mcp.example.com`; do not mix it into the model gateway `/v1/*` path.
- Use long per-agent bearer tokens in `MCP_GATEWAY_API_KEYS`. Bare tokens can use all tools; scoped tokens use `token=scope1|scope2`.
- Current tool scopes include `tool:grok_search`, `tool:grok_extract`, `tool:grok_sources`, provider-wide `provider:grok`, and wildcard `*`.
- API key configuration is strict: duplicate tokens, empty tokens, and empty or malformed scoped token lists fail startup.
- HTTPS `MCP_GATEWAY_PUBLIC_BASE_URL` requires at least one API key at startup; this prevents accidental anonymous public exposure.
- `GROK_API_URL`, `MCP_GATEWAY_PUBLIC_BASE_URL`, `MCP_GATEWAY_ALLOWED_ORIGINS`, and `MCP_GATEWAY_AUTHORIZATION_SERVERS` are validated at startup to catch malformed deployment config early.
- Run `mcp-gateway --check-config` in CI or before deployment. It validates effective configuration and exits without opening SQLite or listening on a port.
- Set `MCP_GATEWAY_ALLOWED_ORIGINS` for public deployments. This is the browser-facing DNS rebinding/CORS boundary; non-browser agents without an `Origin` header continue to work.
- Set `MCP_GATEWAY_AUTHORIZATION_SERVERS` when an OAuth issuer should be advertised to OAuth-aware MCP clients.
- Keep `MCP_GATEWAY_PROTECT_METRICS=true` on public hosts unless a private network or reverse proxy already protects `/metrics`.
- Unauthorized MCP responses include `WWW-Authenticate: Bearer resource_metadata="..."`, pointing clients at `/.well-known/oauth-protected-resource`.
- MCP Streamable HTTP `POST /mcp` requires `Content-Type: application/json` and an `Accept` header compatible with both `application/json` and `text/event-stream`.
- Requests with `MCP-Protocol-Version` must use `2025-06-18`; omitted versions are treated as the current supported version.
- SQLite runs with WAL, `synchronous=NORMAL`, and one writer connection for predictable low-memory operation.
- Short-lived SQLite response cache is enabled by default; tune `MCP_GATEWAY_CACHE_TTL` or set `use_cache=false` per tool call.
- Background SQLite cleanup is controlled by `MCP_GATEWAY_CLEANUP_INTERVAL`; `MCP_GATEWAY_AUDIT_RETENTION` limits audit growth while expired cache entries are always pruned.
- Limit upstream pressure with `MCP_GATEWAY_MAX_CONCURRENCY` and `MCP_GATEWAY_RATE_LIMIT_PER_MIN`.
- Limit MCP JSON request size with `MCP_GATEWAY_MAX_BODY_BYTES` (default `1048576`). Oversized requests return HTTP `413` before JSON-RPC dispatch.
- Put nginx/Cloudflare rate limits in front of the app for public exposure.
- Use `/health` for process liveness and `/ready` for SQLite-backed readiness.
- Scrape `/metrics` for lightweight Prometheus-compatible process metrics without adding a metrics SDK dependency. Labels are intentionally low-cardinality: route, method, status, RPC method/status, tool/status, and tool/cache result only.
- Send `X-Request-Id` from upstream proxies or clients when possible. The gateway echoes it back; otherwise it generates a 128-bit hex request id.
- Access logs are structured JSON and include request id, method, route, status, duration, and the hashed agent id when authenticated. They intentionally do not log bearer tokens, request bodies, tool arguments, or upstream prompts.
- SQLite audit rows in `tool_calls` include the same request id, so operators can join HTTP logs to tool execution records without storing prompts or tokens.
- HTTP panic recovery turns unexpected provider/tool panics into a stable `500` JSON response, records the request id, and avoids logging request bodies or bearer tokens.

## Provider configuration

The built-in Grok tools call an OpenAI-compatible chat completions endpoint configured entirely through environment variables. Public releases should keep provider URLs and keys out of source control.

```bash
GROK_API_URL=https://api.example.com/v1/chat/completions
GROK_API_KEY=replace-with-provider-key
GROK_DEFAULT_MODEL=grok-4.3-fast
```

Use your own reverse proxy or provider endpoint behind `GROK_API_URL`; the gateway does not hard-code any private upstream host.

## Design notes

- Single binary, no Redis required.
- Provider-neutral tool registry.
- Stateless Streamable HTTP mode by default: `POST /mcp` for JSON-RPC; streaming `GET /mcp` is deliberately disabled until session/SSE semantics are needed.
- Tool definitions expose MCP metadata (`title`, `annotations`, `outputSchema`) so clients can reason about safety and display.
- JSON structured logs through Go `slog`, including one access log event per HTTP request.
- Graceful shutdown and conservative HTTP timeouts.
- Outer HTTP panic recovery so one faulty tool call cannot crash the gateway process.
- Configurable MCP request body limit for memory protection on public deployments.
- SQLite audit table: `tool_calls`, indexed by timestamp, tool/status, and request id.
