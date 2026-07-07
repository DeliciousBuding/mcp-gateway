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
go run ./cmd/mcp-gateway --print-config
go run ./cmd/mcp-gateway --version
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
- Authorization uses the standard `Bearer <token>` form; the auth scheme is case-insensitive, but malformed headers with missing or extra fields are rejected.
- Current tool scopes include `tool:grok_search`, `tool:grok_extract`, `tool:grok_sources`, provider-wide `provider:grok`, and wildcard `*`.
- API key configuration is strict: duplicate tokens, empty tokens, and empty or malformed scoped token lists fail startup.
- HTTPS `MCP_GATEWAY_PUBLIC_BASE_URL` requires at least one API key at startup; this prevents accidental anonymous public exposure.
- `GROK_API_URL`, `MCP_GATEWAY_PUBLIC_BASE_URL`, `MCP_GATEWAY_ALLOWED_ORIGINS`, and `MCP_GATEWAY_AUTHORIZATION_SERVERS` are validated at startup to catch malformed deployment config early. `GROK_API_URL` is required only when `GROK_ENABLED=true`.
- Run `mcp-gateway --check-config` in CI or before deployment. It validates effective configuration and exits without opening SQLite or listening on a port.
- Run `mcp-gateway --print-config` during deployment diagnostics. It validates effective configuration, prints redacted JSON, and exits without opening SQLite or listening on a port.
- Run `mcp-gateway --version` to print build metadata. Release builds can inject `Version`, `Commit`, and `Date` with Go ldflags or Docker build args.
- Set `MCP_GATEWAY_ALLOWED_ORIGINS` for browser-based clients. This is the DNS rebinding/CORS boundary: requests that carry an `Origin` header are rejected unless the origin is explicitly allowed or derived from `MCP_GATEWAY_PUBLIC_BASE_URL`; non-browser agents without an `Origin` header continue to work.
- Browser preflight responses allow `Authorization`, `Content-Type`, `Accept`, `MCP-Protocol-Version`, `X-Request-Id`, and `Mcp-Session-Id`.
- Set `MCP_GATEWAY_AUTHORIZATION_SERVERS` when an OAuth issuer should be advertised to OAuth-aware MCP clients.
- Keep `MCP_GATEWAY_PROTECT_METRICS=true` on public hosts unless a private network or reverse proxy already protects `/metrics`.
- Unauthorized MCP responses include `WWW-Authenticate: Bearer resource_metadata="..."`, pointing clients at the RFC 9728 protected-resource metadata URL. For path-based resources such as `/mcp`, the gateway also serves `/.well-known/oauth-protected-resource/mcp` while keeping the root well-known endpoint for compatibility.
- MCP Streamable HTTP `POST /mcp` requires `Content-Type: application/json` and an `Accept` header compatible with both `application/json` and `text/event-stream`.
- `Accept` entries with `q=0` are treated as not acceptable when checking MCP Streamable HTTP response media types.
- Requests with `MCP-Protocol-Version` must use `2025-06-18`; omitted versions are treated as the current supported version.
- `initialize.params` must include a non-empty string `protocolVersion`, object `capabilities`, and `clientInfo.name`/`clientInfo.version` strings; the gateway responds with its supported `2025-06-18` protocol version.
- MCP JSON-RPC `ping` is supported and returns an empty result for client/server liveness checks.
- MCP request ids are validated as string or integer values; omit `id` for notifications. `null`, boolean, object, array, and fractional ids are rejected as invalid requests.
- JSON-RPC notifications without an `id` return `202` with no response body; notification methods sent with an `id` are rejected as invalid requests.
- `tools/call.params` must be an object with a non-empty `name`; when present, `arguments` must be an object. Malformed tool-call params return JSON-RPC `-32602`.
- SQLite runs with WAL, `synchronous=NORMAL`, and one writer connection for predictable low-memory operation.
- Short-lived SQLite response cache is enabled by default; tune `MCP_GATEWAY_CACHE_TTL` or set `use_cache=false` per tool call. Cache keys are SHA-256 digests, so raw prompts and search briefs are not stored in cache key columns.
- Grok query text is capped by `GROK_MAX_QUERY_BYTES` (default `32768`) before upstream calls or cache writes.
- Grok upstream response bodies are capped by `GROK_MAX_RESPONSE_BYTES` (default `4194304`) before JSON parsing or caching.
- Grok tool calls validate `max_tokens` at runtime and reject values outside `1..8192` before contacting the upstream provider.
- Background SQLite cleanup is controlled by `MCP_GATEWAY_CLEANUP_INTERVAL`; `MCP_GATEWAY_AUDIT_RETENTION` limits audit growth while expired cache entries are always pruned.
- Audit rows do not persist client remote addresses by default; set `MCP_GATEWAY_AUDIT_REMOTE_ADDR=true` only when that metadata is operationally required.
- Limit upstream pressure with `MCP_GATEWAY_MAX_CONCURRENCY` and `MCP_GATEWAY_RATE_LIMIT_PER_MIN`; built-in 429 responses include `Retry-After` for client backoff.
- Limit MCP JSON request size with `MCP_GATEWAY_MAX_BODY_BYTES` (default `1048576`). Oversized requests return HTTP `413` before JSON-RPC dispatch.
- Put nginx/Cloudflare rate limits in front of the app for public exposure.
- Use `GET /health` for process liveness and `GET /ready` for SQLite-backed readiness.
- Scrape `/metrics` with `GET` for lightweight Prometheus-compatible process metrics without adding a metrics SDK dependency. Labels are intentionally low-cardinality: route, method, status, RPC method/status, tool/status, and tool/cache result only.
- Latency histograms are exported as classic Prometheus metrics: `mcp_gateway_http_request_duration_seconds` by route/method/status and `mcp_gateway_tool_call_duration_seconds` by tool/status.
- `mcp_gateway_build_info` includes version, commit, and build date labels for runtime identification.
- Dynamic gateway responses include `Cache-Control: no-store` to avoid stale MCP, auth, health, or metrics data behind proxies.
- Unknown routes return a small JSON `404` with the same security and no-store headers as other gateway responses.
- Send `X-Request-Id` from upstream proxies or clients when possible. The gateway echoes it back; otherwise it generates a 128-bit hex request id.
- Access logs are structured JSON and include request id, method, route, status, duration, and the hashed agent id when authenticated. They intentionally do not log bearer tokens, request bodies, tool arguments, or upstream prompts.
- SQLite audit rows in `tool_calls` include the same request id, so operators can join HTTP logs to tool execution records without storing prompts, tokens, or client addresses by default. Tool-call audit writes use a short background timeout so canceled client requests can still record final status when possible.
- Provider failures are sanitized before returning to clients or audit rows: non-2xx responses are reported by status and body size only, and transport errors do not include upstream URLs or paths.
- Tool panics are recovered into stable MCP tool errors without exposing panic details; outer HTTP panic recovery remains as a final `500` safeguard with the request id and no request body or bearer token logging.

## Provider configuration

The built-in Grok tools call an OpenAI-compatible chat completions endpoint configured entirely through environment variables. Public releases should keep provider URLs and keys out of source control.

```bash
GROK_ENABLED=true
GROK_API_URL=https://api.example.com/v1/chat/completions
GROK_API_KEY=replace-with-provider-key
GROK_DEFAULT_MODEL=grok-4.3-fast
GROK_MAX_QUERY_BYTES=32768
GROK_MAX_RESPONSE_BYTES=4194304
```

Use your own reverse proxy or provider endpoint behind `GROK_API_URL`; the gateway does not hard-code any private upstream host.

Set `GROK_ENABLED=false` to run the gateway without registering Grok tools. This mode does not require `GROK_API_URL` or `GROK_API_KEY`, which keeps the public gateway binary usable as a provider-neutral base.

## Design notes

- Single binary, no Redis required.
- Provider-neutral tool registry.
- Stateless Streamable HTTP mode by default: `POST /mcp` for JSON-RPC; streaming `GET /mcp` is deliberately disabled until session/SSE semantics are needed, and `DELETE /mcp` returns a clear 405 because the gateway does not issue server-side sessions.
- Tool definitions expose MCP metadata (`title`, `annotations`, `outputSchema`) so clients can reason about safety and display.
- JSON structured logs through Go `slog`, including one access log event per HTTP request.
- Graceful shutdown and conservative HTTP timeouts.
- Tool-level panic recovery plus outer HTTP panic recovery so one faulty tool call cannot crash the gateway process.
- Configurable MCP request body limit for memory protection on public deployments.
- SQLite audit table: `tool_calls`, indexed by timestamp, tool/status, and request id.

## Build metadata

The binary defaults to `dev none unknown`. Inject release metadata with ldflags:

```bash
go build -trimpath \
  -ldflags "-X github.com/DeliciousBuding/mcp-gateway/internal/buildinfo.Version=v0.1.0 -X github.com/DeliciousBuding/mcp-gateway/internal/buildinfo.Commit=$(git rev-parse --short HEAD) -X github.com/DeliciousBuding/mcp-gateway/internal/buildinfo.Date=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  -o bin/mcp-gateway ./cmd/mcp-gateway
```

Docker builds accept the same values as build args:

```bash
docker build \
  --build-arg VERSION=v0.1.0 \
  --build-arg COMMIT=$(git rev-parse --short HEAD) \
  --build-arg DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
  -t mcp-gateway:v0.1.0 .
```

Run the container with a writable data volume for SQLite:

```bash
docker run --rm -p 8787:8787 \
  -e MCP_GATEWAY_API_KEYS=replace-with-long-random-token \
  -e GROK_ENABLED=false \
  -v mcp-gateway-data:/data \
  mcp-gateway:v0.1.0 \
  -database /data/mcp-gateway.db
```

## Releases

Pushing a `v*` tag runs the release workflow. It gates on public hygiene, tests, and `go vet`, then publishes cross-platform archives with `checksums.txt` and a multi-arch GHCR image tagged with the release tag.
