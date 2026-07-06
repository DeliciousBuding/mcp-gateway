FROM golang:1.26-alpine AS build

ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X github.com/DeliciousBuding/mcp-gateway/internal/buildinfo.Version=${VERSION} -X github.com/DeliciousBuding/mcp-gateway/internal/buildinfo.Commit=${COMMIT} -X github.com/DeliciousBuding/mcp-gateway/internal/buildinfo.Date=${DATE}" -o /out/mcp-gateway ./cmd/mcp-gateway

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=build /out/mcp-gateway /app/mcp-gateway
ENV MCP_GATEWAY_ADDR=0.0.0.0:8787
VOLUME ["/data"]
EXPOSE 8787
ENTRYPOINT ["/app/mcp-gateway"]
