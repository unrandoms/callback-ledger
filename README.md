# callback-ledger

![callback-ledger](assets/project-mark.svg)

Collect HTTP and DNS callbacks under a named test session, then export the observations as JSON or NDJSON. This is a small, self-hosted evidence collector for development and authorized testing.

## Build and start

```sh
go build -o callback-ledger .
export CALLBACK_LEDGER_ADMIN_TOKEN="$(openssl rand -hex 32)"
./callback-ledger --ip 127.0.0.1 --domain canary.example.com --ttl 1h
```

The example advertises localhost, with HTTP on port 8080 and UDP DNS on port 5353. `--ip` must be an explicit IPv4 address appropriate for your deployment. DNS callbacks from external resolvers require a domain delegated to your server and UDP port 53 routing; the example domain does not establish that routing. The server listens on all interfaces. Use `--tls --cert cert.pem --key key.pem` or a TLS reverse proxy for remote administration.

## Name a session and collect evidence

```sh
curl -H "Authorization: Bearer $CALLBACK_LEDGER_ADMIN_TOKEN" \
  'http://127.0.0.1:8080/token?label=login-check'
```

The response includes `token`, `http_url` and `dns_host`. Send an HTTP request to the returned URL, or a DNS query to the returned hostname through your configured DNS infrastructure. Callbacks do not require the administrator secret.

Replace `TOKEN` below with the returned token:

```sh
curl -H "Authorization: Bearer $CALLBACK_LEDGER_ADMIN_TOKEN" \
  http://127.0.0.1:8080/export/TOKEN -o evidence.json
curl -H "Authorization: Bearer $CALLBACK_LEDGER_ADMIN_TOKEN" \
  'http://127.0.0.1:8080/export/TOKEN?format=ndjson' -o evidence.ndjson
```

JSON exports contain `schema_version: 1` and a session with its label, creation/expiry times, retained requests and dropped-event count. NDJSON starts with a `session` record containing the same metadata, followed by one `callback` record per retained request.

## API

All management routes require the bearer token, including WebSocket upgrades. The secret must be at least 32 characters at startup and is never accepted in a query parameter.

| Route | Purpose |
| --- | --- |
| `GET /token?label=...` | Create a session; label up to 128 bytes, without control characters |
| `GET /check/TOKEN` | Poll retained callbacks |
| `GET /export/TOKEN?format=json` | Export a session and its retention metadata |
| `GET /export/TOKEN?format=ndjson` | Export newline-delimited records |
| `GET /list` | List active sessions with retention metadata |
| `POST /clear` | Delete all sessions |
| `GET /ws` | Receive live retained-callback notifications |

## Retention and interpretation

Storage is in memory: restart, expiry or `/clear` removes observations. Export before then. At most 1,024 active sessions and the first 64 callbacks per session are retained; subsequent callbacks increment `dropped_events`. Expired sessions cannot be read or receive callbacks, even before cleanup.

HTTP bodies are limited to 16 KiB and include a `body_truncated` flag. Authorization, proxy authorization and cookie headers are redacted; management requests are excluded from capture. Other headers, URLs and bodies may still contain application data. Source addresses are observed transport peers, which may be proxies or DNS resolvers.

An observation establishes that a request reached this collector. It does not by itself prove a vulnerability or identify the originating application. Exports are ordinary JSON records, not signed or tamper-proof evidence. WebSocket notifications are live-only; exports are the retained record. DNS support is UDP with IPv4 answers, not a complete DNS service.

## Development and history

```sh
go test -race ./...
```

Tests cover authentication, labeled sessions, expiry, retention overflow, evidence isolation, export formats, body truncation, header redaction and DNS domain matching.

Maintained by [unrandoms](https://github.com/unrandoms) under the [MIT License](LICENSE). This project evolves the existing `ssrf-canary` repository; its history remains. The new name reflects session-based evidence collection rather than a claim to replace a commercial testing platform.
