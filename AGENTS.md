## Project Overview

interactsh-lite is a lightweight, dependency-minimal Go implementation of the [Interactsh](https://github.com/projectdiscovery/interactsh) protocol. It provides both a client library and server for out-of-band (OOB/OAST) interaction detection in security testing.

The repository is a multi-module Go project:

- **Root module** (`github.com/go-appsec/interactsh-lite`): OOB client library (`oobclient/`) and client CLI (`interactsh-lite`).
- **Server module** (`github.com/go-appsec/interactsh-lite/interactsh-srv`): OOB interaction capture server (`oobsrv/`) and server CLI (`interactsh-srv`).

## Build & Development Commands

```bash
# Build both binaries into bin/
make build

# Run tests (both modules)
make test            # Short tests
make test-all        # All tests with -race -cover; includes live integration tests for protocol validation

# Lint (both modules)
make lint            # Runs golangci-lint and go vet

# Benchmarks (both modules)
make bench
```

## Architecture

### Client - `oobclient/`

The client library is a single-package design with four source files:

- **client.go**: Core `Client` struct implementing the interactsh protocol:
  - RSA key pair generation (2048-bit) for registration
  - AES-256-CTR decryption of interaction data (RSA-OAEP for key exchange)
  - Server registration/deregistration via HTTP POST
  - Polling loop with keep-alive re-registration
  - Thread-safe state machine (idle → polling → closed)

- **options.go**: `Options` struct, `DefaultOptions` (oastsrv.net servers, 10s timeout, 60s keep-alive), `FallbackServerURLs`, `ResponseConfig` (stored HTTP response for a session - status, headers, body), `IsAllowedUnauthenticated()` (validates redirect-only policy for unauthenticated servers)

- **interaction.go**: `Interaction` struct for captured OOB data (DNS, HTTP, SMTP, LDAP, etc.)

- **errors.go**: Sentinel errors (`ErrSessionEvicted`, `ErrUnauthorized`, `ErrClientClosed`, `ErrAlreadyPolling`)

### Server - `interactsh-srv/oobsrv/`

The server package implements an interactsh-compatible OOB interaction capture server. It imports `oobclient.Interaction` as the canonical wire-format type for all protocol handlers.

Core infrastructure:

- **config.go**: `Config` struct with YAML tags, `DefaultConfig()`, `Validate()` - all server configuration fields
- **server.go**: `Server` struct, `New()`, `Handler()`, `Start()`, `Shutdown()`, HTTP mux setup, `Service` interface (`Name`, `Start`, `Close`) for protocol listener lifecycle, service implementations (`httpService`, `pprofService`)
- **storage.go**: `Storage` interface and implementations - `memoryStorage` (LRU eviction, sliding/fixed TTL) and `diskStorage` (LevelDB-backed with encrypted interactions). `Session` struct for per-client state (includes optional `ResponseConfig`). `SharedBucket` for append-only interaction buffers with per-consumer read offsets (wildcard/LDAP/FTP logging). `GetResponse()` returns stored response config for a correlation ID
- **middleware.go**: HTTP middleware functions - CORS, auth, logger (response recorder), response headers, max request size, remote address extraction

Protocol handlers:

- **dns.go**: DNS handler (miekg/dns) - A/AAAA/MX/NS/SOA/TXT/CNAME/ANY responses, ACME DNS-01 challenge store, custom DNS records (built-in SSRF records), wildcard subdomain support, IP resolution/classification
- **httphandler.go**: HTTP request handling - priority-based response routing (default file, static `/s/*` serving, banner, content-typed, stored/param responses, HTML fallback), URL reflection for correlation IDs, dynamic response parameters (`body`, `b64_body`, `header`, `status`, `delay`), session-stored `ResponseConfig` serving, scheme prepending for schemeless Location headers on 302/307 redirects, unauth validation (redirect-only on unauthenticated servers, delay-only bypasses validation)
- **smtp.go**: SMTP/SMTPS handler - ports 25/587/465, SASL auth (PLAIN, LOGIN, CRAM-MD5), per-recipient interaction capture with correlation ID matching
- **ldap.go**: LDAP handler (ldapserver) - bind/search/add/delete/modify/compare/abandon/StartTLS/WhoAmI operations, BaseDN correlation matching, full operation logging to shared bucket
- **ftp.go**: FTP/FTPS handler (goftp) - ports 21/990, read-only filesystem driver, operation logging (login, file ops, directory ops) to shared bucket

Crypto and protocol support:

- **encrypt.go**: RSA-OAEP key exchange (`ParsePublicKey`, `EncryptAESKey`), AES-256-CTR interaction encryption (`EncryptInteraction`, `GenerateAESKey`)
- **correlation.go**: `Match` struct, `MatchCorrelationID()` (two-tier sliding window on DNS labels), `MatchCorrelationIDEverywhere()` (delimiter-split chunks), `MatchLDAPCorrelationID()` (DN parts), `scanLabels()` for hostname matching
- **endpoints.go**: API handlers - `POST /register`, `GET /poll` (returns encrypted interactions, AES key, extra data, wildcard TLD data), `POST /deregister`
- **tls.go**: TLS certificate provisioning - priority-based: custom certs > ACME (Let's Encrypt DNS-01 via certmagic) > self-signed > none
- **ipdetect.go**: `ServerIPs` struct, `ClassifyIPs()`, `DetectIPs()` - auto-detect public IPv4/IPv6 via external HTTP and UDP fallback
- **metrics.go**: `GET /metrics` endpoint - protocol counters, session stats, cache hit/miss/eviction, memory/CPU/network stats

The server CLI (`interactsh-srv/main.go`, `config.go`) handles flag parsing (pflag), YAML config loading, health check diagnostics, signal handling, and logging setup.

### Key Design Patterns

- Context-aware API: `New()` and `LoadSession()` take `context.Context` for cancellation/timeout
- Correlation ID: configurable-length ID (default 20 characters) encoded in base32 of the xid alphabet, used as subdomain prefix for all payload URLs. The client uses xid-compatible encoding but the server does not enforce xid structure (no machine/process ID requirement)
- zbase32 encoding for payload URL nonces (human-readable, no ambiguous characters)
- Session persistence via YAML for maintaining correlation IDs across restarts

### Code Style

- Use `var` style for zero-value initialization: `var foo bool` not `foo := false`
- Comments should be concise simple and short phrases rather than full sentences when possible
- Comments should only be added when they describe non-obvious context (skip comments when the code or line is very obvious)
- Godocs should only describe the inputs and outputs, not how the function works
- Follow existing naming conventions and neighboring code style

### Testing

Structure and conventions:
- One `_test.go` file per implementation file that requires testing
- One `func Test<FunctionName>` per target function, using table-driven tests or `t.Run` cases
- Test case names should be at most 3 to 5 words and in lower case with underscores
- Use `t.Parallel()` at test function start when no shared state, but not in the test cases
- Isolated temp directories via `t.TempDir()` when needed
- Context timeouts via `t.Context()` for tests with I/O

Assertions and validation:
- Assertions rely on `testify` (`require` for setup, `assert` for assertions)
- Don't include messages unless the message provides context outside of the test point
- Do NOT use time.Sleep for tests, instead use require.Eventually or deterministic triggers

Verification:
- Always verify with `make test-all` and `make lint` before considering changes complete
