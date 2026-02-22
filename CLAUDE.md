# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Phoenix is a high-performance, DPI-resistant censorship circumvention tool written in Go. It tunnels SOCKS5, Shadowsocks, and SSH traffic inside HTTP/2 (h2/h2c) connections to evade Deep Packet Inspection.

## Commands

```bash
make all        # fmt + test + build
make build      # produces bin/server, bin/client, bin/speedtest
make test       # go test ./...
make fmt        # go fmt ./...
make clean      # remove bin/

# Run a single test package
go test ./pkg/config/...

# Documentation site (Node/npm required)
npm run docs:dev      # local VitePress dev server
npm run docs:build    # build docs
```

Binary flags:
- `./bin/server -gen-keys` — generate Ed25519 server keypair
- `./bin/client -gen-keys` — generate Ed25519 client keypair
- `./bin/server -config example_server.toml`
- `./bin/client -config example_client.toml`

## Architecture

### Components

| Path | Role |
|------|------|
| `cmd/server/` | Server binary: listens for H2C connections, routes to protocol handlers |
| `cmd/client/` | Client binary: accepts local proxy connections, tunnels through server |
| `cmd/speedtest/` | Throughput benchmarking utility |
| `pkg/transport/` | Core HTTP/2 multiplexing layer (`server.go`, `client.go`) |
| `pkg/protocol/` | Protocol type constants (SOCKS5, SSH, Shadowsocks) |
| `pkg/config/` | TOML config loading/validation for server and client |
| `pkg/crypto/` | Ed25519 key generation and self-signed TLS certificate creation |
| `pkg/adapter/socks5/` | SOCKS5 handshake + UDP tunneling |
| `pkg/adapter/shadowsocks/` | Shadowsocks encryption/decryption |
| `pkg/adapter/ssh/` | SSH port-forwarding handler |
| `docs/` | VitePress documentation site (also in Persian under `docs/fa/`) |

### Data Flow

```
Local client app
  → pkg/adapter/{socks5,shadowsocks,ssh}   (protocol handshake)
  → cmd/client / PhoenixTunnelDialer       (bridge to transport)
  → pkg/transport/client.go                (HTTP/2 multiplexed stream)
  ~~~~ network ~~~~
  → pkg/transport/server.go                (demux stream, read protocol header)
  → pkg/adapter/...                        (forward to destination)
  → Internet destination
```

### Security Modes

Three TLS modes controlled by config:
1. **mTLS** — mutual Ed25519-based authentication (default secure mode)
2. **One-way TLS** — server cert pinning only
3. **h2c** — cleartext HTTP/2 (for CDN deployments with upstream TLS)

### Key Design Patterns

- Multiple inbounds on the client are each started as goroutines, coordinated with `sync.WaitGroup`.
- Connection failure tracking uses atomic counters (no mutex).
- `PhoenixTunnelDialer` implements the `socks5.Dialer` interface to bridge adapters with the transport layer.
- Configuration is TOML, parsed via `github.com/pelletier/go-toml`.

## Dependencies

Go modules: `golang.org/x/net` (HTTP/2), `github.com/pelletier/go-toml`.
No CGO — all binaries are built with `CGO_ENABLED=0`.

## CI/CD

- `.github/workflows/deploy.yml`: builds cross-platform binaries (Linux/macOS/Windows, amd64/arm64) on tag push and creates a GitHub Release.
- `.github/workflows/docs.yml`: deploys VitePress docs to GitHub Pages on pushes to `main` that touch `docs/`.

---

## Android Client (In Progress)

### Goal
Build a native Android client (`android/`) in Kotlin + Jetpack Compose that connects to an existing Phoenix server and proxies device traffic through it — without requiring root.

### Planned Architecture
- **Language:** Kotlin + Jetpack Compose
- **Go integration:** Compile Go client core as an ARM64 binary, bundle in `assets/`, extract and run as a child process managed by a Kotlin `Service`
- **Proxy model (MVP):** Local SOCKS5 listener on `127.0.0.1:10080` — no root needed
- **Proxy model (v2):** Android `VpnService` + tun2socks for system-wide transparent proxy
- **Background:** Android Foreground Service with persistent notification to survive Doze mode
- **Architecture pattern:** MVVM + Clean Architecture, Hilt DI, Coroutines + StateFlow

### Key Android-Specific Constraints Found During Analysis
- `h2c` (cleartext HTTP/2) mode requires explicit `network_security_config.xml` override on Android 9+
- UDP SOCKS5 buffers must be reduced (4 MB → 512 KB) to avoid memory pressure
- Signal handling (`SIGINT`/`SIGTERM`) from `cmd/client/main.go` cannot be used — replaced by Service lifecycle
- Key files must be written to `Context.getFilesDir()`, not the working directory
- Shadowsocks adapter is currently a stub — not available in Android client initially
- Local listener ports must be > 1024 (use 10080 for SOCKS5)

### Android Project Location
`android/` — Gradle project, standard Android Studio layout

### Android Skill
Senior Android guidance is available at `~/.claude/skills/android-senior/SKILL.md`
