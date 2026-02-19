# Complete Configuration Reference

This guide covers all TOML configuration options for both Server and Client.

## Server Configuration (`server.toml`)

The server configuration file controls network binding and allowed protocols.

### Basic Settings

| Key | Type | Description | Default |
| :--- | :--- | :--- | :--- |
| `listen_addr` | string | The TCP address and port to bind to. Examples: `:8080`, `0.0.0.0:443`. | `:8080` |
| `log_level` | string | Logging verbosity: `debug`, `info`, `warn`, `error`. | `info` |

### Security Section `[security]`
This block controls authentication and tunneling permissions.

| Key | Type | Description | Default |
| :--- | :--- | :--- | :--- |
| `enable_socks5` | bool | Allow clients to tunnel SOCKS5 traffic. | `true` |
| `enable_shadowsocks` | bool | Allow clients to tunnel Shadowsocks traffic. | `false` |
| `enable_ssh` | bool | Allow clients to tunnel SSH traffic. | `false` |
| `cert_file` | string | Path to server's TLS certificate (PEM format). Required for TLS/mTLS. | `""` |
| `key_file` | string | Path to server's TLS private key. Required for TLS/mTLS. | `""` |
| `client_ca_file` | string | Path to CA certificate for verifying client certs (enables mTLS). | `""` |

---

## Client Configuration (`client.toml`)

The client configuration defines how to connect to the server and which local ports to open.

### Basic Settings

| Key | Type | Description | Default |
| :--- | :--- | :--- | :--- |
| `remote_addr` | string | The address of the Phoenix server. | Required |
| `log_level` | string | Logging verbosity. | `info` |
| `cert_file` | string | Path to client's TLS certificate (for mTLS). | `""` |
| `key_file` | string | Path to client's private key (for mTLS). | `""` |
| `ca_file` | string | Path to CA certificate to verify server identity (for self-signed certs). | `""` |

### Inbounds Section `[[inbounds]]`
This is an array of tables. You can define multiple listeners.

#### Example: SOCKS5 Proxy
```toml
[[inbounds]]
protocol = "socks5"
local_addr = "127.0.0.1:1080"
enable_udp = true
```

#### Example: Shadowsocks
```toml
[[inbounds]]
protocol = "shadowsocks"
local_addr = "127.0.0.1:8388"
auth = "chacha20-ietf-poly1305:password"
```

| Key | Type | Description |
| :--- | :--- | :--- |
| `protocol` | string | `socks5`, `shadowsocks`, `ssh`. |
| `local_addr` | string | IP:Port to bind locally (e.g., `127.0.0.1:1080`). |
| `enable_udp` | bool | Enable UDP Associate (SOCKS5 only). |
| `auth` | string | Authentication string (method:password for SS, key path for SSH). |
