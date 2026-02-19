# Configuration Guide

Phoenix uses **TOML** (Tom's Obvious, Minimal Language) for configuration.
Both `phoenix-server` and `phoenix-client` require a configuration file.

## 1. **Server Configuration** (`server.toml`)

This file configures the listening address, security settings, and authorized clients.

```toml
# ==============================
# Phoenix Server Configuration
# ==============================

# Listen Address:
# The IP and Port to bind the server to.
# ":443" binds to port 443 on ALL interfaces (0.0.0.0).
listen_addr = ":443"

# --- Security Settings ---
[security]

# Enable SOCKS5 Protocol Handling:
# Allow clients to initiate SOCKS5 connections.
enable_socks5 = true

# Enable UDP support:
# Allow UDP tunneling (e.g., for Voice Calls, Gaming).
enable_udp = true

# --- Encryption (TLS) Configuration ---

# Path to the Server's Private Key (PEM format).
# Generate this using `./phoenix-server -gen-keys`.
# If empty, the server starts in INSECURE (h2c) mode.
private_key = "server_private.key"

# List of Authorized Client Public Keys (Base64).
# If this list is populated, ONLY clients with matching keys can connect (mTLS).
# If this list is EMPTY or commented out, ANY client can connect (One-Way TLS).
authorized_clients = [
  "CLIENT_PUBLIC_KEY_1_BASE64_STRING...",
  "CLIENT_PUBLIC_KEY_2_BASE64_STRING..."
]
```

## 2. **Client Configuration** (`client.toml`)

This file configures the connection to the server and local listeners.

```toml
# ==============================
# Phoenix Client Configuration
# ==============================

# Remote Server Address:
# The public IP or Domain of your Phoenix Server.
# Example: "example.com:443" or "203.0.113.1:443"
remote_addr = "example.com:443"

# --- Secure Authentication (TLS) ---

# Server's Public Key (Base64).
# This is REQUIRED for TLS mode to verify the server's identity (Pinning).
# Prevents Man-in-the-Middle (MITM) attacks.
server_public_key = "SERVER_PUBLIC_KEY_BASE64..."

# Client's Private Key (Optional - Only for mTLS).
# If you are using mTLS (Mutual Authentication), provide the path to your private key.
# If commented out, the client connects anonymously (One-Way TLS).
# private_key = "client_private.key"

# --- Inbound Listeners ---

# SOCKS5 Proxy Listener
[[inbounds]]
protocol = "socks5"
local_addr = "127.0.0.1:1080"
enable_udp = true     # Enable UDP Associate
# auth = "user:password" # Optional basic auth for SOCKS5

# HTTP Proxy Listener (Future Feature)
# [[inbounds]]
# protocol = "http"
# local_addr = "127.0.0.1:8080"
```

## 3. **Environment Variables**

You can override some settings using environment variables, mostly for containerized deployments (Docker).
_(Currently, only command-line arguments `-c` or `--config` are supported directly. Environment variable support is planned for future releases.)_

## 4. **Key Generation**

To manage keys for secure communication:

**Generate Server Key:**
```bash
./phoenix-server -gen-keys
```
Save the output to `server_private.key` and update `server.toml`.
Copy the **Public Key** to your clients' `client.toml`.

**Generate Client Key (mTLS):**
```bash
./phoenix-client -gen-keys
```
Save the output to `client_private.key` and update `client.toml`.
Add the **Public Key** to the server's `authorized_clients` list.
