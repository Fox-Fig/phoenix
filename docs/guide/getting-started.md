# Getting Started with Phoenix

Welcome to the Phoenix documentation. This guide will help you install, configure, and run your own Phoenix server and client.

## Installation

### Prerequisites

- A remote server (VPS) with Linux.
- Go 1.21+ installed on your build machine (or download releases).

### Quick Install

**Download the latest release:**  
Go to the [Releases](https://github.com/Selin2005/phoenix/releases) page and download the binary for your operating system (Linux, Windows, macOS, Android).

**Make it executable (Linux/macOS):**
```bash
chmod +x phoenix-client-linux-amd64
chmod +x phoenix-server-linux-amd64
```

## Running the Server

1. **Copy the binary** to your VPS.
2. **Create a config file** `server.toml` (see `example_server.toml`).
3. **Run**:
   ```bash
   ./phoenix-server -c server.toml
   ```

## Running the Client

1. **Create a config file** `client.toml` (see `example_client.toml`).
2. **Run**:
   ```bash
   ./phoenix-client -c client.toml
   ```
3. **Connect** your browser or applications to the SOCKS5 proxy (default port 1080).

## Advanced Usage

For more advanced configurations, including CDN setup and mTLS, please refer to the dedicated sections.
