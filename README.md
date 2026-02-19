<div align="center">
  <img src="logo.png" alt="Phoenix Logo" width="200" height="200">
  <h1>Phoenix</h1>
  <p>
    <img src="https://img.shields.io/badge/License-GPLv2-blue.svg" alt="License">
    <img src="https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go" alt="Go Version">
    <img src="https://img.shields.io/badge/PRs-Welcome-brightgreen.svg" alt="PRs Welcome">
  </p>
  <p>High-performance, DPI-resistant censorship circumvention via <strong>HTTP/2 Cleartext (h2c)</strong> multiplexing.</p>

  [🇮🇷 Read in Persian (فارسی) 🇮🇷](README-fa.md)
</div>

---

## 🚀 Introduction

**Phoenix** is a next-generation tunneling tool designed to bypass sophisticated Deep Packet Inspection (DPI) systems. It leverages the power of **HTTP/2 Cleartext (h2c)** to encapsualte traffic, making it incredibly difficult for firewalls to distinguish from legitimate web traffic.

Unlike traditional VPNs that use distinct protocols, Phoenix masquerades as standard HTTP/2 traffic. This allows it to:
- **Resist Reset Storms:** Maintains connections even under aggressive active probing.
- **CDN Compatible:** Can be proxied through Cloudflare, Gcore, or other CDNs that support HTTP/2.
- **Zero Overhead:** Designed with minimal latency and high throughput in mind.

## 🛠 Architecture

```mermaid
graph LR
    subgraph Client Side
        A[User Apps<br/>(Telegram/Browser)] -->|SOCKS5/HTTP| B[Phoenix Client]
    end
    
    B -->|h2c Multiplexed Tunnel| C{Internet / CDN / Firewall}
    C -->|h2c Multiplexed Tunnel| D[Phoenix Server]
    
    subgraph Server Side
        D -->|TCP/UDP| E[Target Destination<br/>(YouTube/Twitter/etc.)]
    end
    
    style B fill:#f9f,stroke:#333,stroke-width:2px
    style D fill:#f9f,stroke:#333,stroke-width:2px
```

## ✅ Pros & Cons

### Advantages
- **DPI Resistance:** Hides traffic inside standard HTTP/2 frames.
- **CDN Support:** Works behind Cloudflare and other CDNs to mask the server IP.
- **Low Latency:** Multiplexing allows multiple streams over a single TCP connection, reducing handshake overhead.
- **Cross-Platform:** Single binary for Linux, Windows, macOS, and Android (via termux).

### Limitations
- **Requires HTTP/2:** The intermediate network path must support HTTP/2 (most modern networks do).
- **Setup Required:** Requires a VPS or server to run the backend.

## ⚡ Getting Started

### Installation

1. **Download the latest release:**
   Go to the [Releases](https://github.com/Selin2005/phoenix/releases) page and download the binary for your operating system (Linux, Windows, macOS, Android).

2. **Make it executable (Linux/macOS):**
   ```bash
   chmod +x phoenix-client-linux-amd64
   chmod +x phoenix-server-linux-amd64
   ```

### Configuration

**Client Example (`example_client.toml`):**
```toml
# remote_addr: The address of the Phoenix server.
remote_addr = "127.0.0.1:8080"

[[inbounds]]
protocol = "socks5"
local_addr = "127.0.0.1:1080"
enable_udp = true
```

**Server Example (`example_server.toml`):**
```toml
# listen_addr: The address to bind to.
listen_addr = ":8080"

[security]
enable_socks5 = true
enable_udp = true
```

### Running

Start the server on your VPS:
```bash
./phoenix-server -c example_server.toml
```

Start the client on your local machine:
```bash
./phoenix-client -c example_client.toml
```

## ❤️ Support & Donate

If you find this project useful, please consider donating to support development.

| Currency | Address |
| :--- | :--- |
| **Ethereum (ETH)** | `0x0000000000000000000000000000000000000000` |
| **Bitcoin (BTC)** | `bc1q00000000000000000000000000000000000000` |
| **USDT (TRC20)** | `T000000000000000000000000000000000` |

---

<div align="center">
  Made with ❤️ at <a href="https://t.me/FoxFig">FoxFig</a><br>
  Dedicated to all people of Iran 🇮🇷
</div>

## 📄 License

This project is licensed under the [GPLv2 License](LICENSE).
