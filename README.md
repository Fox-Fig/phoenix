<div align="center">
  <img src="logo.png" alt="Phoenix Logo" width="200" height="200">
  <h1>Phoenix</h1>
  <p>
    <img src="https://img.shields.io/badge/License-GPLv2-blue.svg" alt="License">
    <img src="https://img.shields.io/badge/Go-1.24+-00ADD8?logo=go" alt="Go Version">
    <img src="https://github.com/Fox-Fig/phoenix/actions/workflows/deploy.yml/badge.svg" alt="Build Status">
    <a href="https://Fox-Fig.github.io/phoenix/"><img src="https://img.shields.io/github/v/release/Fox-Fig/phoenix?include_prereleases" alt="Latest Release"></a>
  </p>
  <p><strong>Phoenix</strong> is a high-performance, resilient tunneling tool designed to bypass DPI and severe network censorship using <strong>HTTP/2 (h2/h2c)</strong> multiplexing.</p>

  [🇮🇷 Read in Persian (فارسی) 🇮🇷](README-fa.md) | [📚 **Full Documentation**](https://Fox-Fig.github.io/phoenix/)
</div>

---

## 🚀 Introduction

Phoenix establishes a persistent, multiplexed HTTP/2 tunnel between a client and server. It offers advanced features like **mTLS authentication**, **One-Way TLS** (HTTPS-like), and automatic **Zombie Connection Recovery** to maintain connectivity in hostile network environments.

For detailed architecture, configuration, and security analysis, please visit our **[Official Documentation](https://Fox-Fig.github.io/phoenix/)**.

## ⚡ Quick Start

1.  **Download:** Get the latest binary for your OS from the [Releases Page](https://github.com/Fox-Fig/phoenix/releases).
2.  **Server:** Run on your VPS with a config file.
    ```bash
    ./phoenix-server -config server.toml
    ```
3.  **Client:** Run on your local machine.
    ```bash
    ./phoenix-client -config client.toml
    ```

> **Note:** Comprehensive setup guides for Linux, Windows, macOS, and Android are available in the [Getting Started Guide](https://Fox-Fig.github.io/phoenix/guide/getting-started).

## ❤️ Support & Donate

If you find this project useful, please consider donating to support development and server costs.

| Currency | Address |
| :--- | :--- |
| **Ethereum (ETH)** | `0xb59993FeCace98BF6b89a216f5ca1776028A7047` |
| **Bitcoin (BTC)** | `bc1qx28s2sz3nvhelclpgan24ymflssql8uzcmexn3` |
| **Ripple (XRP)** | `rHoTVZWrPhYWf4uHkHZFicrJsADp57Yq4g` |
| **USDT / TRX (TRC20)** | `TXKnT3drzW4kb7imKrr1DVfwZWkrQWWpJo` |
| **Toncoin (TON)** | `UQBfP7DC-SJZT7aITPIGacrm09H6b_thlSOzc_5zesnBYMBI` |

## 📄 License
This project is licensed under the [GPLv2 License](LICENSE).

---

<div align="center">
  Made with ❤️ by <a href="https://t.me/FoxFig">FoxFig Team</a><br>
  Dedicated to all people of Iran 🇮🇷
</div>
