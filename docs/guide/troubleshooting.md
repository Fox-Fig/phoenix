# Troubleshooting & Logs

::: info Goal of this Page
This page contains a complete list of all errors and messages you might see on the **Server** or **Client** side. If your application is not working, check the logs first and search for the message in the list below.
:::

## How to Read Logs
When you run the application (Linux, Windows, or Mac), messages are printed in the terminal.
- **INFO:** Normal messages indicating correct operation.
- **WARNING:** Warnings that do not stop the application but should be checked (e.g. low security).
- **FATAL / ERROR:** Critical errors causing shutdown or connection drop.

---

## 1. Client Side Errors

In this section, messages seen on your computer or phone terminal are examined.

### A. Startup Errors

| Log Message | Possible Cause | Solution |
| :--- | :--- | :--- |
| `Failed to load config: ...` | `client.toml` missing or formatted incorrectly. | Ensure config file is next to the app and command is correct (`-config`). |
| `Failed to generate keys: ...` | (`-gen-keys`) App has no write permission. | Run as Administrator/Root or test in another folder. |
| `Creating SECURE transport (TLS)` | **Not an Error.** Indicates Secure Mode (mTLS/TLS) is active. | - |
| `Creating INSECURE transport (h2c)` | **Not an Error.** Indicates Insecure Mode (Cleartext) is active. | If you intend security, check config to ensure keys are filled. |
| `WARNING: server_public_key NOT SET...` | You have `private_key` but `server_public_key` is empty. | To prevent MITM attacks, you must enter Server Public Key in `client.toml`. |
| `Failed to load private key: ...` | Private Key file (e.g. `client.private.key`) not found. | Check file path in `client.toml`. Does the file exist? |

### B. Connection & Network Errors (Runtime)

| Log Message | Possible Cause | Solution |
| :--- | :--- | :--- |
| `Failed to dial server: connection refused` | Server is down or wrong port entered. | Check if server is running (`./phoenix-server`). Check `remote_addr` port in client. |
| `Failed to dial server: i/o timeout` | Server firewall or Iran network blocked the port. | Change server port. Check server firewall (ufw). |
| `server key verification failed. Expected X, Got Y` | **Crucial:** Your server is fake or key in config is wrong. | Check `server_public_key` in `client.toml`. If key is correct, you are likely under MITM attack! |
| `Failed to listen on 127.0.0.1:1080...` | Port 1080 is occupied by another app (e.g. another VPN). | Change `local_addr` to another port (e.g. `1085`) in `client.toml`. |
| `SOCKS5 Handler Error: ...` | Browser or Telegram closed connection or errored. | If frequent, internet connection is unstable. |
| `Error: Shadowsocks inbound found but 'auth' is empty` | (`-get-ss`) Shadowsocks password empty in config. | Fill `auth` field with `method:password` format for Shadowsocks inbound. |

---

## 2. Server Side Errors

These messages are seen on your VPS terminal.

### A. General Errors

| Log Message | Possible Cause | Solution |
| :--- | :--- | :--- |
| `Failed to load config: ...` | `server.toml` not found or corrupt. | Check config file. |
| `Starting Phoenix Server on :443` | **Not an Error.** Server started successfully on port 443. | - |
| `Server failed: listen tcp :443: bind: access denied` | Server lacks permission for ports under 1024. | Run server with `sudo` or use port above 1024 (e.g. `8443`). |
| `Server failed: listen tcp :443: bind: address already in use` | Another app (Nginx/Apache) is using this port. | Stop that app or change Phoenix port. |

### B. Security Errors

| Log Message | Possible Cause | Solution |
| :--- | :--- | :--- |
| `Client authentication failed` | (mTLS Mode) Client has no valid private key. | Add Client Public Key to `authorized_clients` on server. |
| `Handshake error: remote error: bad certificate` | Client sent invalid certificate or keys mismatch. | Ensure Client/Server key pairs match (Ed25519). |
| `http2: server: error reading preface from client` | Client connecting with non-HTTP/2 protocol (e.g. browser/scanner). | Usually indicates Probing by filter/censor. Server correctly cut connection. |

---

## 3. Common Scenarios & Solutions

### Scenario 1: App connects but sites like YouTube don't open
- **Cause:** `enable_udp` likely off on Server, but Client trying to send UDP, or DNS issue.
- **Solution:** Check browser if HTTP sites open? If only Telegram opens (TCP), check `enable_udp`.

### Scenario 2: Zero speed or frequent disconnects
- **Cause:** Severe Packet Loss or Port Blocking.
- **Solution:** Change server port. Use mTLS mode to avoid detection.

### Scenario 3: Receiving `bad certificate` error
- **Cause:** Client/Server keys don't match.
- **Solution:** Re-generate keys with `-gen-keys` and copy-paste exactly as guided. Ensure Server Public Key is in Client and vice versa (mTLS).
