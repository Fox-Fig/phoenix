# Installation and Setup

This guide provides a completely practical and step-by-step explanation of how to install the Phoenix server and client.

## 1. Download and Install Server (Server Side)

First, download the **Server** version on your VPS.
Please select the relevant tab based on your server's operating system and execute the commands.

::: code-group

```bash [Linux AMD64]
wget https://github.com/Fox-Fig/phoenix/releases/latest/download/phoenix-server-linux-amd64.zip
unzip phoenix-server-linux-amd64.zip
cp example_server.toml server.toml
chmod +x phoenix-server
```

```bash [Linux ARM64]
wget https://github.com/Fox-Fig/phoenix/releases/latest/download/phoenix-server-linux-arm64.zip
unzip phoenix-server-linux-arm64.zip
cp example_server.toml server.toml
chmod +x phoenix-server
```

```powershell [Windows AMD64 (PowerShell)]
Invoke-WebRequest -Uri "https://github.com/Fox-Fig/phoenix/releases/latest/download/phoenix-server-windows-amd64.zip" -OutFile "phoenix-server.zip"
Expand-Archive -Path "phoenix-server.zip" -DestinationPath "."
Copy-Item "example_server.toml" -Destination "server.toml"
```

:::

::: tip Important Note
The file `server.toml` is created and must be configured in the next step. Do not run the program yet.
:::

### Initial Server Configuration

::: tip Linux File Editor
To edit `server.toml` in the Linux terminal, you can use the `nano` command:
```bash
nano server.toml
```
To save changes, press `Ctrl+O` then `Enter`. To exit, press `Ctrl+X`.
:::

::: warning Important Attention
You **must** set all variables in the table below (except for optional encryption items).
:::

::: info Note
In TOML files, the `#` symbol at the beginning of a line means comments, and that line is not executed.
:::

| Variable | Type | Status | Description |
| :--- | :--- | :--- | :--- |
| `listen_addr` | String | **Mandatory** | The address and port the server listens on (e.g. `":443"`). |
| `[security]` | Section | **Mandatory** | Start of security settings and protocols section. |
| `enable_socks5` | Boolean | **Mandatory** | Are clients allowed to use SOCKS5 protocol? (`true` or `false`). |
| `enable_udp` | Boolean | **Mandatory** | UDP support. Most modern services (YouTube, Instagram) require it. Only set to `false` for specific usage like Telegram (TLS-only). |
| `enable_shadowsocks`| Boolean | **Mandatory** | Enable Shadowsocks protocol support. |
| `enable_ssh` | Boolean | **Mandatory** | Enable SSH tunnel support. |
| `private_key` | String | Optional | Path to server private key file (only for secure modes). |
| `authorized_clients`| Array | Optional | List of authorized client public keys (only for mTLS). |

---

## 2. Download and Install Client (Client Side)

Now download the **Client** version for your personal system (Windows, Linux, or Mac).

::: code-group

```powershell [Windows AMD64 (PowerShell)]
Invoke-WebRequest -Uri "https://github.com/Fox-Fig/phoenix/releases/latest/download/phoenix-client-windows-amd64.zip" -OutFile "phoenix-client.zip"
Expand-Archive -Path "phoenix-client.zip" -DestinationPath "."
Copy-Item "example_client.toml" -Destination "client.toml"
```

```bash [Linux AMD64]
wget https://github.com/Fox-Fig/phoenix/releases/latest/download/phoenix-client-linux-amd64.zip
unzip phoenix-client-linux-amd64.zip
cp example_client.toml client.toml
chmod +x phoenix-client
```

```bash [macOS Intel]
wget https://github.com/Fox-Fig/phoenix/releases/latest/download/phoenix-client-darwin-amd64.zip
unzip phoenix-client-darwin-amd64.zip
cp example_client.toml client.toml
chmod +x phoenix-client
```

```bash [macOS Silicon]
wget https://github.com/Fox-Fig/phoenix/releases/latest/download/phoenix-client-darwin-arm64.zip
unzip phoenix-client-darwin-arm64.zip
cp example_client.toml client.toml
chmod +x phoenix-client
```

:::

::: warning Attention
Do NOT run `client.toml`! You must configure it first.
:::

### Initial Client Configuration

::: tip Note
The `client.toml` file is created. You can open it with Notepad or any other text editor.
:::

#### 1. Global Settings

| Variable | Type | Status | Description |
| :--- | :--- | :--- | :--- |
| `remote_addr` | String | **Mandatory** | Phoenix server address (IP or Domain) and port. Example: `"203.0.113.10:443"`. |
| `server_public_key` | String | Optional | Server public key (for One-way TLS and mTLS). |
| `private_key` | String | Optional | Path to client private key file (only for mTLS). |

#### 2. Inbound Settings (`[[inbounds]]`)

This section specifies which ports the client listens on in your computer. You can have multiple inbounds.

::: tip Disabling Inbound
If you want to disable an inbound (e.g. Socks5 or SSH), simply place a `#` symbol at the beginning of all lines related to that `[[inbounds]]` block in the config file to comment them out.
:::

::: warning Important Note on Server Support
Note that a defined inbound works only if the server supports it. If the server does not support it, the inbound comes online but will not work upon connection!
:::

| Variable | Type | Status | Description |
| :--- | :--- | :--- | :--- |
| `protocol` | String | **Mandatory** | Inbound protocol type. Allowed values: `"socks5"`, `"shadowsocks"`, `"ssh"`. |
| `local_addr` | String | **Mandatory** | Address and port opened on your system. Example: `"127.0.0.1:1080"`. |
| `enable_udp` | Boolean | Optional | Enable UDP Associate (only for SOCKS5). For modern services (YouTube, Instagram) usually `true` is recommended. |
| `auth` | String | Optional | Authentication info (e.g. Shadowsocks password or SSH key path). |


---

## Executing the Application

::: danger Security Warning
If you have only filled in the mandatory fields in the settings files up to this stage, the program works and you can run it; **but it has NO security (Cleartext)!**

Therefore, if you intend to enable security modes (mTLS/One-Way TLS), **before execution**, refer to the **[Advanced Configuration](configuration.md)** page and perform the relevant settings, then run the program.
:::

To run the program on the server, enter the following command:
```bash
./phoenix-server -config server.toml
```

And on the client to run:
```bash
./phoenix-client -config client.toml
```

### Flags Guide

To learn about various program flags, you can read the table below:

| Flag | Program | Description |
| :--- | :--- | :--- |
| `-config` | Both | Specifies the configuration file path. (Default: `server.toml` or `client.toml`) |
| `-gen-keys` | Both | Generates a new pair of public and private keys (Ed25519) (for mTLS/One-Way TLS). |
| `-get-ss` | Client | If you have a Shadowsocks inbound, generates and prints the connection link (`ss://`). |

---

In the next page, you will learn **Configuration** for three different security modes.
