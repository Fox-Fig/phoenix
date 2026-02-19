# Getting Started

This guide will walk you through setting up a Phoenix Server on a VPS and connecting to it using a Phoenix Client.

## Prerequisites

1.  **A VPS (Virtual Private Server):** You need a server with a public IP address. Ubuntu 22.04 or Debian 11/12 is recommended.
2.  **Basic Terminal Knowledge:** You should be comfortable issuing commands in a terminal/command prompt.

## 1. Server Setup (Linux VPS)

### Step 1: Download & Install
SSH into your VPS and run the following commands to download the latest release (replace `v1.0.0dev17` with the actual latest tag):

```bash
# create directory
mkdir -p /opt/phoenix
cd /opt/phoenix

# Download binary (Example for Linux AMD64)
wget https://github.com/Selin2005/phoenix/releases/latest/download/phoenix-server-linux-amd64.zip
unzip phoenix-server-linux-amd64.zip
chmod +x phoenix-server-linux-amd64
mv phoenix-server-linux-amd64 phoenix-server
```

### Step 2: Generate Keys
For maximum security, generate an Ed25519 key pair:

```bash
./phoenix-server -gen-keys
```
*   Save the `private.key` file (it's created in the current directory).
*   Copy the **Public Key** printed to the screen. You will need this for the Client.

### Step 3: Configure
Edit `server.toml` (included in the zip or create new):

```toml
listen_addr = ":443"

[security]
enable_socks5 = true
enable_udp = true
private_key = "private.key"

# Add your Client's Public Key here for mTLS (Recommended)
# If left empty, ANY client with the server key can connect (One-Way TLS).
authorized_clients = [
    "YOUR_CLIENT_PUBLIC_KEY_HERE"
]
```

### Step 4: Run as Service (Systemd)
To ensure Phoenix runs in the background and restarts on reboot:

```bash
# Create service file
sudo nano /etc/systemd/system/phoenix.service
```

Paste the following:
```ini
[Unit]
Description=Phoenix Tunnel Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/phoenix
ExecStart=/opt/phoenix/phoenix-server -c server.toml
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

Enable and Start:
```bash
sudo systemctl enable phoenix
sudo systemctl start phoenix
sudo systemctl status phoenix
```

## 2. Client Setup

### Windows
1.  Download `phoenix-client-windows-amd64.zip` from Releases.
2.  Extract the zip file.
3.  Open `example_client.toml` and rename it to `client.toml`.
4.  Edit `client.toml`:
    ```toml
    remote_addr = "YOUR_VPS_IP:443"
    server_public_key = "YOUR_SERVER_PUBLIC_KEY"
    
    [[inbounds]]
    protocol = "socks5"
    local_addr = "127.0.0.1:1080"
    enable_udp = true
    ```
5.  Open PowerShell or Command Prompt in the folder and run:
    ```powershell
    .\phoenix-client-windows-amd64.exe -c client.toml
    ```
6.  Configure your browser or Telegram to use SOCKS5 Proxy: `127.0.0.1:1080`.

### Linux / macOS
1.  Download and extract the binary.
2.  Make executable: `chmod +x phoenix-client*`.
3.  Generate Client Keys (for mTLS):
    ```bash
    ./phoenix-client -gen-keys
    ```
4.  Edit `client.toml` with `server_public_key` and your `private_key` (if using mTLS).
5.  Run:
    ```bash
    ./phoenix-client -c client.toml
    ```

### Android (Termux)
1.  Install **Termux** from F-Droid.
2.  Install wget: `pkg install wget`.
3.  Download the `linux-arm64` binary.
4.  Follow the Linux setup steps above.

## Troubleshooting

-   **Connection Refused:** Check your VPS Firewall (UFW/IPTables). Ensure port 443 is open.
    ```bash
    sudo ufw allow 443/tcp
    ```
-   **Handshake Failure:** Check that your System Time is correct on both Client and Server.
-   **"Reset Storm" Logs:** This means the network is unstable. Phoenix is automatically resetting the connection to recover. This is normal behavior in hostile networks.
