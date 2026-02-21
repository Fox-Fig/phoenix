# Manage with Systemd (Linux)

To ensure the Phoenix server is always running and starts automatically after a reboot, the best way is to use **Systemd** on Linux.

## Setup Steps

### 1. Create Service File
First, create a new service file for Phoenix using a text editor (like nano):

```bash
sudo nano /etc/systemd/system/phoenix.service
```

### 2. Add Configuration
Copy and paste the following content into the file. Make sure the `WorkingDirectory` and `ExecStart` match your installation path:

```ini
[Unit]
Description=Phoenix Tunnel Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/root/phoenix
ExecStart=/root/phoenix/phoenix-server -config server.toml
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

> [!TIP]
> If you installed Phoenix in a different directory, be sure to update `/root/phoenix` to the correct path.

### 3. Reload and Enable
After saving the file (in nano, press `Ctrl+O` then `Enter`, and exit with `Ctrl+X`), execute the following commands in order:

```bash
# Reload systemd manager configuration
sudo systemctl daemon-reload

# Enable the service to start at boot
sudo systemctl enable phoenix.service

# Start the service
sudo systemctl start phoenix.service

# Check service status
sudo systemctl status phoenix.service
```

## Managing the Service
You can manage the service using the following commands:

- **Stop service:** `sudo systemctl stop phoenix.service`
- **Restart service:** `sudo systemctl restart phoenix.service`
- **View logs:** `sudo journalctl -u phoenix.service -f`
