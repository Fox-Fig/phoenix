# Security & Encryption Modes

Phoenix offers flexible security modes to adapt to different network environments and threat models. It supports operation without additional encryption, with one-way TLS (like HTTPS), and with Mutual TLS (mTLS) for client authentication.

## 1. No Encryption (Cleartext h2c)
In this mode, traffic is encapsulated in HTTP/2 frames but transmitted over plain TCP. This is useful when running behind a CDN that handles the SSL/TLS termination, or for local testing.

> **Note:** While "Cleartext", the traffic is still multiplexed and binary-encoded HTTP/2, making it difficult for simple DPI to inspect.

### Server Configuration
```toml
# No special security settings needed, just bind to a port.
listen_addr = ":8080"
```

### Client Configuration
```toml
remote_addr = "server-ip:8080"
```

---

## 2. One-Way TLS (Standard HTTPS)
This mode mimics standard web traffic. The server has a TLS certificate (like a website), and the client verifies the server's identity. This encrypts the tunnel and hides the traffic content.

### Prerequisites
- A valid TLS certificate (`server.crt`) and private key (`server.key`). You can generate self-signed ones or use Let's Encrypt.

### Server Configuration
```toml
listen_addr = ":8443"

[security]
# Path to your server's TLS certificate and private key
cert_file = "server.crt"
key_file = "server.key"
```

### Client Configuration
```toml
# Use the domain name if you have a valid cert, or IP.
# If using a self-signed cert, you might need to trust the CA on the client.
remote_addr = "example.com:8443"
```

---

## 3. Mutual TLS (mTLS - Advanced Security)
mTLS adds a layer of authentication where the **client must also present a valid certificate**. This prevents unauthorized users from even connecting to your server (active probing protection). The server will reject any handshake that doesn't provide a trusted client certificate.

### Prerequisites
- Server Certificate & Key (`server.crt`, `server.key`)
- Client Certificate & Key (`client.crt`, `client.key`)
- CA Certificate (to verify both)

### Step 1: Generate Keys
You can use the built-in helper (if available) or `openssl`:

```bash
# 1. Generate CA
openssl req -x509 -newkey rsa:4096 -nodes -keyout ca.key -out ca.crt -days 3650

# 2. Generate Server Cert
openssl req -new -keyout server.key -out server.csr -nodes
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -set_serial 01 -out server.crt

# 3. Generate Client Cert
openssl req -new -keyout client.key -out client.csr -nodes
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -set_serial 02 -out client.crt
```

### Server Configuration
```toml
listen_addr = ":8443"

[security]
cert_file = "server.crt"
key_file = "server.key"

# Enforce mTLS by specifying the CA that signed the client certs
client_ca_file = "ca.crt"
```

### Client Configuration
```toml
remote_addr = "example.com:8443"

# Client must provide its own certificate
cert_file = "client.crt"
key_file = "client.key"
# Trust the CA that signed the server's cert
ca_file = "ca.crt"
```
