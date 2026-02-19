# Security Model & Threat Analysis

Phoenix is designed to provide secure, resilient communication through restricted networks.

## 1. Threat Model

Phoenix assumes the following environment:
- **Client:** The user's device is trusted.
- **Server:** The Phoenix server is managed by the user or a trusted party.
- **Network (Path):** The intermediate network (Internet, ISP, DPI Appliance) is untrusted and actively hostile.
  - **DPI:** Can analyze traffic patterns, payload size, and timing.
  - **Active Probing:** Can connect to the server/client and try to enumerate services (`Reset Storm`).
  - **MITM:** Can attempt to intercept and decrypt TLS traffic (using forced CA installation or forged certs).

## 2. Security Modes

### A. mTLS (Mutual TLS) - **Maximum Security**
- **Authentication:** Both Client and Server authenticate each other using **Ed25519** key pairs.
- **Encryption:** All traffic is encrypted using standard TLS 1.3 suites (X25519, ChaCha20-Poly1305).
- **Pinning:** The client pins the server's public key (not relying on CA system).
- **Probing Resistance:** The server drops any connection that does not present a valid client certificate with an authorized public key.
- **Use Case:** Private VPN, strict access control.

### B. One-Way TLS (Server-Side Encryption) - **Standard Security**
- **Authentication:** Only Server authenticates (via pinned key).
- **Encryption:** Same strong TLS 1.3 encryption.
- **Anonymity:** Clients do not present a certificate. The server accepts any client request.
- **Probing Resistance:** Vulnerable to active probing if the probe knows the protocol. However, the traffic content is still hidden.
- **Use Case:** Public Proxy, sharing access with friends/family without key distribution.

### C. h2c (Cleartext) - **Stealth Mode**
- **Authentication:** None (unless HTTP Basic Auth is configured).
- **Encryption:** None (Cleartext).
- **Stealth:** Relies on blending in with HTTP traffic.
- **Use Case:** Behind a CDN (Cloudflare/Gcore) that handles TLS termination. Or inside a trusted internal network.

## 3. Active Defense Mechanisms

### Circuit Breaker & Hard Reset
To combat active network disruption (Reset Storms/Flapping):
- Phoenix Client monitors consecutive failures.
- If connectivity drops, it executes a **Hard Reset**, destroying the entire HTTP/2 connection pool and rebuilding it from scratch.
- **Debounce:** Prevents rapid-fire retries that could alert DPI systems or overload the client device.

### Ed25519 Signatures
We use **Ed25519** for all cryptographic operations (Key Generation, Singing certificates).
- **High Performance:** Very fast verification/signing suitable for high throughput.
- **Small Keys:** Small 32-byte public keys are easy to distribute in config files.
- **Quantum Resistance:** No, but standard industry practice. (Post-quantum algorithms planned for v2.0).

## 4. Best Practices

1. **Always use mTLS if possible.** It completely blocks unauthorized access to your server.
2. **Rotate Keys periodically.** Use `-gen-keys` to create new key pairs every few months.
3. **Keep binaries updated.** We regularly patch vulnerabilities and improve obfuscation.
4. **Use a CDN (Cloudflare) with h2c mode** if your IP is blocklisted. This hides your server IP behind the CDN's massive infrastructure.
