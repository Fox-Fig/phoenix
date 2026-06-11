package config

import (
	"phoenix/pkg/protocol"
)

// ClientInbound defines a single inbound protocol binding on the client side.
type ClientInbound struct {
	// Protocol specifies the protocol type (e.g., "socks5", "shadowsocks", "ssh").
	Protocol protocol.ProtocolType `toml:"protocol" doc:"Protocol type for this inbound listener (e.g., 'socks5', 'ssh', 'shadowsocks')."`

	// LocalAddr is the address and port the client should listen on (e.g., "127.0.0.1:1080").
	LocalAddr string `toml:"local_addr" doc:"Local address and port the client should listen on (e.g., '127.0.0.1:1080')."`

	// EnableUDP allows UDP Associate for SOCKS5
	EnableUDP bool `toml:"enable_udp,omitempty" doc:"Enable UDP Associate for SOCKS5 protocol." default:"true"`

	// TargetAddr is the remote destination address (optional, mainly for SSH/Port Forwarding).
	TargetAddr string `toml:"target_addr,omitempty" doc:"Remote destination address (mainly for SSH or direct Port Forwarding)."`

	// Encryption and authentication parameters for the protocol (if applicable).
	// For Shadowsocks, this might be "aes-256-gcm:password".
	// For SSH, this might be a key file path or simple forwarding.
	Auth string `toml:"auth,omitempty" doc:"Authentication string for specific protocols (e.g., Shadowsocks cypher:password)."`
}

// ClientRecovery defines settings for zombie connection detection and full-jitter backoff.
type ClientRecovery struct {
	Enabled        bool `toml:"enabled" doc:"Enable or disable the recovery and exponential backoff system." default:"true"`
	ErrorThreshold int  `toml:"error_threshold" doc:"Number of connection errors allowed within the error window before triggering a hard reset." default:"10"`
	ErrorWindowS   int  `toml:"error_window_s" doc:"Time window in seconds to count connection errors." default:"30"`
	BackoffBaseMs  int  `toml:"backoff_base_ms" doc:"Base delay in milliseconds for exponential backoff." default:"500"`
	BackoffCapMs   int  `toml:"backoff_cap_ms" doc:"Maximum delay in milliseconds for exponential backoff." default:"15000"`
	BackoffJitter  bool `toml:"backoff_jitter" doc:"Enable randomized AWS full-jitter for backoff delays." default:"true"`
}

// ClientConfig defines the full structure of the client configuration.
// It allows for multiple simultaneous inbound listeners on different ports.
type ClientConfig struct {
	// RemoteAddr is the address of the Phoenix server (e.g., "example.com:8080").
	RemoteAddr string `toml:"remote_addr" doc:"The address and port of the remote Phoenix server (e.g., 'example.com:8080')." default:"127.0.0.1:8080"`

	// Protocol specifies the underlying transport protocol (e.g., "h2", "ssh", "http1").
	Protocol string `toml:"protocol" doc:"Transport protocol to use for the tunnel ('h2', 'ssh', 'http1')." default:"h2"`

	// APIPaths defines the list of fake API paths to use for HTTP/1 API Camouflage (only for protocol 'http1').
	APIPaths []string `toml:"api_paths" protocol:"http1" doc:"List of fake API paths to use for API Camouflage when protocol is 'http1'." default:"[\"/api/v1/sync\", \"/upload/media\", \"/config/sync\"]" commented:"true"`

	// AuthToken is sent to the server for authentication.
	// Must match the server's auth_token.
	AuthToken string `toml:"auth_token" group:"Security" protocol:"h2" doc:"Authentication token. Must match the server's auth_token." commented:"true"`

	// PrivateKeyPath is the path to the client's private key file (PEM).
	PrivateKeyPath string `toml:"private_key" protocol:"h2,http1" doc:"Path to the client's Ed25519 private key file (PEM format) for mTLS." commented:"true"`

	// ServerPublicKey is the detailed public key of the server (Base64).
	ServerPublicKey string `toml:"server_public_key" protocol:"h2,http1" doc:"The exact Ed25519 public key of the server (Base64). Used for strict key pinning (One-Way TLS or mTLS)." commented:"true"`

	// TLSMode controls the TLS verification strategy.
	// "system" = use system CA store (for CDN/Cloudflare setups)
	// "" (empty) = use Phoenix Ed25519 pinning or h2c based on other fields
	TLSMode string `toml:"tls_mode" protocol:"h2,http1" doc:"TLS verification mode. 'system' uses system CA (e.g. for CDNs). 'insecure' disables verification. Leave empty for strict Phoenix key pinning or cleartext." default:"system" commented:"true"`

	// CustomSNI specifies an arbitrary SNI value to be sent during the TLS handshake.
	// If set, it overrides the remote address's hostname.
	CustomSNI string `toml:"custom_sni" protocol:"h2,http1" doc:"Arbitrary SNI hostname to send during TLS handshake (SNI spoofing)." default:"google.com" commented:"true"`

	// Fingerprint controls TLS ClientHello fingerprint spoofing.
	// Mimics a browser to bypass DPI-based filtering on some ISPs.
	// ""        → Go default TLS (no spoofing)
	// "chrome"  → Mimic Chrome (recommended)
	// "firefox" → Mimic Firefox
	// "safari"  → Mimic Safari
	// "random"  → Random browser fingerprint per connection
	Fingerprint string `toml:"fingerprint" protocol:"h2,http1" doc:"TLS ClientHello fingerprint. Options: 'chrome', 'firefox', 'safari', 'random', 'chrome_dynamic', or empty for none." default:"chrome_dynamic" commented:"true"`

	// Inbounds is a list of local listeners that the client will open.
	// Each inbound corresponds to a specific protocol and local port.
	Inbounds []ClientInbound `toml:"inbounds" group:"Inbound Listeners" doc:"List of local inbound listeners (e.g., SOCKS5 or local port forwards)."`

	// Recovery controls how the client handles zombie connections and disconnects.
	Recovery ClientRecovery `toml:"recovery" group:"Zombie Connection Recovery" doc:"Connection recovery and exponential backoff settings."`
}

// DefaultClientConfig returns a basic client configuration with a single SOCKS5 inbound.
func DefaultClientConfig() *ClientConfig {
	return &ClientConfig{
		Protocol:   "h2",
		APIPaths:   []string{"/api/v1/sync", "/upload/media", "/config/sync"},
		RemoteAddr: "127.0.0.1:8080",
		Inbounds: []ClientInbound{
			{
				Protocol:  protocol.ProtocolSOCKS5,
				LocalAddr: "127.0.0.1:1080",
			},
		},
		Recovery: ClientRecovery{
			Enabled:        true,
			ErrorThreshold: 10,
			ErrorWindowS:   30,
			BackoffBaseMs:  500,
			BackoffCapMs:   15000,
			BackoffJitter:  true,
		},
	}
}
