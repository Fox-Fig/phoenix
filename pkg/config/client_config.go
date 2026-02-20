package config

import (
	"phoenix/pkg/protocol"
)

// ClientInbound defines a single inbound protocol binding on the client side.
type ClientInbound struct {
	// Protocol specifies the protocol type (e.g., "socks5", "shadowsocks", "ssh").
	Protocol protocol.ProtocolType `toml:"protocol"`

	// LocalAddr is the address and port the client should listen on (e.g., "127.0.0.1:1080").
	LocalAddr string `toml:"local_addr"`

	// EnableUDP allows UDP Associate for SOCKS5
	EnableUDP bool `toml:"enable_udp,omitempty"`

	// TargetAddr is the remote destination address (optional, mainly for SSH/Port Forwarding).
	TargetAddr string `toml:"target_addr,omitempty"`

	// Encryption and authentication parameters for the protocol (if applicable).
	// For Shadowsocks, this might be "aes-256-gcm:password".
	// For SSH, this might be a key file path or simple forwarding.
	Auth string `toml:"auth,omitempty"`
}

// ClientConfig defines the full structure of the client configuration.
// It allows for multiple simultaneous inbound listeners on different ports.
type ClientConfig struct {
	// RemoteAddr is the address of the Phoenix server (e.g., "example.com:8080").
	RemoteAddr string `toml:"remote_addr"`

	// Inbounds is a list of local listeners that the client will open.
	// Each inbound corresponds to a specific protocol and local port.
	Inbounds []ClientInbound `toml:"inbounds"`

	// ClientID is a unique identifier or token for authentication with the server (optional, for future use).
	ClientID string `toml:"client_id,omitempty"`

	// PrivateKeyPath is the path to the client's private key file (PEM).
	PrivateKeyPath string `toml:"private_key"`

	// ServerPublicKey is the detailed public key of the server (Base64).
	ServerPublicKey string `toml:"server_public_key"`

	// HardResetThreshold is the number of connection failures before a hard reset
	HardResetThreshold uint32 `toml:"hard_reset_threshold"`

	// HardResetDebounce is the minimum seconds between hard resets
	HardResetDebounce int `toml:"hard_reset_debounce"`

	// EnablePool turns on or off the multipath connection pool system
	EnablePool bool `toml:"enable_pool"`

	// PoolSize specifies the number of independent HTTP clients (TCP connections) to multiplex over.
	PoolSize int `toml:"pool_size"`
}

// DefaultClientConfig returns a basic client configuration with a single SOCKS5 inbound.
func DefaultClientConfig() *ClientConfig {
	return &ClientConfig{
		RemoteAddr: "127.0.0.1:8080",
		Inbounds: []ClientInbound{
			{
				Protocol:  protocol.ProtocolSOCKS5,
				LocalAddr: "127.0.0.1:1080",
			},
		},
		HardResetThreshold: 3,
		HardResetDebounce:  5,
		EnablePool:         true,
		PoolSize:           5,
	}
}
