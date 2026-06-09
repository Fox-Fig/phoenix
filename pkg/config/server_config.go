package config

// ServerSecurity defines the security configuration for the server.
// It controls which protocols are allowed to be tunneled.
type ServerSecurity struct {
	// AuthToken is a shared secret for application-level authentication.
	// If set, clients must provide this exact token to connect.
	// Works with all TLS modes (h2c, system, mTLS).
	AuthToken string `toml:"auth_token" doc:"Shared secret for application-level authentication. If set, clients must provide this exact token to connect." commented:"true"`

	// EnableSOCKS5 enables or disables the SOCKS5 proxy protocol (TCP).
	EnableSOCKS5 bool `toml:"enable_socks5" doc:"Enable or disable the SOCKS5 proxy protocol (TCP)."`

	// EnableUDP enables or disables UDP tunneling (SOCKS5 UDP Associate).
	EnableUDP bool `toml:"enable_udp" doc:"Enable or disable UDP tunneling (SOCKS5 UDP Associate)."`

	// EnableShadowsocks enables or disables the Shadowsocks proxy protocol.
	EnableShadowsocks bool `toml:"enable_shadowsocks" doc:"Enable or disable the Shadowsocks proxy protocol."`

	// EnableSSH enables or disables SSH tunneling.
	EnableSSH bool `toml:"enable_ssh" doc:"Enable or disable SSH tunneling."`

	// PrivateKeyPath is the path to the server's private key file (PEM).
	PrivateKeyPath string `toml:"private_key" doc:"Path to the server's Ed25519 private key file (PEM format) for TLS." commented:"true"`

	// AuthorizedClientKeys is a list of authorized client public keys (Base64).
	AuthorizedClientKeys []string `toml:"authorized_clients" doc:"List of authorized client Ed25519 public keys (Base64) for mTLS. If empty, mTLS is disabled." commented:"true"`

	// AllowedSNI restricts which SNI hostnames the server will accept during the TLS handshake.
	// If empty, any SNI is accepted (standard Go behavior).
	AllowedSNI []string `toml:"allowed_sni" doc:"List of allowed SNI hostnames for TLS handshake. Supports wildcard (*). Empty means all are accepted." commented:"true"`

	// AllowEmptySNI determines if the server accepts direct IP connections where the SNI field is empty.
	AllowEmptySNI bool `toml:"allow_empty_sni" doc:"Accept direct IP connections where the SNI field is empty during TLS handshake." default:"true"`
}

// DefaultServerSecurity returns the default security configuration (all disabled by default).
func DefaultServerSecurity() ServerSecurity {
	return ServerSecurity{
		EnableSOCKS5:      false,
		EnableShadowsocks: false,
		EnableSSH:         false,
		AllowEmptySNI:     true, // Default to true to allow direct IP connections without SNI spoofing
	}
}

// ServerConfig defines the full structure of the server configuration file.
type ServerConfig struct {
	// ListenAddr is the address and port the server will bind to (e.g., ":8080").
	// This uses the underlying h2c protocol.
	ListenAddr string `toml:"listen_addr" doc:"The address and port the server will bind to (e.g., 0.0.0.0:8080)." default:"0.0.0.0:8080"`

	// Security defines the protocol access controls.
	Security ServerSecurity `toml:"security" group:"Security Controls" doc:"Security settings and protocol access controls."`

	// Outbound defines the relay/intermediary configuration (optional).
	Outbound *Outbound `toml:"outbound" group:"Outbound Relay" doc:"Outbound configuration for middle-server relay. If set, this server forwards traffic to another server." commented:"true"`
}

// Outbound defines the relay/intermediary configuration.
// It embeds ClientConfig to share the exact same networking and recovery engine.
type Outbound struct {
	Type       string `toml:"type" doc:"Type of outbound connection: 'direct' (default), 'phoenix' (relay to another Phoenix server), or 'forwarder' (SOCKS5)." default:"phoenix"`
	SOCKS5User string `toml:"socks5_user,omitempty" doc:"Username for SOCKS5 forwarder authentication." commented:"true"`
	SOCKS5Pass string `toml:"socks5_pass,omitempty" doc:"Password for SOCKS5 forwarder authentication." commented:"true"`
	
	// Inherit all client properties (remote_addr, auth_token, tls_mode, fingerprint, etc.)
	ClientConfig
}

// DefaultServerConfig returns a server configuration with safe defaults.
func DefaultServerConfig() *ServerConfig {
	return &ServerConfig{
		ListenAddr: ":8080",
		Security:   DefaultServerSecurity(),
	}
}
