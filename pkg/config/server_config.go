package config

// ServerSecurity defines the security configuration for the server.
// It controls which protocols are allowed to be tunneled.
type ServerSecurity struct {
	// AuthToken is a shared secret for application-level authentication.
	// If set, clients must provide this exact token to connect.
	// Works with all TLS modes (h2c, system, mTLS).
	AuthToken string `toml:"auth_token"`

	// EnableSOCKS5 enables or disables the SOCKS5 proxy protocol (TCP).
	EnableSOCKS5 bool `toml:"enable_socks5"`

	// EnableUDP enables or disables UDP tunneling (SOCKS5 UDP Associate).
	EnableUDP bool `toml:"enable_udp"`

	// EnableShadowsocks enables or disables the Shadowsocks proxy protocol.
	EnableShadowsocks bool `toml:"enable_shadowsocks"`

	// EnableSSH enables or disables SSH tunneling.
	EnableSSH bool `toml:"enable_ssh"`

	// PrivateKeyPath is the path to the server's private key file (PEM).
	PrivateKeyPath string `toml:"private_key"`

	// AuthorizedClientKeys is a list of authorized client public keys (Base64).
	AuthorizedClientKeys []string `toml:"authorized_clients"`

	// AllowedSNI restricts which SNI hostnames the server will accept during the TLS handshake.
	// If empty, any SNI is accepted (standard Go behavior).
	AllowedSNI []string `toml:"allowed_sni"`

	// AllowEmptySNI determines if the server accepts direct IP connections where the SNI field is empty.
	AllowEmptySNI bool `toml:"allow_empty_sni"`
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
	ListenAddr string `toml:"listen_addr"`

	// Security defines the protocol access controls.
	Security ServerSecurity `toml:"security"`

	// Outbound defines the relay/intermediary configuration (optional).
	Outbound *Outbound `toml:"outbound"`
}

// Outbound defines the relay/intermediary configuration.
type Outbound struct {
	Type            string `toml:"type"` // "direct" (default), "phoenix", "socks5"
	Target          string `toml:"target"`
	TLSMode         string `toml:"tls_mode"`
	CustomSNI       string `toml:"custom_sni"`
	Fingerprint     string `toml:"fingerprint"`
	AuthToken       string `toml:"auth_token"`
	ServerPublicKey string `toml:"server_public_key"`
	PrivateKeyPath  string         `toml:"private_key"`
	SOCKS5User      string         `toml:"socks5_user"`
	SOCKS5Pass      string         `toml:"socks5_pass"`
	Recovery        ClientRecovery `toml:"recovery"`
}

// DefaultServerConfig returns a server configuration with safe defaults.
func DefaultServerConfig() *ServerConfig {
	return &ServerConfig{
		ListenAddr: ":8080",
		Security:   DefaultServerSecurity(),
	}
}
