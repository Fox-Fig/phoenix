package transport

import (
	"fmt"
	"log"

	"phoenix/pkg/config"
	"phoenix/pkg/transport/h2"
	"phoenix/pkg/underlay"
)

// StartServer starts the server based on the configuration.
// It handles Underlay (TLS/Cleartext/Forwarder) and Transport (H2/etc) logic.
func StartServer(cfg *config.ServerConfig) error {
	// 1. Check for Outbound Forwarder Mode
	if cfg.Outbound != nil && cfg.Outbound.Type == "forwarder" {
		log.Printf("Starting in Port Forwarder mode (TCP/UDP) on %s -> %s", cfg.ListenAddr, cfg.Outbound.RemoteAddr)
		return underlay.StartPortForwarder(cfg.ListenAddr, cfg.Outbound.RemoteAddr)
	}

	// 2. Setup Underlay (TLS or Cleartext)
	log.Printf("Initializing Underlay networking...")
	underlayCfg := underlay.ServerConfig{
		TLSEnabled:           cfg.Security.PrivateKeyPath != "",
		PrivateKeyPath:       cfg.Security.PrivateKeyPath,
		AuthorizedClientKeys: cfg.Security.AuthorizedClientKeys,
		AllowedSNI:           cfg.Security.AllowedSNI,
		AllowEmptySNI:        cfg.Security.AllowEmptySNI,
		NextProtos:           []string{"h2"},
	}

	listener, err := underlay.Listen(cfg.ListenAddr, underlayCfg)
	if err != nil {
		return fmt.Errorf("underlay listen failed: %v", err)
	}

	// 3. Mount H2 Transport on top of Underlay
	log.Printf("Mounting H2 Transport on Underlay...")
	h2Server, err := h2.NewServer(cfg)
	if err != nil {
		return err
	}

	// In the future, we will pass a core.StreamHandler. For now, h2 routes internally.
	return h2Server.Serve(listener)
}

// Client is a wrapper for the transport client
type Client struct {
	*h2.Client
}

// NewClient creates a new Client
func NewClient(cfg *config.ClientConfig) *Client {
	return &Client{
		Client: h2.NewClient(cfg),
	}
}
