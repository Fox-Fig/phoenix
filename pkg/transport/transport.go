package transport

import (
	"fmt"
	"log"

	"phoenix/pkg/config"
	"phoenix/pkg/transport/core"
	"phoenix/pkg/transport/h2"
	"phoenix/pkg/transport/http1"
	"phoenix/pkg/transport/ssh"
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

	// Setup Underlay
	log.Printf("Initializing Underlay networking...")
	var nextProtos []string
	if cfg.Protocol == "http1" {
		nextProtos = []string{"http/1.1"}
	} else {
		nextProtos = []string{"h2"}
	}

	underlayCfg := underlay.ServerConfig{
		TLSEnabled:           cfg.Security.PrivateKeyPath != "" && cfg.Protocol != "ssh", // SSH does its own crypto
		PrivateKeyPath:       cfg.Security.PrivateKeyPath,
		AuthorizedClientKeys: cfg.Security.AuthorizedClientKeys,
		AllowedSNI:           cfg.Security.AllowedSNI,
		AllowEmptySNI:        cfg.Security.AllowEmptySNI,
		NextProtos:           nextProtos,
	}

	listener, err := underlay.Listen(cfg.ListenAddr, underlayCfg)
	if err != nil {
		return fmt.Errorf("underlay listen failed: %v", err)
	}

	// Mount Transport on top of Underlay
	if cfg.Protocol == "ssh" {
		log.Printf("Mounting SSH Transport on Underlay...")
		sshServer, err := ssh.NewServer(cfg)
		if err != nil {
			return err
		}
		return sshServer.Serve(listener)
	} else if cfg.Protocol == "http1" {
		log.Printf("Mounting HTTP/1 API Camouflage Transport on Underlay...")
		http1Server := http1.NewServer(cfg)
		if cfg.Outbound != nil && cfg.Outbound.Type == "phoenix" {
			http1Server.SetOutboundPhoenixClient(NewClient(&cfg.Outbound.ClientConfig))
		}
		return http1Server.Serve(listener)
	}

	log.Printf("Mounting H2 Transport on Underlay...")
	h2Server, err := h2.NewServer(cfg)
	if err != nil {
		return err
	}

	return h2Server.Serve(listener)
}

// Client is a wrapper for the transport client
type Client struct {
	core.ClientTransport
}

// NewClient creates a new Client
func NewClient(cfg *config.ClientConfig) *Client {
	if cfg.Protocol == "ssh" {
		return &Client{
			ClientTransport: ssh.NewClient(cfg),
		}
	} else if cfg.Protocol == "http1" {
		return &Client{
			ClientTransport: http1.NewClient(cfg),
		}
	}
	
	return &Client{
		ClientTransport: h2.NewClient(cfg),
	}
}
