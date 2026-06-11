package ssh

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"phoenix/pkg/config"
	"phoenix/pkg/crypto"
	"phoenix/pkg/protocol"
	"phoenix/pkg/underlay"
)

// Client handles outgoing SSH multiplexed connections to the Server.
type Client struct {
	Config          *config.ClientConfig
	sshClient       *gossh.Client
	mu              sync.RWMutex
	resetAttempts   int
	errorTimestamps []time.Time
}

// NewClient creates a new SSH transport client instance.
func NewClient(cfg *config.ClientConfig) *Client {
	c := &Client{
		Config: cfg,
	}

	c.logSecurityMode()
	c.connect()

	return c
}

func (c *Client) logSecurityMode() {
	tokenStatus := "disabled"
	if c.Config.AuthToken != "" {
		tokenStatus = "ENABLED"
	}
	log.Printf("Security Mode: SSH Transport (Native Ed25519 Auth) | Token Auth: %s", tokenStatus)
}

func (c *Client) createSSHConfig() (*gossh.ClientConfig, error) {
	cfg := c.Config
	
	sshConfig := &gossh.ClientConfig{
		User: "phoenix",
		HostKeyCallback: func(hostname string, remote net.Addr, key gossh.PublicKey) error {
			if cfg.ServerPublicKey == "" {
				return nil // Insecure
			}
			
			// Verify server's public key
			serverKeyRaw, err := base64.StdEncoding.DecodeString(cfg.ServerPublicKey)
			if err != nil {
				return fmt.Errorf("invalid server public key config: %v", err)
			}
			
			expectedKey, err := gossh.NewPublicKey(ed25519.PublicKey(serverKeyRaw))
			if err != nil {
				return fmt.Errorf("failed to parse server public key: %v", err)
			}
			
			if !bytes.Equal(key.Marshal(), expectedKey.Marshal()) {
				return fmt.Errorf("server key verification failed: %s", gossh.FingerprintSHA256(key))
			}
			return nil
		},
		Timeout: 10 * time.Second,
	}

	var authMethods []gossh.AuthMethod

	if cfg.PrivateKeyPath != "" {
		privRaw, err := crypto.LoadPrivateKey(cfg.PrivateKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load private key: %v", err)
		}
		
		signer, err := gossh.NewSignerFromKey(privRaw)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key to signer: %v", err)
		}
		authMethods = append(authMethods, gossh.PublicKeys(signer))
	}

	if cfg.AuthToken != "" {
		authMethods = append(authMethods, gossh.Password(cfg.AuthToken))
	}

	sshConfig.Auth = authMethods
	return sshConfig, nil
}

func (c *Client) connect() {
	c.mu.Lock()
	defer c.mu.Unlock()

	sshConfig, err := c.createSSHConfig()
	if err != nil {
		log.Printf("Failed to create SSH config: %v", err)
		return
	}

	// We use the underlay but force TLS off since SSH is our secure layer.
	// We just want a raw TCP connection, which underlay.Dial provides if TLSEnabled is false.
	underlayCfg := underlay.ClientConfig{
		TLSEnabled: false,
	}

	conn, err := underlay.Dial(c.Config.RemoteAddr, underlayCfg)
	if err != nil {
		log.Printf("Failed to dial server: %v", err)
		return
	}

	sshConn, chans, reqs, err := gossh.NewClientConn(conn, c.Config.RemoteAddr, sshConfig)
	if err != nil {
		log.Printf("SSH Handshake failed: %v", err)
		conn.Close()
		return
	}

	c.sshClient = gossh.NewClient(sshConn, chans, reqs)
	c.resetAttempts = 0
	log.Printf("SSH Transport connected to %s", c.Config.RemoteAddr)
}

// Dial opens a new SSH Channel for the given protocol and target.
func (c *Client) Dial(proto protocol.ProtocolType, target string) (io.ReadWriteCloser, error) {
	c.mu.RLock()
	client := c.sshClient
	c.mu.RUnlock()

	if client == nil {
		c.connect()
		c.mu.RLock()
		client = c.sshClient
		c.mu.RUnlock()
		if client == nil {
			return nil, fmt.Errorf("no active SSH connection")
		}
	}

	meta := &ChannelMetadata{
		Protocol: string(proto),
		Target:   target,
	}

	channel, requests, err := client.OpenChannel("nerve-stream", meta.Encode())
	if err != nil {
		c.handleConnectionFailure(err)
		return nil, fmt.Errorf("failed to open ssh channel: %v", err)
	}
	
	go gossh.DiscardRequests(requests)

	return channel, nil
}

func (c *Client) handleConnectionFailure(err error) {
	if !c.Config.Recovery.Enabled {
		return
	}

	c.mu.Lock()
	now := time.Now()
	var recentErrors []time.Time
	windowStart := now.Add(-time.Duration(c.Config.Recovery.ErrorWindowS) * time.Second)
	
	for _, t := range c.errorTimestamps {
		if t.After(windowStart) {
			recentErrors = append(recentErrors, t)
		}
	}
	recentErrors = append(recentErrors, now)
	c.errorTimestamps = recentErrors
	errCount := len(recentErrors)
	
	triggerReset := errCount >= c.Config.Recovery.ErrorThreshold
	if triggerReset {
		c.errorTimestamps = nil
	}
	c.mu.Unlock()

	if triggerReset {
		log.Printf("Network unstable. Reconnecting SSH...")
		if c.sshClient != nil {
			c.sshClient.Close()
			c.sshClient = nil
		}
		c.connect()
	}
}

// Close gracefully closes the client.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sshClient != nil {
		return c.sshClient.Close()
	}
	return nil
}
