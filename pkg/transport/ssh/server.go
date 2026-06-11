package ssh

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"

	gossh "golang.org/x/crypto/ssh"

	"phoenix/pkg/adapter/socks5"
	"phoenix/pkg/adapter/ssh"
	"phoenix/pkg/config"
	"phoenix/pkg/crypto"
	"phoenix/pkg/protocol"
	"phoenix/pkg/utils"

	txsocks5 "github.com/txthinking/socks5"
)

// Server implements the Phoenix transport using standard SSH.
type Server struct {
	Config            *config.ServerConfig
	socks5ProxyClient *txsocks5.Client
	sshConfig         *gossh.ServerConfig
}

// NewServer creates a new SSH transport server instance.
func NewServer(cfg *config.ServerConfig) (*Server, error) {
	s := &Server{Config: cfg}

	if cfg.Outbound != nil {
		if cfg.Outbound.Type == "socks5" {
			c, err := txsocks5.NewClient(cfg.Outbound.RemoteAddr, cfg.Outbound.SOCKS5User, cfg.Outbound.SOCKS5Pass, 0, 0)
			if err != nil {
				return nil, fmt.Errorf("failed to init socks5 outbound: %v", err)
			}
			s.socks5ProxyClient = c
		}
		// Note: Chaining Phoenix over Phoenix via SSH is omitted here for brevity, 
		// but can be added similarly to H2.
	}

	// Setup SSH Server Config
	sshConfig := &gossh.ServerConfig{
		NoClientAuth: len(cfg.Security.AuthorizedClientKeys) == 0 && cfg.Security.AuthToken == "",
		PublicKeyCallback: func(conn gossh.ConnMetadata, key gossh.PublicKey) (*gossh.Permissions, error) {
			// Find if the key matches any of our authorized clients
			authorizedKeys := cfg.Security.AuthorizedClientKeys
			if len(authorizedKeys) == 0 {
				return nil, fmt.Errorf("no authorized clients configured")
			}

			// We need to compare the parsed key with the base64 keys we have
			
			// Try to match against authorized clients. 
			// In our config, AuthorizedClientKeys are base64 encoded ed25519 raw public keys.
			for _, authKeyB64 := range authorizedKeys {
				authKeyRaw, err := base64.StdEncoding.DecodeString(authKeyB64)
				if err != nil {
					continue
				}
				
				parsedSSHKey, err := gossh.NewPublicKey(ed25519.PublicKey(authKeyRaw))
				if err == nil && bytes.Equal(key.Marshal(), parsedSSHKey.Marshal()) {
					return &gossh.Permissions{
						Extensions: map[string]string{
							"pubkey-fp": gossh.FingerprintSHA256(key),
						},
					}, nil
				}
			}
			return nil, fmt.Errorf("unauthorized client key")
		},
		PasswordCallback: func(conn gossh.ConnMetadata, password []byte) (*gossh.Permissions, error) {
			// We only use password auth for the AuthToken feature as a fallback or additional layer
			if cfg.Security.AuthToken != "" {
				if subtle.ConstantTimeCompare(password, []byte(cfg.Security.AuthToken)) == 1 {
					return nil, nil
				}
			}
			return nil, fmt.Errorf("password rejected")
		},
	}

	if cfg.Security.PrivateKeyPath != "" {
		privateKeyRaw, err := crypto.LoadPrivateKey(cfg.Security.PrivateKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load private key: %v", err)
		}
		
		signer, err := gossh.NewSignerFromKey(privateKeyRaw)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key to ssh signer: %v", err)
		}
		sshConfig.AddHostKey(signer)
	} else {
		// Generate ephemeral key for No Auth / Insecure scenarios
		_, privRaw, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate ephemeral ssh key: %v", err)
		}
		signer, err := gossh.NewSignerFromKey(privRaw)
		if err != nil {
			return nil, fmt.Errorf("failed to parse ephemeral key to ssh signer: %v", err)
		}
		sshConfig.AddHostKey(signer)
	}

	s.sshConfig = sshConfig
	return s, nil
}

// Serve accepts connections and performs the SSH handshake.
func (s *Server) Serve(l net.Listener) error {
	log.Printf("[SSH] Serving SSH Transport Multiplexer")
	for {
		nConn, err := l.Accept()
		if err != nil {
			log.Printf("Failed to accept incoming connection: %v", err)
			continue
		}
		go s.handleConn(nConn)
	}
}

func (s *Server) handleConn(nConn net.Conn) {
	sshConn, chans, reqs, err := gossh.NewServerConn(nConn, s.sshConfig)
	if err != nil {
		log.Printf("[SSH] Handshake failed: %v", err)
		return
	}
	log.Printf("[SSH] New connection from %s (%s)", sshConn.RemoteAddr(), sshConn.ClientVersion())

	// Discard out-of-band requests
	go gossh.DiscardRequests(reqs)

	// Handle channels
	for newChannel := range chans {
		if newChannel.ChannelType() != "nerve-stream" {
			newChannel.Reject(gossh.UnknownChannelType, "unknown channel type")
			continue
		}

		meta, err := DecodeChannelMetadata(newChannel.ExtraData())
		if err != nil {
			newChannel.Reject(gossh.Prohibited, "invalid metadata")
			continue
		}

		channel, requests, err := newChannel.Accept()
		if err != nil {
			log.Printf("Could not accept channel: %v", err)
			continue
		}
		
		go gossh.DiscardRequests(requests)

		go s.handleStream(channel, meta)
	}
}

func (s *Server) handleStream(stream gossh.Channel, meta *ChannelMetadata) {
	defer stream.Close()

	proto := meta.Protocol
	target := meta.Target

	allowed := false
	switch protocol.ProtocolType(proto) {
	case protocol.ProtocolSOCKS5:
		allowed = s.Config.Security.EnableSOCKS5
	case protocol.ProtocolSOCKS5UDP:
		allowed = s.Config.Security.EnableUDP
	case protocol.ProtocolShadowsocks:
		allowed = s.Config.Security.EnableShadowsocks
	case protocol.ProtocolSSH:
		allowed = s.Config.Security.EnableSSH
	default:
		log.Printf("Unknown protocol requested: %s", proto)
	}

	if !allowed {
		log.Printf("Blocked request for protocol %s", proto)
		return
	}

	var dialer socks5.Dialer = &socks5.NetDialer{}
	var sshDialer ssh.Dialer = &ssh.NetDialer{}

	if s.socks5ProxyClient != nil {
		dialer = s.socks5ProxyClient
		sshDialer = s.socks5ProxyClient
	}

	var err error
	if target != "" {
		err = ssh.HandleConnection(stream, target, sshDialer)
	} else {
		switch protocol.ProtocolType(proto) {
		case protocol.ProtocolSOCKS5:
			err = socks5.HandleConnection(stream, dialer, s.Config.Security.EnableUDP)
		case protocol.ProtocolSOCKS5UDP:
			err = socks5.HandleUDPTunnel(stream, dialer)
		case protocol.ProtocolShadowsocks:
			err = fmt.Errorf("shadowsocks requires target address")
		case protocol.ProtocolSSH:
			err = ssh.HandleConnection(stream, "", sshDialer)
		default:
			_, err = io.Copy(stream, stream)
		}
	}

	if err != nil && err != io.EOF {
		if !utils.ContainsExpectedTeardownError(err.Error()) {
			// Don't log expected closed connection errors from benchmarks
			log.Printf("[SSH] Stream error: %v", err)
		}
	}
}
