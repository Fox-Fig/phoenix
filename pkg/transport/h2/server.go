package h2

import (
	"crypto/subtle"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"

	"phoenix/pkg/adapter/socks5"
	"phoenix/pkg/adapter/ssh"
	"phoenix/pkg/config"
	"phoenix/pkg/protocol"
	"phoenix/pkg/transport/core"
	"phoenix/pkg/utils"

	txsocks5 "github.com/txthinking/socks5"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

// Server implements core.ServerTransport for the H2 protocol.
type Server struct {
	Config                *config.ServerConfig
	outboundPhoenixClient *Client
	socks5ProxyClient     *txsocks5.Client
	handler               core.StreamHandler
}

// NewServer creates a new H2C server instance.
func NewServer(cfg *config.ServerConfig) (*Server, error) {
	s := &Server{Config: cfg}

	if cfg.Outbound != nil {
		if cfg.Outbound.Type == "phoenix" {
			s.outboundPhoenixClient = NewClient(&cfg.Outbound.ClientConfig)
		} else if cfg.Outbound.Type == "socks5" {
			c, err := txsocks5.NewClient(cfg.Outbound.RemoteAddr, cfg.Outbound.SOCKS5User, cfg.Outbound.SOCKS5Pass, 0, 0)
			if err != nil {
				return nil, fmt.Errorf("failed to init socks5 outbound: %v", err)
			}
			s.socks5ProxyClient = c
		}
	}

	return s, nil
}

// ServeHTTP implements the http.Handler interface.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// Token Authentication
	if s.Config.Security.AuthToken != "" {
		token := r.Header.Get("X-Nerve-Token")
		if subtle.ConstantTimeCompare([]byte(token), []byte(s.Config.Security.AuthToken)) != 1 {
			log.Printf("Rejected unauthorized connection from %s", r.RemoteAddr)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
	}

	proto := r.Header.Get("X-Nerve-Protocol")
	if proto == "" {
		http.Error(w, "Missing Protocol Header", http.StatusBadRequest)
		return
	}

	target := r.Header.Get("X-Nerve-Target")

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
		log.Printf("Blocked request for protocol %s from %s", proto, r.RemoteAddr)
		http.Error(w, "Protocol Disabled by Server", http.StatusForbidden)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming not supported", http.StatusInternalServerError)
		return
	}

	log.Printf("Accepted stream for protocol %s from %s (Target: %s)", proto, r.RemoteAddr, target)
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	// Wrap the request body and response writer into a ReadWriteCloser-like interface
	stream := &H2Stream{
		Reader:  r.Body,
		Writer:  w,
		Flusher: flusher,
	}

	// If phoenix outbound is configured, intercept everything!
	if s.Config.Outbound != nil && s.Config.Outbound.Type == "phoenix" {
		outboundStream, err := s.outboundPhoenixClient.Dial(protocol.ProtocolType(proto), target)
		if err != nil {
			log.Printf("Outbound Phoenix Dial failed: %v", err)
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
			return
		}
		defer outboundStream.Close()

		err = utils.Relay(stream, outboundStream)
		if err != nil && err != io.EOF {
			errStr := err.Error()
			if !utils.ContainsExpectedTeardownError(errStr) {
				log.Printf("Phoenix Relay error: %v", err)
			}
		}
		return
	}

	var dialer socks5.Dialer = &socks5.NetDialer{}
	var sshDialer ssh.Dialer = &ssh.NetDialer{}

	if s.Config.Outbound != nil && s.Config.Outbound.Type == "socks5" {
		// Use txsocks5 Client as Dialer
		// Wait, txsocks5.Client has Dial(network, addr string) (net.Conn, error)
		// We can just use it directly!
		dialer = s.socks5ProxyClient
		sshDialer = s.socks5ProxyClient
	}

	var err error
	// If target is provided in header, we assume the handshake is already done (e.g. at client side)
	// and we just need to tunnel to the target.
	if target != "" {
		err = ssh.HandleConnection(stream, target, sshDialer)
	} else {
		switch protocol.ProtocolType(proto) {
		case protocol.ProtocolSOCKS5:
			// Server handles SOCKS5 handshake
			err = socks5.HandleConnection(stream, dialer, s.Config.Security.EnableUDP)
		case protocol.ProtocolSOCKS5UDP:
			// Server handles SOCKS5 UDP Tunnel
			if !s.Config.Security.EnableUDP {
				http.Error(w, "UDP Disabled", http.StatusForbidden)
				return
			}
			err = socks5.HandleUDPTunnel(stream, dialer) // We'll update this next if needed
		case protocol.ProtocolShadowsocks:
			// SS is decrypted on client side; server gets target in header.
			// If no target, we can't do anything.
			err = fmt.Errorf("shadowsocks requires target address")
		case protocol.ProtocolSSH:
			// No target provided, impossible for tunnel unless Server is destination
			// or we implement SSH handshake parsing.
			// Revert to default handling or error?
			// For now, assume SSH forwarding always comes with target or Client is "Smart".
			err = ssh.HandleConnection(stream, "", sshDialer)
		default:
			_, err = io.Copy(stream, stream)
		}
	}

	if err != nil && err != io.EOF {
		errStr := err.Error()
		if !utils.ContainsExpectedTeardownError(errStr) {
			log.Printf("Stream error: %v", err)
		}
	}
}

// H2Stream adapts request/response to ReadWriteCloser
type H2Stream struct {
	io.Reader
	io.Writer
	http.Flusher
}

func (s *H2Stream) Write(p []byte) (n int, err error) {
	n, err = s.Writer.Write(p)
	if n > 0 {
		s.Flusher.Flush()
	}
	return
}

func (s *H2Stream) Close() error {
	// We can't really "close" the response writer other than returning from the handler.
	// But we can close the Request Body if needed, though HTTP server does that.
	if c, ok := s.Reader.(io.Closer); ok {
		c.Close()
	}
	return nil
}

// Serve implements core.ServerTransport.
// It mounts the HTTP/2 and HTTP/1 multiplexer on top of the given listener.
func (s *Server) Serve(l net.Listener) error {
	h2s := &http2.Server{
		MaxConcurrentStreams: 100, // Adjust as needed
	}

	h1s := &http.Server{
		Handler: h2c.NewHandler(s, h2s),
	}

	log.Printf("[H2] Serving HTTP/2 multiplexer on Underlay Listener")
	return h1s.Serve(l)
}
