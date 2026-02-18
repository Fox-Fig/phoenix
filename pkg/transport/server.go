package transport

import (
	"io"
	"log"
	"net/http"
	"phoenix/pkg/adapter/shadowsocks"
	"phoenix/pkg/adapter/socks5"
	"phoenix/pkg/adapter/ssh"
	"phoenix/pkg/config"
	"phoenix/pkg/protocol"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

// Server handles incoming H2C connections and routes them to the appropriate protocol handler.
type Server struct {
	Config *config.ServerConfig
}

// NewServer creates a new H2C server instance.
func NewServer(cfg *config.ServerConfig) *Server {
	return &Server{Config: cfg}
}

// ServeHTTP implements the http.Handler interface.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
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

	var err error
	// If target is provided in header, we assume the handshake is already done (e.g. at client side)
	// and we just need to tunnel to the target.
	if target != "" {
		err = ssh.HandleConnection(stream, target)
	} else {
		switch protocol.ProtocolType(proto) {
		case protocol.ProtocolSOCKS5:
			// Server handles SOCKS5 handshake
			err = socks5.HandleConnection(stream, &socks5.NetDialer{}, s.Config.Security.EnableUDP)
		case protocol.ProtocolSOCKS5UDP:
			// Server handles SOCKS5 UDP Tunnel
			if !s.Config.Security.EnableUDP {
				http.Error(w, "UDP Disabled", http.StatusForbidden)
				return
			}
			err = socks5.HandleUDPTunnel(stream)
		case protocol.ProtocolShadowsocks:
			err = shadowsocks.HandleConnection(stream)
		case protocol.ProtocolSSH:
			// No target provided, impossible for tunnel unless Server is destination
			// or we implement SSH handshake parsing.
			// Revert to default handling or error?
			// For now, assume SSH forwarding always comes with target or Client is "Smart".
			err = ssh.HandleConnection(stream, "")
		default:
			_, err = io.Copy(stream, stream)
		}
	}

	if err != nil && err != io.EOF {
		log.Printf("Stream error: %v", err)
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

// StartServer starts the H2C server.
func StartServer(cfg *config.ServerConfig) error {
	srv := NewServer(cfg)
	h2s := &http2.Server{
		MaxConcurrentStreams: 500,         // Increase concurrency
		MaxReadFrameSize:     1024 * 1024, // 1MB frames if possible
		IdleTimeout:          10 * time.Second,
	}
	handler := h2c.NewHandler(srv, h2s)

	s := &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      handler,
		ReadTimeout:  0, // Disable read timeout for streaming
		WriteTimeout: 0, // Disable write timeout for streaming
		IdleTimeout:  0, // Disable idle timeout
	}

	log.Printf("Listening on %s", cfg.ListenAddr)
	return s.ListenAndServe()
}
