package http1

import (
	"log"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"phoenix/pkg/adapter/socks5"
	"phoenix/pkg/adapter/ssh"
	"phoenix/pkg/config"
	"phoenix/pkg/protocol"
	"phoenix/pkg/transport/core"
	"phoenix/pkg/utils"
	txsocks5 "github.com/txthinking/socks5"
)

type Server struct {
	Config  *config.ServerConfig
	
	// We use core.ClientTransport to avoid circular dependency
	outboundPhoenixClient core.ClientTransport
	socks5ProxyClient     *txsocks5.Client

	streamsMu sync.RWMutex
	streams   map[string]*VirtualStream

	clientsMu sync.Mutex
	clients   map[string]*clientSession

	httpServer *http.Server
}

type clientSession struct {
	mu     sync.Mutex
	queue  []DownlinkMessage
	signal chan struct{}
}

func (cs *clientSession) notify() {
	select {
	case cs.signal <- struct{}{}:
	default:
	}
}

// NewServer creates a new HTTP/1 Server Transport.
func NewServer(cfg *config.ServerConfig) *Server {
	s := &Server{
		Config:  cfg,
		streams: make(map[string]*VirtualStream),
		clients: make(map[string]*clientSession),
	}
	
	if cfg.Outbound != nil {
		if cfg.Outbound.Type == "socks5" {
			c, err := txsocks5.NewClient(cfg.Outbound.RemoteAddr, cfg.Outbound.SOCKS5User, cfg.Outbound.SOCKS5Pass, 0, 0)
			if err == nil {
				s.socks5ProxyClient = c
			}
		}
	}
	return s
}

// SetOutboundPhoenixClient sets the outbound client (injected from transport package)
func (s *Server) SetOutboundPhoenixClient(client core.ClientTransport) {
	s.outboundPhoenixClient = client
}

func (s *Server) getClientSession(clientID string) *clientSession {
	s.clientsMu.Lock()
	defer s.clientsMu.Unlock()
	if cs, ok := s.clients[clientID]; ok {
		return cs
	}
	cs := &clientSession{
		signal: make(chan struct{}, 1),
	}
	s.clients[clientID] = cs
	return cs
}

// Serve begins serving HTTP/1 multiplexing.
func (s *Server) Serve(l net.Listener) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleHTTP)

	s.httpServer = &http.Server{
		Handler:      mux,
		ReadTimeout:  60 * time.Second,
		WriteTimeout: 60 * time.Second,
	}

	return s.httpServer.Serve(l)
}

// Close implements core.ServerTransport.
func (s *Server) Close() error {
	if s.httpServer != nil {
		return s.httpServer.Close()
	}
	return nil
}

func (s *Server) handleHTTP(w http.ResponseWriter, r *http.Request) {
	clientID := r.Header.Get("X-Client-ID")
	if clientID == "" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	streamID := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")

	if r.Header.Get("X-Phoenix-Sync") == "1" {
		// Long-polling GET
		s.handleSync(w, r, clientID)
		return
	}

	if r.Header.Get("X-Phoenix-Init") == "1" {
		// New Stream Initialization
		innerProto := r.Header.Get("X-Protocol")
		target := r.Header.Get("X-Target")
		if innerProto == "" || target == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		cs := s.getClientSession(clientID)
		writeFunc := func(data []byte) (int, error) {
			cs.mu.Lock()
			// Backpressure: If queue is too large (e.g. > 100 chunks ≈ 3.2MB), wait.
			// This prevents OOM and infinite memory growth during high-speed downloads.
			for len(cs.queue) > 100 {
				cs.mu.Unlock()
				time.Sleep(10 * time.Millisecond)
				cs.mu.Lock()
			}
			cs.queue = append(cs.queue, DownlinkMessage{StreamID: streamID, Data: data})
			cs.mu.Unlock()
			cs.notify()
			return len(data), nil
		}
		closeFunc := func() error {
			s.streamsMu.Lock()
			delete(s.streams, streamID)
			s.streamsMu.Unlock()

			// send empty chunk to signal close to the client
			cs.mu.Lock()
			cs.queue = append(cs.queue, DownlinkMessage{StreamID: streamID, Data: []byte{}})
			cs.mu.Unlock()
			cs.notify()
			return nil
		}

		vs := NewVirtualStream(streamID, protocol.ProtocolType(innerProto), target, writeFunc, closeFunc)
		s.streamsMu.Lock()
		s.streams[streamID] = vs
		s.streamsMu.Unlock()

		// Invoke handler asynchronously so the proxy can start processing
		go s.processStream(vs, target, protocol.ProtocolType(innerProto))
		
		w.WriteHeader(http.StatusCreated)
		return
	}

	if r.Method == "DELETE" {
		s.streamsMu.RLock()
		vs, ok := s.streams[streamID]
		s.streamsMu.RUnlock()
		if ok {
			vs.MarkClosed() // mark locally closed, do not trigger closeFunc recursively
			s.streamsMu.Lock()
			delete(s.streams, streamID)
			s.streamsMu.Unlock()
		}
		w.WriteHeader(http.StatusOK)
		return
	}

	// Uplink Data Chunk (POST/PUT/PATCH)
	s.streamsMu.RLock()
	vs, ok := s.streams[streamID]
	s.streamsMu.RUnlock()

	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	data, err := io.ReadAll(r.Body)
	if err != nil || len(data) == 0 {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	vs.PushData(data)
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleSync(w http.ResponseWriter, r *http.Request, clientID string) {
	cs := s.getClientSession(clientID)

	cs.mu.Lock()
	if len(cs.queue) == 0 {
		cs.mu.Unlock()
		// Wait up to 25 seconds for data
		select {
		case <-cs.signal:
		case <-time.After(25 * time.Second):
			w.WriteHeader(http.StatusNoContent)
			return
		case <-r.Context().Done():
			return
		}
		cs.mu.Lock()
	}

	if len(cs.queue) == 0 {
		cs.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// Copy and clear queue (batching)
	msgs := cs.queue
	cs.queue = nil
	cs.mu.Unlock()

	payload := EncodeDownlink(msgs)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	w.Write(payload)
}

func (s *Server) processStream(stream *VirtualStream, target string, proto protocol.ProtocolType) {
	defer stream.Close()

	if s.Config.Outbound != nil && s.Config.Outbound.Type == "phoenix" && s.outboundPhoenixClient != nil {
		outboundStream, err := s.outboundPhoenixClient.Dial(proto, target)
		if err != nil {
			return
		}
		defer outboundStream.Close()

		utils.Relay(stream, outboundStream)
		return
	}

	var dialer socks5.Dialer = &socks5.NetDialer{}
	var sshDialer ssh.Dialer = &ssh.NetDialer{}

	if s.Config.Outbound != nil && s.Config.Outbound.Type == "socks5" && s.socks5ProxyClient != nil {
		dialer = s.socks5ProxyClient
		sshDialer = s.socks5ProxyClient
	}

	if target != "" {
		ssh.HandleConnection(stream, target, sshDialer)
	} else {
		switch proto {
		case protocol.ProtocolSOCKS5:
			socks5.HandleConnection(stream, dialer, s.Config.Security.EnableUDP)
		case protocol.ProtocolSOCKS5UDP:
			if s.Config.Security.EnableUDP {
				socks5.HandleUDPTunnel(stream, dialer)
			}
		case protocol.ProtocolSSH:
			if err := ssh.HandleConnection(stream, "", sshDialer); err != nil {
				if err != io.EOF && !utils.ContainsExpectedTeardownError(err.Error()) {
					log.Printf("[HTTP1] Stream error: %v", err)
				}
			}
		default:
			io.Copy(stream, stream)
		}
	}
}
