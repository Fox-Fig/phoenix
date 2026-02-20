package transport

import (
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"phoenix/pkg/config"
	"phoenix/pkg/crypto"
	"phoenix/pkg/protocol"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"
)

// PooledClient represents a single HTTP client and its error state.
type PooledClient struct {
	client        *http.Client
	failureCount  uint32
	lastReset     time.Time
	mu            sync.RWMutex
	activeStreams atomic.Int32
}

// Client handles outgoing connections to the Server multiplexed over a Connection Pool.
type Client struct {
	Config *config.ClientConfig
	Scheme string
	pool   []*PooledClient
}

// NewClient creates a new Phoenix client instance.
func NewClient(cfg *config.ClientConfig) *Client {
	c := &Client{
		Config: cfg,
	}

	// Initialize scheme based on config
	if cfg.PrivateKeyPath != "" || cfg.ServerPublicKey != "" {
		c.Scheme = "https"
	} else {
		c.Scheme = "http"
	}

	// Initialize pool
	size := 1
	if cfg.EnablePool {
		size = cfg.PoolSize
		if size <= 0 {
			size = 5
		}
	}

	c.pool = make([]*PooledClient, size)
	for i := 0; i < size; i++ {
		c.pool[i] = &PooledClient{
			client: c.createHTTPClient(),
		}
	}

	return c
}

// createHTTPClient creates a fresh http.Client based on configuration.
func (c *Client) createHTTPClient() *http.Client {
	var tr *http2.Transport

	// Check if Secure Mode is requested (mTLS or One-Way TLS)
	// Requires either PrivateKey (mTLS) OR ServerPublicKey (One-Way)
	if c.Config.PrivateKeyPath != "" || c.Config.ServerPublicKey != "" {
		log.Println("Creating SECURE transport (TLS)")

		var certs []tls.Certificate
		if c.Config.PrivateKeyPath != "" {
			priv, err := crypto.LoadPrivateKey(c.Config.PrivateKeyPath)
			if err != nil {
				log.Printf("Failed to load private key: %v", err) // Should we panic? Maybe just log here to allow retry
			} else {
				cert, err := crypto.GenerateTLSCertificate(priv)
				if err != nil {
					log.Printf("Failed to generate TLS cert: %v", err)
				} else {
					certs = []tls.Certificate{cert}
				}
			}
		}

		tlsConfig := &tls.Config{
			Certificates:       certs,
			InsecureSkipVerify: true, // We use custom verification
			VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
				if c.Config.ServerPublicKey == "" {
					log.Println("WARNING: server_public_key NOT SET. Connection vulnerable to MITM.")
					return nil
				}

				if len(rawCerts) == 0 {
					return errors.New("no server certificate presented")
				}
				leaf, err := x509.ParseCertificate(rawCerts[0])
				if err != nil {
					return fmt.Errorf("failed to parse server cert: %v", err)
				}

				pub := leaf.PublicKey
				pubBytes, ok := pub.(ed25519.PublicKey)
				if !ok {
					return errors.New("server key is not Ed25519")
				}

				pubStr := base64.StdEncoding.EncodeToString(pubBytes)
				if pubStr != c.Config.ServerPublicKey {
					return fmt.Errorf("server key verification failed. Expected %s, Got %s", c.Config.ServerPublicKey, pubStr)
				}
				return nil
			},
		}

		tr = &http2.Transport{
			TLSClientConfig:            tlsConfig,
			StrictMaxConcurrentStreams: true,
			ReadIdleTimeout:            0,
			PingTimeout:                5 * time.Second,
		}

	} else {
		// INSECURE MODE (h2c)
		log.Println("Creating INSECURE transport (h2c)")
		tr = &http2.Transport{
			AllowHTTP: true,
			DialTLS: func(network, addr string, cfg *tls.Config) (net.Conn, error) {
				return net.Dial(network, addr)
			},
			StrictMaxConcurrentStreams: true,
			ReadIdleTimeout:            0,
			PingTimeout:                5 * time.Second,
		}
	}

	return &http.Client{Transport: tr}
}

// GetClient returns a PooledClient using a Least-Loaded (Active Streams) algorithm.
// PINNING ENFORCEMENT: GetClient MUST be called exactly once per incoming connection (e.g. SOCKS5 dial),
// and the chosen client must be used for the entirety of that specific io.Copy lifecycle.
func (c *Client) GetClient() (*PooledClient, int) {
	var bestClient *PooledClient
	var bestIdx int
	var minStreams int32 = -1

	// Attempt to find the least loaded healthy client
	for i, pc := range c.pool {
		failures := atomic.LoadUint32(&pc.failureCount)
		if failures >= c.Config.HardResetThreshold {
			continue // Skip dead/degraded clients according to Watchdog
		}

		active := pc.activeStreams.Load()
		if minStreams == -1 || active < minStreams {
			bestClient = pc
			bestIdx = i
			minStreams = active
		}
	}

	// Fallback: If all clients are marked degraded (e.g. widespread network drop),
	// we still must pick the one with the least active streams to distribute load.
	if bestClient == nil && len(c.pool) > 0 {
		for i, pc := range c.pool {
			active := pc.activeStreams.Load()
			if minStreams == -1 || active < minStreams {
				bestClient = pc
				bestIdx = i
				minStreams = active
			}
		}
	}

	return bestClient, bestIdx
}

// Dial initiates a tunnel for a specific protocol.
// It connects to the server and returns the stream to be used by the local listener.
func (c *Client) Dial(proto protocol.ProtocolType, target string) (io.ReadWriteCloser, error) {
	// Select connection from pool via Least-Loaded
	pc, poolIdx := c.GetClient()

	pc.mu.RLock()
	httpClient := pc.client
	pc.mu.RUnlock()

	// We use io.Pipe to bridge the local connection to the request body.
	pr, pw := io.Pipe()

	req, err := http.NewRequest("POST", c.Scheme+"://"+c.Config.RemoteAddr, pr)
	if err != nil {
		return nil, err
	}

	// Set headers
	req.Header.Set("X-Nerve-Protocol", string(proto))
	if target != "" {
		req.Header.Set("X-Nerve-Target", target)
	}

	respChan := make(chan *http.Response, 1)
	errChan := make(chan error, 1)

	go func() {
		// Use the selected client instance
		resp, err := httpClient.Do(req)
		if err != nil {
			errChan <- err
			return
		}
		respChan <- resp
	}()

	select {
	case resp := <-respChan:
		// Connection Successful
		atomic.StoreUint32(&pc.failureCount, 0) // Reset failure count

		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, fmt.Errorf("server rejected connection with status: %d", resp.StatusCode)
		}

		// Dial successful, stream starts. Hook: Add(1) to the active streams for this pooled client.
		pc.activeStreams.Add(1)

		return &Stream{
			Writer: pw,
			Reader: resp.Body,
			Closer: resp.Body,
			onClose: func() {
				// Hook: Done() / Add(-1) when the stream closes
				pc.activeStreams.Add(-1)
			},
		}, nil

	case err := <-errChan:
		c.handleConnectionFailure(pc, poolIdx, err)
		return nil, err

	case <-time.After(10 * time.Second):
		err := fmt.Errorf("connection to server timed out")
		c.handleConnectionFailure(pc, poolIdx, err)
		return nil, err
	}
}

// handleConnectionFailure increments failure count for a specific pooled client and triggers a rebuild if needed.
func (c *Client) handleConnectionFailure(pc *PooledClient, index int, err error) {
	newCount := atomic.AddUint32(&pc.failureCount, 1)
	log.Printf("Connection Error [Pool-%d] (%d/%d): %v", index, newCount, c.Config.HardResetThreshold, err)

	if newCount >= c.Config.HardResetThreshold {
		c.resetPooledClient(pc, index)
	}
}

// resetPooledClient destroys a degraded HTTP connection within the pool and creates a fresh one.
func (c *Client) resetPooledClient(pc *PooledClient, index int) {
	pc.mu.Lock()
	defer pc.mu.Unlock()

	// Debounce: Check if we reset recently
	debounceDuration := time.Duration(c.Config.HardResetDebounce) * time.Second
	if time.Since(pc.lastReset) < debounceDuration {
		// Reset already happened recently. Just ensure failure count is low and return.
		atomic.StoreUint32(&pc.failureCount, 0)
		return
	}

	log.Printf("[Watchdog] Connection index %d degraded. Rebuilding...", index)

	// Close old connections to free resources
	if pc.client != nil {
		pc.client.CloseIdleConnections()
	}

	// Create new client specifically for this array index
	pc.client = c.createHTTPClient()

	// Update timestamp and reset failure count
	pc.lastReset = time.Now()
	atomic.StoreUint32(&pc.failureCount, 0)

	// Minimal Backoff
	time.Sleep(1 * time.Second)
	log.Printf("[Watchdog] Connection index %d re-initialized.", index)
}

// Stream wraps the pipe endpoint to implement io.ReadWriteCloser.
// It also acts as the wrapper to enforce decrementing active_streams on closure.
type Stream struct {
	io.Writer
	io.Reader
	io.Closer
	onClose func()
	closed  atomic.Bool
}

func (s *Stream) Close() error {
	// Ensure we only decrement once even if Close is called multiple times
	if s.closed.CompareAndSwap(false, true) && s.onClose != nil {
		s.onClose()
	}
	s.Closer.Close()
	if w, ok := s.Writer.(io.Closer); ok {
		w.Close()
	}
	return nil
}
