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

// Client handles outgoing connections to the Server.
type Client struct {
	Config       *config.ClientConfig
	httpClient   *http.Client // Internal HTTP client (protected by mu)
	Scheme       string
	failureCount uint32       // Atomic counter
	mu           sync.RWMutex // Protects httpClient
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

	// Initialize the first HTTP client
	c.httpClient = c.createHTTPClient()
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

// Dial initiates a tunnel for a specific protocol.
// It connects to the server and returns the stream to be used by the local listener.
func (c *Client) Dial(proto protocol.ProtocolType, target string) (io.ReadWriteCloser, error) {
	// Get current HTTP client (Read Lock)
	c.mu.RLock()
	client := c.httpClient
	c.mu.RUnlock()

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
		// Use the captured client instance
		resp, err := client.Do(req)
		if err != nil {
			errChan <- err
			return
		}
		respChan <- resp
	}()

	select {
	case resp := <-respChan:
		// Connection Successful
		atomic.StoreUint32(&c.failureCount, 0) // Reset failure count

		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, fmt.Errorf("server rejected connection with status: %d", resp.StatusCode)
		}
		return &Stream{
			Writer: pw,
			Reader: resp.Body,
			Closer: resp.Body,
		}, nil

	case err := <-errChan:
		c.handleConnectionFailure(err)
		return nil, err

	case <-time.After(10 * time.Second):
		err := fmt.Errorf("connection to server timed out")
		c.handleConnectionFailure(err)
		return nil, err
	}
}

// handleConnectionFailure increments failure count and triggers Hard Reset if needed.
func (c *Client) handleConnectionFailure(err error) {
	newCount := atomic.AddUint32(&c.failureCount, 1)
	log.Printf("Connection Error (%d/3): %v", newCount, err)

	if newCount >= 3 {
		c.resetClient()
	}
}

// resetClient destroys the old HTTP connection and creates a fresh one.
func (c *Client) resetClient() {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Double check failure count (optimization)
	// If reset already happened, count might be 0 or low.
	// But we aggressively reset if called.

	log.Println("WARNING: Network unstable. Destroying and recreating HTTP client (Hard Reset)...")

	// Close old connections to free resources
	if c.httpClient != nil {
		c.httpClient.CloseIdleConnections()
	}

	// Create new client
	// Note: Creating new http.Client creates new Transport, which creates new TCP connection pool.
	c.httpClient = c.createHTTPClient()

	// Reset failure count
	atomic.StoreUint32(&c.failureCount, 0)

	// Backoff
	time.Sleep(2 * time.Second)
	log.Println("Client re-initialized. Ready for new connections.")
}

// Stream wraps the pipe endpoint to implement io.ReadWriteCloser.
type Stream struct {
	io.Writer
	io.Reader
	io.Closer
}

func (s *Stream) Close() error {
	s.Closer.Close()
	if w, ok := s.Writer.(io.Closer); ok {
		w.Close()
	}
	return nil
}
