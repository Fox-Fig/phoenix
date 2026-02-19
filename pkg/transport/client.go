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
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"
)

// Client handles outgoing connections to the Server.
type Client struct {
	Config       *config.ClientConfig
	Client       *http.Client
	Scheme       string
	failureCount uint32 // Atomic counter
}

// NewClient creates a new Phoenix client instance.
func NewClient(cfg *config.ClientConfig) *Client {
	var tr *http2.Transport
	scheme := "http"

	// Check if Secure Mode is requested (mTLS or One-Way TLS)
	// Requires either PrivateKey (mTLS) OR ServerPublicKey (One-Way)
	if cfg.PrivateKeyPath != "" || cfg.ServerPublicKey != "" {
		log.Println("Initializing Client in SECURE mode (TLS)")
		scheme = "https"

		var certs []tls.Certificate
		if cfg.PrivateKeyPath != "" {
			priv, err := crypto.LoadPrivateKey(cfg.PrivateKeyPath)
			if err != nil {
				log.Fatalf("Failed to load private key: %v", err)
			}
			cert, err := crypto.GenerateTLSCertificate(priv)
			if err != nil {
				log.Fatalf("Failed to generate TLS cert: %v", err)
			}
			certs = []tls.Certificate{cert}
		} else {
			log.Println("No private_key provided. Using One-Way TLS (Anonymous Client).")
		}

		tlsConfig := &tls.Config{
			Certificates:       certs,
			InsecureSkipVerify: true, // We use custom verification
			VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
				if cfg.ServerPublicKey == "" {
					// Pinning disabled. Insecure against MITM.
					// Allow it? For "easy setup"? User requested "security multiplied".
					// But we will allow it with warning if user explicitly omits key.
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
				if pubStr != cfg.ServerPublicKey {
					return fmt.Errorf("server key verification failed. Expected %s, Got %s", cfg.ServerPublicKey, pubStr)
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
		log.Println("Initializing Client in INSECURE mode (h2c)")
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

	return &Client{
		Config: cfg,
		Client: &http.Client{Transport: tr},
		Scheme: scheme,
	}
}

// Dial initiates a tunnel for a specific protocol.
// It connects to the server and returns the stream to be used by the local listener.
func (c *Client) Dial(proto protocol.ProtocolType, target string) (io.ReadWriteCloser, error) {
	// Circuit Breaker Check (Optional: Fail fast if in recovery state? No, let's try)

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
		resp, err := c.Client.Do(req)
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

// handleConnectionFailure increments failure count and forces reconnect if threshold exceeded.
func (c *Client) handleConnectionFailure(err error) {
	newCount := atomic.AddUint32(&c.failureCount, 1)
	log.Printf("Connection Error (%d/3): %v", newCount, err)

	if newCount >= 3 {
		log.Println("WARNING: Connection unstable (3 consecutive failures). Forcing transport reset...")

		// Force Close Idle Connections to drop zombie TCP connections
		c.Client.CloseIdleConnections()

		// Reset counter immediate or after backoff?
		// We reset it so next try starts fresh.
		atomic.StoreUint32(&c.failureCount, 0)

		// Backoff to prevent spinning
		time.Sleep(1 * time.Second)
	}
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
