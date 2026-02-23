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

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

// Client handles outgoing connections to the Server.
type Client struct {
	Config       *config.ClientConfig
	httpClient   *http.Client // Internal HTTP client (protected by mu)
	Scheme       string
	failureCount uint32       // Atomic counter
	mu           sync.RWMutex // Protects httpClient
	lastReset    time.Time    // Timestamp of last reset (for debounce)
}

// NewClient creates a new Phoenix client instance.
func NewClient(cfg *config.ClientConfig) *Client {
	c := &Client{
		Config: cfg,
	}

	// Initialize scheme based on config
	if cfg.TLSMode == "system" || cfg.TLSMode == "insecure" || cfg.PrivateKeyPath != "" || cfg.ServerPublicKey != "" {
		c.Scheme = "https"
	} else {
		c.Scheme = "http"
	}

	// Log security status
	c.logSecurityMode()

	// Initialize the first HTTP client
	c.httpClient = c.createHTTPClient()
	return c
}

// dialWithFingerprint dials a TLS connection using uTLS to spoof a browser fingerprint.
// If fingerprint is empty, falls back to standard Go TLS.
func dialWithFingerprint(network, addr string, tlsCfg *tls.Config, fingerprint string) (net.Conn, error) {
	if fingerprint == "" {
		// Standard TLS — no spoofing
		return tls.Dial(network, addr, tlsCfg)
	}

	rawConn, err := net.Dial(network, addr)
	if err != nil {
		return nil, err
	}

	// Extract host for SNI
	host, _, _ := net.SplitHostPort(addr)

	utlsCfg := &utls.Config{
		ServerName:         host,
		InsecureSkipVerify: tlsCfg != nil && tlsCfg.InsecureSkipVerify, //nolint:gosec
	}
	if tlsCfg != nil && tlsCfg.RootCAs != nil {
		utlsCfg.RootCAs = tlsCfg.RootCAs
	}

	uConn := utls.UClient(rawConn, utlsCfg, pickHelloID(fingerprint))
	if err := uConn.Handshake(); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("utls handshake failed: %v", err)
	}

	// If caller provided custom VerifyPeerCertificate, run it now
	if tlsCfg != nil && tlsCfg.VerifyPeerCertificate != nil {
		state := uConn.ConnectionState()
		rawCerts := make([][]byte, len(state.PeerCertificates))
		for i, c := range state.PeerCertificates {
			rawCerts[i] = c.Raw
		}
		if err := tlsCfg.VerifyPeerCertificate(rawCerts, nil); err != nil {
			uConn.Close()
			return nil, err
		}
	}

	return uConn, nil
}

// pickHelloID maps a fingerprint name to a uTLS ClientHelloID.
func pickHelloID(fp string) utls.ClientHelloID {
	switch fp {
	case "firefox":
		return utls.HelloFirefox_Auto
	case "safari":
		return utls.HelloSafari_Auto
	case "random":
		return utls.HelloRandomized
	default: // "chrome" or anything else
		return utls.HelloChrome_Auto
	}
}

// createHTTPClient creates a fresh http.Client based on configuration.
func (c *Client) createHTTPClient() *http.Client {
	var tr *http2.Transport

	// System TLS Mode (for CDN like Cloudflare)
	if c.Config.TLSMode == "system" {
		log.Println("[Transport] Creating SYSTEM TLS transport (System CA verification)")
		baseTLS := &tls.Config{}
		tr = &http2.Transport{
			DialTLS: func(network, addr string, cfg *tls.Config) (net.Conn, error) {
				return dialWithFingerprint(network, addr, baseTLS, c.Config.Fingerprint)
			},
			StrictMaxConcurrentStreams: true,
			ReadIdleTimeout:            0,
			PingTimeout:                5 * time.Second,
		}
	} else if c.Config.TLSMode == "insecure" {
		// Insecure TLS Mode: HTTPS but skip certificate verification.
		// Use for direct connections to servers with self-signed TLS certs.
		log.Println("[Transport] Creating INSECURE TLS transport (cert verification DISABLED)")
		baseTLS := &tls.Config{InsecureSkipVerify: true} //nolint:gosec
		tr = &http2.Transport{
			DialTLS: func(network, addr string, cfg *tls.Config) (net.Conn, error) {
				return dialWithFingerprint(network, addr, baseTLS, c.Config.Fingerprint)
			},
			StrictMaxConcurrentStreams: true,
			ReadIdleTimeout:            0,
			PingTimeout:                5 * time.Second,
		}
	} else if c.Config.PrivateKeyPath != "" || c.Config.ServerPublicKey != "" {
		// Phoenix Secure Mode (mTLS or One-Way TLS with Ed25519 pinning)
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
			DialTLS: func(network, addr string, _ *tls.Config) (net.Conn, error) {
				return dialWithFingerprint(network, addr, tlsConfig, c.Config.Fingerprint)
			},
			StrictMaxConcurrentStreams: true,
			ReadIdleTimeout:            0,
			PingTimeout:                5 * time.Second,
		}

	} else {
		// CLEARTEXT MODE (h2c)
		log.Println("[Transport] Creating CLEARTEXT transport (h2c)")
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

// logSecurityMode prints a human-readable security status at startup.
func (c *Client) logSecurityMode() {
	cfg := c.Config
	tokenStatus := "disabled"
	if cfg.AuthToken != "" {
		tokenStatus = "ENABLED"
	}

	fpStatus := "disabled"
	if cfg.Fingerprint != "" {
		fpStatus = cfg.Fingerprint
	}

	switch {
	case cfg.PrivateKeyPath != "" && len(cfg.ServerPublicKey) > 0:
		log.Printf("Security Mode: mTLS (Ed25519 key pinning) | Token Auth: %s | Fingerprint: %s", tokenStatus, fpStatus)
	case cfg.PrivateKeyPath != "" || cfg.ServerPublicKey != "":
		log.Printf("Security Mode: ONE-WAY TLS (Ed25519 key pinning) | Token Auth: %s | Fingerprint: %s", tokenStatus, fpStatus)
	case cfg.TLSMode == "system":
		log.Printf("Security Mode: SYSTEM TLS (System CA — use with CDN/Cloudflare) | Token Auth: %s | Fingerprint: %s", tokenStatus, fpStatus)
	case cfg.TLSMode == "insecure":
		log.Printf("Security Mode: INSECURE TLS (cert verify DISABLED) | Token Auth: %s | Fingerprint: %s", tokenStatus, fpStatus)
	default:
		log.Printf("Security Mode: CLEARTEXT h2c (no TLS) | Token Auth: %s", tokenStatus)
	}
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
	if c.Config.AuthToken != "" {
		req.Header.Set("X-Nerve-Token", c.Config.AuthToken)
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

	// Debounce: Check if we reset recently (e.g. within 5 seconds)
	if time.Since(c.lastReset) < 5*time.Second {
		// Reset already happened recently. Just ensure failure count is low and return.
		atomic.StoreUint32(&c.failureCount, 0)
		return
	}

	log.Println("WARNING: Network unstable. Destroying and recreating HTTP client (Hard Reset)...")

	// Close old connections to free resources
	if c.httpClient != nil {
		c.httpClient.CloseIdleConnections()
	}

	// Create new client
	// Note: Creating new http.Client creates new Transport, which creates new TCP connection pool.
	c.httpClient = c.createHTTPClient()

	// Update timestamp and reset failure count
	c.lastReset = time.Now()
	atomic.StoreUint32(&c.failureCount, 0)

	// Backoff
	time.Sleep(1 * time.Second)
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
