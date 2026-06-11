package h2

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"math"
	"math/rand"
	"net"
	"net/http"
	"phoenix/pkg/config"
	"phoenix/pkg/protocol"
	"phoenix/pkg/underlay"
	"sync"
	"time"

	"golang.org/x/net/http2"
)

// Client handles outgoing connections to the Server.
type Client struct {
	Config       *config.ClientConfig
	httpClient   *http.Client // Internal HTTP client (protected by mu)
	Scheme          string
	errorTimestamps []time.Time  // Tracks error times within the error window
	resetAttempts   int          // Tracks consecutive resets for exponential backoff
	mu              sync.RWMutex // Protects httpClient and recovery state
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

// createHTTPClient creates a fresh http.Client based on configuration.
func (c *Client) createHTTPClient() *http.Client {
	underlayCfg := underlay.ClientConfig{
		TLSEnabled:      c.Config.TLSMode != "" || c.Config.PrivateKeyPath != "" || c.Config.ServerPublicKey != "",
		TLSMode:         c.Config.TLSMode,
		Fingerprint:     c.Config.Fingerprint,
		CustomSNI:       c.Config.CustomSNI,
		ServerPublicKey: c.Config.ServerPublicKey,
		PrivateKeyPath:  c.Config.PrivateKeyPath,
		NextProtos:      []string{"h2"},
	}

	tr := &http2.Transport{
		AllowHTTP: !underlayCfg.TLSEnabled,
		DialTLS: func(network, addr string, cfg *tls.Config) (net.Conn, error) {
			return underlay.Dial(addr, underlayCfg)
		},
		StrictMaxConcurrentStreams: true,
		ReadIdleTimeout:            0,
		PingTimeout:                5 * time.Second,
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
		c.mu.Lock()
		c.resetAttempts = 0
		c.mu.Unlock()

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

// calculateJitterBackoff computes the delay using AWS full jitter formula.
func (c *Client) calculateJitterBackoff() time.Duration {
	base := float64(c.Config.Recovery.BackoffBaseMs)
	capMs := float64(c.Config.Recovery.BackoffCapMs)
	
	maxSleepMs := base * math.Pow(2, float64(c.resetAttempts))
	if maxSleepMs > capMs {
		maxSleepMs = capMs
	}
	
	if !c.Config.Recovery.BackoffJitter {
		return time.Duration(maxSleepMs) * time.Millisecond
	}
	
	sleepMs := rand.Float64() * maxSleepMs
	return time.Duration(sleepMs) * time.Millisecond
}

// handleConnectionFailure tracks error windows and triggers Hard Reset if needed.
func (c *Client) handleConnectionFailure(err error) {
	if !c.Config.Recovery.Enabled {
		log.Printf("Connection Error (Recovery disabled): %v", err)
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
		c.errorTimestamps = nil // Clear so we don't trigger again immediately
	}
	c.mu.Unlock()

	log.Printf("Connection Error (%d/%d in %ds window): %v", errCount, c.Config.Recovery.ErrorThreshold, c.Config.Recovery.ErrorWindowS, err)

	if triggerReset {
		c.resetClient()
	}
}

// resetClient destroys the old HTTP connection and creates a fresh one with backoff.
func (c *Client) resetClient() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.resetAttempts++
	backoffDelay := c.calculateJitterBackoff()

	log.Printf("WARNING: Network unstable. Destroying HTTP client. Backoff %v before reconnect...", backoffDelay)

	// Close old connections to free resources
	if c.httpClient != nil {
		c.httpClient.CloseIdleConnections()
	}

	// Backoff before dialing (holds the lock to freeze new Dial attempts)
	time.Sleep(backoffDelay)

	// Create new client
	c.httpClient = c.createHTTPClient()
	
	log.Printf("Client re-initialized (Attempt %d). Ready for new connections.", c.resetAttempts)
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

// Close gracefully shuts down the HTTP/2 client connections.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.httpClient != nil {
		c.httpClient.CloseIdleConnections()
	}
	return nil
}
