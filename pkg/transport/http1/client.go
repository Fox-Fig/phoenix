package http1

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"sync"
	"time"

	"phoenix/pkg/config"
	"phoenix/pkg/protocol"
	"phoenix/pkg/underlay"
)

type Client struct {
	Config     *config.ClientConfig
	httpClient *http.Client
	clientID   string
	scheme     string
	
	streamsMu sync.RWMutex
	streams   map[string]*VirtualStream

	ctx       context.Context
	cancel    context.CancelFunc
}

func NewClient(cfg *config.ClientConfig) *Client {
	ctx, cancel := context.WithCancel(context.Background())
	// Generate random ClientID for this session
	idBuf := make([]byte, 16)
	rand.Read(idBuf)
	
	tlsEnabled := cfg.TLSMode != "" || cfg.PrivateKeyPath != "" || cfg.ServerPublicKey != ""
	scheme := "http"
	if tlsEnabled {
		scheme = "https"
	}

	c := &Client{
		Config:   cfg,
		clientID: hex.EncodeToString(idBuf),
		streams:  make(map[string]*VirtualStream),
		ctx:      ctx,
		cancel:   cancel,
		scheme:   scheme,
	}

	// Create Underlay Dialer
	underlayCfg := underlay.ClientConfig{
		TLSEnabled:      tlsEnabled,
		TLSMode:         cfg.TLSMode,
		Fingerprint:     cfg.Fingerprint,
		CustomSNI:       cfg.CustomSNI,
		ServerPublicKey: cfg.ServerPublicKey,
		PrivateKeyPath:  cfg.PrivateKeyPath,
		NextProtos:      []string{"http/1.1"},
	}

	tr := &http.Transport{
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   100,
		IdleConnTimeout:       90 * time.Second,
		ForceAttemptHTTP2:     false, // We strictly use HTTP/1.1
		ExpectContinueTimeout: 1 * time.Second,
	}

	if tlsEnabled {
		tr.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return underlay.Dial(cfg.RemoteAddr, underlayCfg)
		}
	} else {
		tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return underlay.Dial(cfg.RemoteAddr, underlayCfg)
		}
	}

	c.httpClient = &http.Client{
		Transport: tr,
		// No timeout, we handle it via contexts and Long-Polling logic
	}

	// Start Downlink loops
	// 2 parallel loops are enough for high throughput while keeping connection count low
	for i := 0; i < 2; i++ {
		go c.downlinkLoop()
	}

	return c
}

func (c *Client) Dial(innerProtocol protocol.ProtocolType, target string) (io.ReadWriteCloser, error) {
	// Generate Stream ID
	buf := make([]byte, 16)
	rand.Read(buf)
	streamID := hex.EncodeToString(buf)

	// Send Init request to Server
	req, err := http.NewRequest("POST", c.getRandomURL(), bytes.NewReader(nil))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+streamID)
	req.Header.Set("X-Client-ID", c.clientID)
	req.Header.Set("X-Phoenix-Init", "1")
	req.Header.Set("X-Protocol", string(innerProtocol))
	req.Header.Set("X-Target", target)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http1 dial init failed: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("http1 dial rejected with status: %v", resp.StatusCode)
	}

	writeFunc := func(data []byte) (int, error) {
		req, err := http.NewRequest(c.getRandomMethod(), c.getRandomURL(), bytes.NewReader(data))
		if err != nil {
			return 0, err
		}
		req.Header.Set("Authorization", "Bearer "+streamID)
		req.Header.Set("X-Client-ID", c.clientID)
		req.Header.Set("Content-Type", "application/octet-stream")

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return 0, err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return 0, fmt.Errorf("uplink rejected: %d", resp.StatusCode)
		}
		return len(data), nil
	}

	closeFunc := func() error {
		c.streamsMu.Lock()
		delete(c.streams, streamID)
		c.streamsMu.Unlock()

		req, err := http.NewRequest("DELETE", c.getRandomURL(), nil)
		if err == nil {
			req.Header.Set("Authorization", "Bearer "+streamID)
			req.Header.Set("X-Client-ID", c.clientID)
			resp, err := c.httpClient.Do(req)
			if err == nil {
				resp.Body.Close()
			}
		}
		return nil
	}

	vs := NewVirtualStream(streamID, innerProtocol, target, writeFunc, closeFunc)
	c.streamsMu.Lock()
	c.streams[streamID] = vs
	c.streamsMu.Unlock()

	return vs, nil
}

func (c *Client) Close() error {
	c.cancel()
	c.httpClient.CloseIdleConnections()
	return nil
}

func (c *Client) downlinkLoop() {
	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}

		req, err := http.NewRequestWithContext(c.ctx, "GET", c.getRandomURL(), nil)
		if err != nil {
			time.Sleep(1 * time.Second)
			continue
		}
		req.Header.Set("X-Phoenix-Sync", "1")
		req.Header.Set("X-Client-ID", c.clientID)
		// The server uses long-polling and blocks until it has data

		resp, err := c.httpClient.Do(req)
		if err != nil {
			time.Sleep(1 * time.Second)
			continue
		}

		if resp.StatusCode == http.StatusNoContent {
			resp.Body.Close()
			continue
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			time.Sleep(1 * time.Second)
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil || len(body) == 0 {
			// empty body means timeout or no data, just loop
			continue
		}

		msgs, err := DecodeDownlink(body)
		if err != nil {
			continue
		}

		c.streamsMu.RLock()
		for _, msg := range msgs {
			if len(msg.Data) == 0 {
				// Special empty data means Server closed the stream
				if vs, ok := c.streams[msg.StreamID]; ok {
					vs.MarkClosed()
				}
				continue
			}
			if vs, ok := c.streams[msg.StreamID]; ok {
				vs.PushData(msg.Data)
			}
		}
		c.streamsMu.RUnlock()
	}
}

func (c *Client) getRandomURL() string {
	paths := c.Config.APIPaths
	if len(paths) == 0 {
		return c.scheme + "://" + c.Config.RemoteAddr + "/api/v1/sync"
	}
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(paths))))
	return c.scheme + "://" + c.Config.RemoteAddr + paths[n.Int64()]
}

func (c *Client) getRandomMethod() string {
	methods := []string{"POST", "PUT", "PATCH"}
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(methods))))
	return methods[n.Int64()]
}
