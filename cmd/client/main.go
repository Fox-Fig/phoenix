package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"phoenix/pkg/adapter/socks5"
	"phoenix/pkg/config"
	"phoenix/pkg/crypto"
	"phoenix/pkg/protocol"
	"phoenix/pkg/transport"
	"sync"
	"syscall"
)

// PhoenixTunnelDialer implements socks5.Dialer by tunneling h2c
type PhoenixTunnelDialer struct {
	Client *transport.Client
	Proto  protocol.ProtocolType
}

func (d *PhoenixTunnelDialer) Dial(target string) (io.ReadWriteCloser, error) {
	proto := d.Proto
	if target == "udp-tunnel" {
		proto = protocol.ProtocolSOCKS5UDP
		target = ""
	}
	return d.Client.Dial(proto, target)
}

func main() {
	configPath := flag.String("config", "client.toml", "Path to client configuration file")
	getSS := flag.Bool("get-ss", false, "Generate Shadowsocks config from client config")
	genKeys := flag.Bool("gen-keys", false, "Generate a new pair of Ed25519 keys (public/private)")
	genToken := flag.Bool("gen-token", false, "Generate a secure random auth token")
	flag.Parse()

	if *genToken {
		token, err := crypto.GenerateToken()
		if err != nil {
			log.Fatalf("Failed to generate token: %v", err)
		}
		fmt.Println("=== Phoenix Token Generator ===")
		fmt.Println("Auth Token (add to both server and client config):")
		fmt.Println(token)
		return
	}

	if *genKeys {
		priv, pub, err := crypto.GenerateKeypair()
		if err != nil {
			log.Fatalf("Failed to generate keys: %v", err)
		}
		if err := os.WriteFile("client_private.key", priv, 0600); err != nil {
			log.Fatalf("Failed to save private key: %v", err)
		}
		fmt.Printf("Client Keys generated successfully.\n")
		fmt.Printf("Private Key: client_private.key (Keep this secret!)\n")
		fmt.Printf("Public Key:  %s (Add this to Server's authorized_clients)\n", pub)
		return
	}

	cfg, err := config.LoadClientConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	if *getSS {
		generateShadowsocksConfig(cfg)
		return
	}

	client := transport.NewClient(cfg)
	log.Printf("Phoenix Client started. Connecting to %s", cfg.RemoteAddr)

	var wg sync.WaitGroup

	for _, inbound := range cfg.Inbounds {
		wg.Add(1)
		go func(in config.ClientInbound) {
			defer wg.Done()
			startInbound(client, in)
		}(inbound)
	}

	// Capture interrupt signal for graceful shutdown
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		log.Println("Shutting down...")
		os.Exit(0)
	}()

	wg.Wait()
}

func generateShadowsocksConfig(cfg *config.ClientConfig) {
	found := false
	for _, in := range cfg.Inbounds {
		if in.Protocol == protocol.ProtocolShadowsocks {
			found = true
			if in.Auth == "" {
				fmt.Println("Error: Shadowsocks inbound found but 'auth' (method:password) is empty.")
				continue
			}
			// Encode UserInfo
			userInfo := base64.URLEncoding.EncodeToString([]byte(in.Auth))
			// Construct Link
			// ss://userInfo@host:port#Phoenix
			link := fmt.Sprintf("ss://%s@%s#Phoenix-Client", userInfo, in.LocalAddr)
			fmt.Println("Shadowsocks Configuration:")
			fmt.Println(link)
		}
	}
	if !found {
		fmt.Println("No Shadowsocks inbound found in configuration.")
	}
}

func startInbound(client *transport.Client, in config.ClientInbound) {
	ln, err := net.Listen("tcp", in.LocalAddr)
	if err != nil {
		log.Printf("Failed to listen on %s: %v", in.LocalAddr, err)
		return
	}
	log.Printf("Listening on %s (%s)", in.LocalAddr, in.Protocol)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("Accept error on %s: %v", in.LocalAddr, err)
			continue
		}

		go handleConnection(client, in, conn)
	}
}

func handleConnection(client *transport.Client, in config.ClientInbound, conn net.Conn) {
	// Connection requires closing. The handlers below should handle closing or we do it here.
	// socks5.HandleConnection closes the conn.
	// ssh.HandleConnection closes the conn.
	// We should be careful not to double close or leak.

	switch in.Protocol {
	case protocol.ProtocolSOCKS5:
		// Client acts as SOCKS5 server for local apps.
		// It performs handshake, extracts target, then Dials server with target.
		dialer := &PhoenixTunnelDialer{
			Client: client,
			Proto:  protocol.ProtocolSOCKS5,
		}
		// Wrap conn to io.ReadWriteCloser to satisfy interface
		if err := socks5.HandleConnection(conn, dialer, in.EnableUDP); err != nil {
			log.Printf("SOCKS5 Handler Error: %v", err)
		}

	case protocol.ProtocolSSH:
		// SSH Tunneling.
		// If TargetAddr is specified, we Tunnel to that target.
		// If not, we Tunnel to Server (empty target).
		target := in.TargetAddr

		// Dial Server for Tunnel
		stream, err := client.Dial(protocol.ProtocolSSH, target)
		if err != nil {
			log.Printf("Failed to dial server: %v", err)
			conn.Close()
			return
		}

		// Bridge connections
		// ssh.HandleConnection bridges (ReadWriteCloser, target) but here we have TWO conns.
		// We can reuse the Copy logic.
		// Wait, ssh.HandleConnection expects (stream, target) where `stream` is the connection to proxy.
		// And `ssh.HandleConnection` dials `target` itself.
		// That logic is for SERVER side (or direct client side) dialing.
		// Here we already dialed the Server stream.
		// We just need to copy conn <-> stream.

		go func() {
			defer conn.Close()
			defer stream.Close()
			io.Copy(conn, stream)
		}()
		go func() {
			defer conn.Close()
			defer stream.Close()
			io.Copy(stream, conn)
		}()

	case protocol.ProtocolShadowsocks:
		// Shadowsocks Inbound.
		// Simplest: Blind forward to Server.
		// Assuming Server expects encrypted stream.
		stream, err := client.Dial(protocol.ProtocolShadowsocks, in.TargetAddr)
		if err != nil {
			log.Printf("Failed to dial server: %v", err)
			conn.Close()
			return
		}
		go func() {
			defer conn.Close()
			defer stream.Close()
			io.Copy(conn, stream)
		}()
		go func() {
			defer conn.Close()
			defer stream.Close()
			io.Copy(stream, conn)
		}()

	default:
		log.Printf("Unknown protocol inbound: %s", in.Protocol)
		conn.Close()
	}
}
