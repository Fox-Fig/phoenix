package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"phoenix/pkg/adapter/socks5"
	"phoenix/pkg/config"
	"phoenix/pkg/crypto"
	"phoenix/pkg/protocol"
	"phoenix/pkg/transport"
	"sync"
)

// PhoenixTunnelDialer implements socks5.Dialer by tunneling over HTTP/2.
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
	filesDir := flag.String("files-dir", ".", "Directory for writing key files (use Android Context.getFilesDir())")
	getSS := flag.Bool("get-ss", false, "Generate Shadowsocks config from client config")
	genKeys := flag.Bool("gen-keys", false, "Generate a new pair of Ed25519 keys (public/private)")
	flag.Parse()

	if *genKeys {
		priv, pub, err := crypto.GenerateKeypair()
		if err != nil {
			log.Fatalf("Failed to generate keys: %v", err)
		}
		keyPath := filepath.Join(*filesDir, "client_private.key")
		if err := os.WriteFile(keyPath, priv, 0600); err != nil {
			log.Fatalf("Failed to save private key: %v", err)
		}
		// Print to stdout so the Android Service can read the public key.
		fmt.Printf("KEY_PATH=%s\n", keyPath)
		fmt.Printf("PUBLIC_KEY=%s\n", pub)
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

	// Block until all inbounds exit (Android Service kills this process to stop).
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
			userInfo := base64.URLEncoding.EncodeToString([]byte(in.Auth))
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
	switch in.Protocol {
	case protocol.ProtocolSOCKS5:
		dialer := &PhoenixTunnelDialer{
			Client: client,
			Proto:  protocol.ProtocolSOCKS5,
		}
		if err := socks5.HandleConnection(conn, dialer, in.EnableUDP); err != nil {
			log.Printf("SOCKS5 Handler Error: %v", err)
		}

	case protocol.ProtocolSSH:
		target := in.TargetAddr
		stream, err := client.Dial(protocol.ProtocolSSH, target)
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

	case protocol.ProtocolShadowsocks:
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
