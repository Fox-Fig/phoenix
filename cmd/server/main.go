package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"phoenix/pkg/config"
	"phoenix/pkg/crypto"
	"phoenix/pkg/transport"
	"syscall"
)

func main() {
	configPath := flag.String("config", "server.toml", "Path to server configuration file")
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
		if err := os.WriteFile("private.key", priv, 0600); err != nil {
			log.Fatalf("Failed to save private key: %v", err)
		}
		fmt.Println("=== Phoenix Key Generator ===")
		fmt.Println("Private Key saved to: private.key")
		fmt.Println("Public Key (add this to config):")
		fmt.Println(pub)
		return
	}

	cfg, err := config.LoadServerConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Make sure security is strict by default if config is missing values
	log.Printf("Starting Phoenix Server on %s", cfg.ListenAddr)
	log.Printf("Enabled Protocols: SOCKS5=%v, Shadowsocks=%v, SSH=%v",
		cfg.Security.EnableSOCKS5,
		cfg.Security.EnableShadowsocks,
		cfg.Security.EnableSSH)

	go func() {
		if err := transport.StartServer(cfg); err != nil {
			log.Fatalf("Server failed: %v", err)
		}
	}()

	// Graceful shutdown
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c
	log.Println("Shutting down...")
	os.Exit(0)
}
