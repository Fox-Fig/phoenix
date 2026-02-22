package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"phoenix/pkg/config"
	"phoenix/pkg/crypto"
	"phoenix/pkg/protocol"
	"phoenix/pkg/transport"
	"time"
)

func main() {
	// Start shared Echo, Sink, and Source servers
	echoAddr := startEchoServer()
	sinkAddr := startSinkServer()
	sourceAddr := startSourceServer(100 * 1024 * 1024) // 100MB

	time.Sleep(500 * time.Millisecond)

	// ========================================
	// Phase 1: Direct (No Token, h2c)
	// ========================================
	fmt.Println("\n====================================")
	fmt.Println("  PHASE 1: Direct (h2c, No Token)")
	fmt.Println("====================================")

	serverAddr1 := findFreeAddr()
	serverCfg1 := config.DefaultServerConfig()
	serverCfg1.ListenAddr = serverAddr1
	serverCfg1.Security.EnableSOCKS5 = true
	serverCfg1.Security.EnableSSH = true

	clientCfg1 := config.DefaultClientConfig()
	clientCfg1.RemoteAddr = serverAddr1

	runBenchmark("Direct", serverCfg1, clientCfg1, echoAddr, sinkAddr, sourceAddr)

	// ========================================
	// Phase 2: Token Auth (h2c + Token)
	// ========================================
	fmt.Println("\n====================================")
	fmt.Println("  PHASE 2: Token Auth (h2c)")
	fmt.Println("====================================")

	token, _ := crypto.GenerateToken()
	serverAddr2 := findFreeAddr()

	serverCfg2 := config.DefaultServerConfig()
	serverCfg2.ListenAddr = serverAddr2
	serverCfg2.Security.EnableSOCKS5 = true
	serverCfg2.Security.EnableSSH = true
	serverCfg2.Security.AuthToken = token

	clientCfg2 := config.DefaultClientConfig()
	clientCfg2.RemoteAddr = serverAddr2
	clientCfg2.AuthToken = token

	runBenchmark("Token Auth", serverCfg2, clientCfg2, echoAddr, sinkAddr, sourceAddr)

	fmt.Println("\n====================================")
	fmt.Println("  ALL BENCHMARKS COMPLETE ✓")
	fmt.Println("====================================")

	os.Exit(0)
}

func runBenchmark(name string, serverCfg *config.ServerConfig, clientCfg *config.ClientConfig, echoAddr, sinkAddr, sourceAddr string) {
	// Start server
	go func() {
		if err := transport.StartServer(serverCfg); err != nil {
			log.Printf("[%s] Server error: %v", name, err)
		}
	}()
	time.Sleep(1 * time.Second)

	// Create client
	client := transport.NewClient(clientCfg)
	dataSize := 100 * 1024 * 1024 // 100MB
	chunk := make([]byte, 32*1024)

	// --- Upload Test (Client -> Sink via Server) ---
	fmt.Printf("[%s] Upload Speed Test (100MB)...\n", name)
	start := time.Now()
	upStream, err := client.Dial(protocol.ProtocolSSH, sinkAddr)
	if err != nil {
		log.Fatalf("[%s] Upload Dial failed: %v", name, err)
	}
	totalWritten := 0
	for totalWritten < dataSize {
		n, err := upStream.Write(chunk)
		if err != nil {
			log.Fatalf("[%s] Upload Write failed: %v", name, err)
		}
		totalWritten += n
	}
	upDuration := time.Since(start)
	upMBs := float64(dataSize) / 1024 / 1024 / upDuration.Seconds()
	fmt.Printf("[%s] Upload Speed:   %.2f MB/s\n", name, upMBs)
	upStream.Close()

	// --- Download Test (Client <- Source via Server) ---
	fmt.Printf("[%s] Download Speed Test (100MB)...\n", name)
	start = time.Now()
	downStream, err := client.Dial(protocol.ProtocolSSH, sourceAddr)
	if err != nil {
		log.Fatalf("[%s] Download Dial failed: %v", name, err)
	}
	received, _ := io.Copy(io.Discard, downStream)
	downDuration := time.Since(start)
	downMBs := float64(received) / 1024 / 1024 / downDuration.Seconds()
	fmt.Printf("[%s] Download Speed: %.2f MB/s\n", name, downMBs)

	// --- Latency Test ---
	start = time.Now()
	pingStream, err := client.Dial(protocol.ProtocolSSH, echoAddr)
	if err != nil {
		log.Fatalf("[%s] Latency Dial failed: %v", name, err)
	}
	pingStream.Write([]byte("ping"))
	buf := make([]byte, 4)
	pingStream.Read(buf)
	latency := time.Since(start)
	fmt.Printf("[%s] Latency (RTT):  %v\n", name, latency)
	pingStream.Close()
}

// ========================================
// Helper Servers
// ========================================

func startEchoServer() string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go io.Copy(c, c)
		}
	}()
	return ln.Addr().String()
}

func startSinkServer() string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go io.Copy(io.Discard, c)
		}
	}()
	return ln.Addr().String()
}

func startSourceServer(limit int) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				data := make([]byte, 32*1024)
				written := 0
				for written < limit {
					n, err := conn.Write(data)
					if err != nil {
						return
					}
					written += n
				}
			}(c)
		}
	}()
	return ln.Addr().String()
}

func findFreeAddr() string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	return addr
}
