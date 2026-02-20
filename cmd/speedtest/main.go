package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"phoenix/pkg/config"
	"phoenix/pkg/protocol"
	"phoenix/pkg/transport"
	"time"
)

func main() {
	// 1. Setup Server
	serverPort := "127.0.0.1:0"
	l, err := net.Listen("tcp", serverPort)
	if err != nil {
		log.Fatal(err)
	}
	serverAddr := l.Addr().String()
	l.Close() // Close to allow server to listen

	serverCfg := config.DefaultServerConfig()
	serverCfg.ListenAddr = serverAddr
	serverCfg.Security.EnableSOCKS5 = true
	serverCfg.Security.EnableSSH = true

	go func() {
		if err := transport.StartServer(serverCfg); err != nil {
			log.Printf("Server error: %v", err)
		}
	}()

	// Wait for server to start
	time.Sleep(1 * time.Second)

	// Start a local Echo Server (Target)
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	echoAddr := echoLn.Addr().String()
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go io.Copy(c, c) // Echo
		}
	}()

	// Sink Server
	sinkLn, _ := net.Listen("tcp", "127.0.0.1:0")
	sinkAddr := sinkLn.Addr().String()
	go func() {
		for {
			c, _ := sinkLn.Accept()
			if c == nil {
				continue
			}
			go io.Copy(io.Discard, c)
		}
	}()

	// Source Server
	sourceLn, _ := net.Listen("tcp", "127.0.0.1:0")
	sourceAddr := sourceLn.Addr().String()
	go func() {
		for {
			c, _ := sourceLn.Accept()
			if c == nil {
				continue
			}
			go func(conn net.Conn) {
				// Generate 100MB
				data := make([]byte, 32*1024)
				limit := 100 * 1024 * 1024
				written := 0
				for written < limit {
					n, _ := conn.Write(data)
					written += n
				}
				conn.Close()
			}(c)
		}
	}()

	dataSize := 100 * 1024 * 1024 // 100MB

	// Test with PoolSize = 1
	runSpeedTest(serverAddr, 1, echoAddr, sinkAddr, sourceAddr, dataSize)

	// Test with PoolSize = 5
	runSpeedTest(serverAddr, 5, echoAddr, sinkAddr, sourceAddr, dataSize)

	os.Exit(0)
}

func runSpeedTest(serverAddr string, poolSize int, echoAddr, sinkAddr, sourceAddr string, dataSize int) {
	fmt.Printf("\n=== Testing with PoolSize = %d ===\n", poolSize)
	clientCfg := config.DefaultClientConfig()
	clientCfg.RemoteAddr = serverAddr
	clientCfg.PoolSize = poolSize

	client := transport.NewClient(clientCfg)

	// Pure Upload
	start := time.Now()
	chunk := make([]byte, 32*1024)
	upStream, _ := client.Dial(protocol.ProtocolSSH, sinkAddr)
	totalWritten := 0
	for totalWritten < dataSize {
		n, _ := upStream.Write(chunk)
		totalWritten += n
	}
	upDuration := time.Since(start)
	upMbps := float64(dataSize) / 1024 / 1024 / upDuration.Seconds()
	fmt.Printf("Upload Speed (%d Pool): %.2f MB/s\n", poolSize, upMbps)
	upStream.Close()

	// Pure Download
	start = time.Now()
	downStream, _ := client.Dial(protocol.ProtocolSSH, sourceAddr)
	received, _ := io.Copy(io.Discard, downStream)
	downDuration := time.Since(start)
	downMbps := float64(received) / 1024 / 1024 / downDuration.Seconds()
	fmt.Printf("Download Speed (%d Pool): %.2f MB/s\n", poolSize, downMbps)

	// Latency
	start = time.Now()
	pingStream, _ := client.Dial(protocol.ProtocolSSH, echoAddr)
	pingStream.Write([]byte("ping"))
	buf := make([]byte, 4)
	pingStream.Read(buf)
	latency := time.Since(start)
	fmt.Printf("Latency (RTT) (%d Pool): %v\n", poolSize, latency)
	pingStream.Close()
}
