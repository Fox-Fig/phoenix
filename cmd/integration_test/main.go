package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"time"

	"phoenix/pkg/crypto"

	"golang.org/x/net/proxy"
)

// suiteConfig holds the parameters for a single test suite run.
type suiteConfig struct {
	Name           string
	ServerConfFile string
	ClientConfFile string
	ServerConf     string
	ClientConf     string
	SOCKS5Addr     string
	EchoTCPAddr    string
	EchoUDPPort    uint16
}

func main() {
	// 1. Build binaries
	log.Println("Building binaries...")
	cmd := exec.Command("make", "build")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Fatalf("Build failed: %v", err)
	}

	// 2. Start shared Echo Servers
	go startTCPEchoServer(":9001")
	go startUDPEchoServer(":9002")
	time.Sleep(500 * time.Millisecond)

	// ========================================
	// Phase 1: mTLS Direct
	// ========================================
	log.Println("\n====================================")
	log.Println("  PHASE 1: mTLS Direct Connection")
	log.Println("====================================")

	privServer, pubServer, _ := crypto.GenerateKeypair()
	privClient, pubClient, _ := crypto.GenerateKeypair()
	os.WriteFile("server.key", privServer, 0600)
	os.WriteFile("client.key", privClient, 0600)

	runSuite(suiteConfig{
		Name:           "mTLS",
		ServerConfFile: "test_server_mtls.toml",
		ClientConfFile: "test_client_mtls.toml",
		ServerConf: fmt.Sprintf(`
listen_addr = ":8080"
[security]
enable_socks5 = true
enable_udp = true
private_key = "server.key"
authorized_clients = ["%s"]
`, pubClient),
		ClientConf: fmt.Sprintf(`
remote_addr = "127.0.0.1:8080"
private_key = "client.key"
server_public_key = "%s"
[[inbounds]]
protocol = "socks5"
local_addr = "127.0.0.1:1080"
enable_udp = true
`, pubServer),
		SOCKS5Addr:  "127.0.0.1:1080",
		EchoTCPAddr: "127.0.0.1:9001",
		EchoUDPPort: 9002,
	})

	// Cleanup phase 1
	os.Remove("server.key")
	os.Remove("client.key")
	os.Remove("test_server_mtls.toml")
	os.Remove("test_client_mtls.toml")

	// ========================================
	// Phase 2: h2c + Token Auth
	// ========================================
	log.Println("\n====================================")
	log.Println("  PHASE 2: Token Auth (h2c)")
	log.Println("====================================")

	token, _ := crypto.GenerateToken()

	runSuite(suiteConfig{
		Name:           "Token",
		ServerConfFile: "test_server_token.toml",
		ClientConfFile: "test_client_token.toml",
		ServerConf: fmt.Sprintf(`
listen_addr = ":8081"
[security]
auth_token = "%s"
enable_socks5 = true
enable_udp = true
`, token),
		ClientConf: fmt.Sprintf(`
remote_addr = "127.0.0.1:8081"
auth_token = "%s"
[[inbounds]]
protocol = "socks5"
local_addr = "127.0.0.1:1081"
enable_udp = true
`, token),
		SOCKS5Addr:  "127.0.0.1:1081",
		EchoTCPAddr: "127.0.0.1:9001",
		EchoUDPPort: 9002,
	})

	// Cleanup phase 2
	os.Remove("test_server_token.toml")
	os.Remove("test_client_token.toml")

	log.Println("\n====================================")
	log.Println("  ALL PHASES PASSED ✓")
	log.Println("====================================")
}

func runSuite(cfg suiteConfig) {
	log.Printf("[%s] Writing configs...", cfg.Name)
	os.WriteFile(cfg.ServerConfFile, []byte(cfg.ServerConf), 0644)
	os.WriteFile(cfg.ClientConfFile, []byte(cfg.ClientConf), 0644)

	// Start Server
	log.Printf("[%s] Starting Phoenix Server...", cfg.Name)
	serverCmd := exec.Command("./bin/server", "--config", cfg.ServerConfFile)
	serverCmd.Stdout = os.Stdout
	serverCmd.Stderr = os.Stderr
	if err := serverCmd.Start(); err != nil {
		log.Fatalf("[%s] Failed to start server: %v", cfg.Name, err)
	}
	defer func() {
		serverCmd.Process.Kill()
		serverCmd.Wait()
	}()

	// Start Client
	log.Printf("[%s] Starting Phoenix Client...", cfg.Name)
	clientCmd := exec.Command("./bin/client", "--config", cfg.ClientConfFile)
	clientCmd.Stdout = os.Stdout
	clientCmd.Stderr = os.Stderr
	if err := clientCmd.Start(); err != nil {
		log.Fatalf("[%s] Failed to start client: %v", cfg.Name, err)
	}
	defer func() {
		clientCmd.Process.Kill()
		clientCmd.Wait()
	}()

	time.Sleep(2 * time.Second)

	// TCP Test
	log.Printf("[%s] === Testing TCP via SOCKS5 ===", cfg.Name)
	testTCP(cfg.SOCKS5Addr, cfg.EchoTCPAddr)

	// TCP Speed Test
	log.Printf("[%s] === Testing TCP Speed (10MB) ===", cfg.Name)
	testTCPSpeed(cfg.SOCKS5Addr, cfg.EchoTCPAddr, 10*1024*1024)

	// UDP Test
	log.Printf("[%s] === Testing UDP via SOCKS5 ===", cfg.Name)
	testUDP(cfg.SOCKS5Addr, cfg.EchoUDPPort)

	// UDP Stress Test
	log.Printf("[%s] === Testing UDP Speed (1000 Packets) ===", cfg.Name)
	testUDPStress(cfg.SOCKS5Addr, cfg.EchoUDPPort)

	log.Printf("[%s] === ALL TESTS PASSED ===", cfg.Name)
}

// ========================================
// Test Functions
// ========================================

func testTCP(proxyAddr, targetAddr string) {
	dialer, err := proxy.SOCKS5("tcp", proxyAddr, nil, proxy.Direct)
	if err != nil {
		log.Fatalf("Failed to create SOCKS5 dialer: %v", err)
	}

	conn, err := dialer.Dial("tcp", targetAddr)
	if err != nil {
		log.Fatalf("TCP Dial failed: %v", err)
	}
	defer conn.Close()

	msg := "Hello TCP"
	conn.Write([]byte(msg))

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		log.Fatalf("TCP Read failed: %v", err)
	}

	reply := string(buf[:n])
	if reply != msg {
		log.Fatalf("TCP Mismatch: got %q, want %q", reply, msg)
	}
	log.Printf("TCP Success: %s", reply)
}

func testTCPSpeed(proxyAddr, targetAddr string, size int) {
	dialer, _ := proxy.SOCKS5("tcp", proxyAddr, nil, proxy.Direct)
	conn, err := dialer.Dial("tcp", targetAddr)
	if err != nil {
		log.Fatalf("TCP Speed Dial failed: %v", err)
	}
	defer conn.Close()

	data := make([]byte, 32*1024)
	totalSent := 0
	start := time.Now()

	go func() {
		buf := make([]byte, 32*1024)
		received := 0
		for received < size {
			n, err := conn.Read(buf)
			if err != nil {
				break
			}
			received += n
		}
	}()

	for totalSent < size {
		n := len(data)
		if size-totalSent < n {
			n = size - totalSent
		}
		if _, err := conn.Write(data[:n]); err != nil {
			log.Fatalf("TCP Speed Write failed: %v", err)
		}
		totalSent += n
	}

	duration := time.Since(start)
	mbps := float64(size) * 8 / (1000000 * duration.Seconds())
	log.Printf("TCP Speed: %.2f Mbps (%.2f MB in %v)", mbps, float64(size)/1024/1024, duration)
}

func testUDP(proxyAddr string, echoUDPPort uint16) {
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		log.Fatalf("UDP Handshake TCP Dial failed: %v", err)
	}
	defer conn.Close()

	// Handshake
	conn.Write([]byte{0x05, 0x01, 0x00})
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		log.Fatalf("UDP Handshake Read failed: %v", err)
	}
	if buf[0] != 0x05 || buf[1] != 0x00 {
		log.Fatalf("UDP Handshake Method rejected: %v", buf)
	}

	// Request UDP ASSOCIATE
	req := []byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	conn.Write(req)

	// Read Reply
	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil {
		log.Fatalf("UDP Handshake Reply Read failed: %v", err)
	}
	if reply[1] != 0x00 {
		log.Fatalf("UDP Handshake Failed with Rep: %d", reply[1])
	}

	var relayPort int
	if reply[3] == 0x01 {
		relayPort = int(binary.BigEndian.Uint16(reply[8:10]))
	} else if reply[3] == 0x04 {
		rest := make([]byte, 12)
		if _, err := io.ReadFull(conn, rest); err != nil {
			log.Fatalf("UDP Handshake IPv6 Read failed: %v", err)
		}
		full := append(reply, rest...)
		relayPort = int(binary.BigEndian.Uint16(full[20:22]))
	}

	proxyHost, _, _ := net.SplitHostPort(proxyAddr)
	relayAddr := net.JoinHostPort(proxyHost, fmt.Sprint(relayPort))
	log.Printf("UDP Relay is at: %s", relayAddr)

	// Send UDP Packet
	uConn, err := net.Dial("udp", relayAddr)
	if err != nil {
		log.Fatalf("UDP Dial failed: %v", err)
	}
	defer uConn.Close()

	// SOCKS5 UDP Header
	pkt := make([]byte, 0, 1024)
	pkt = append(pkt, 0x00, 0x00, 0x00, 0x01)
	pkt = append(pkt, []byte{127, 0, 0, 1}...)
	port := make([]byte, 2)
	binary.BigEndian.PutUint16(port, echoUDPPort)
	pkt = append(pkt, port...)

	msg := "Hello UDP"
	pkt = append(pkt, []byte(msg)...)

	if _, err := uConn.Write(pkt); err != nil {
		log.Fatalf("UDP Write failed: %v", err)
	}

	// Read Reply
	resp := make([]byte, 1024)
	uConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := uConn.Read(resp)
	if err != nil {
		log.Fatalf("UDP Read failed: %v", err)
	}

	if n < 10 {
		log.Fatalf("UDP Reply too short: %d", n)
	}
	replyMsg := string(resp[10:n])
	if replyMsg != msg {
		log.Fatalf("UDP Mismatch: got %q, want %q", replyMsg, msg)
	}
	log.Printf("UDP Success: %s", replyMsg)
}

func testUDPStress(proxyAddr string, echoUDPPort uint16) {
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		log.Fatalf("Stress Handshake TCP Dial failed: %v", err)
	}
	defer conn.Close()

	// Handshake
	conn.Write([]byte{0x05, 0x01, 0x00})
	buf := make([]byte, 2)
	io.ReadFull(conn, buf)

	// Request UDP ASSOCIATE
	req := []byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	conn.Write(req)

	// Read Reply
	reply := make([]byte, 10)
	io.ReadFull(conn, reply)

	var relayPort int
	if reply[3] == 0x01 {
		relayPort = int(binary.BigEndian.Uint16(reply[8:10]))
	} else if reply[3] == 0x04 {
		rest := make([]byte, 12)
		io.ReadFull(conn, rest)
		full := append(reply, rest...)
		relayPort = int(binary.BigEndian.Uint16(full[20:22]))
	}

	proxyHost, _, _ := net.SplitHostPort(proxyAddr)
	relayAddr := net.JoinHostPort(proxyHost, fmt.Sprint(relayPort))
	log.Printf("Stress UDP Relay: %s", relayAddr)

	// Send Stream
	uConn, err := net.Dial("udp", relayAddr)
	if err != nil {
		log.Fatalf("Stress UDP Dial failed: %v", err)
	}
	defer uConn.Close()

	// SOCKS5 UDP Header
	basePkt := make([]byte, 0, 1500)
	basePkt = append(basePkt, 0x00, 0x00, 0x00, 0x01)
	basePkt = append(basePkt, []byte{127, 0, 0, 1}...)
	port := make([]byte, 2)
	binary.BigEndian.PutUint16(port, echoUDPPort)
	basePkt = append(basePkt, port...)

	headerLen := len(basePkt)
	payloadSize := 1000
	totalPackets := 1000

	// Receiver
	receivedCount := 0
	doneChan := make(chan bool)
	go func() {
		rBuf := make([]byte, 2048)
		uConn.SetReadDeadline(time.Now().Add(10 * time.Second))
		for {
			n, err := uConn.Read(rBuf)
			if err != nil {
				break
			}
			if n > headerLen {
				receivedCount++
			}
			if receivedCount == totalPackets {
				doneChan <- true
				return
			}
		}
		doneChan <- false
	}()

	start := time.Now()
	for i := 0; i < totalPackets; i++ {
		pkt := make([]byte, len(basePkt))
		copy(pkt, basePkt)

		data := make([]byte, payloadSize)
		binary.BigEndian.PutUint32(data, uint32(i))
		pkt = append(pkt, data...)

		if _, err := uConn.Write(pkt); err != nil {
			log.Fatalf("Stress Write failed at %d: %v", i, err)
		}
		time.Sleep(1 * time.Millisecond)
	}

	log.Printf("Sent %d packets in %v", totalPackets, time.Since(start))

	select {
	case success := <-doneChan:
		if !success {
			log.Printf("Stress Test: Only received %d/%d packets (Timeout/Error)", receivedCount, totalPackets)
		} else {
			log.Printf("Stress Test Success: Received %d/%d packets", receivedCount, totalPackets)
		}
	case <-time.After(15 * time.Second):
		log.Printf("Stress Test Timeout: Received %d/%d packets", receivedCount, totalPackets)
	}
}

// ========================================
// Echo Servers
// ========================================

func startTCPEchoServer(addr string) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("TCP Echo Listen failed: %v", err)
	}
	for {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		go io.Copy(conn, conn)
	}
}

func startUDPEchoServer(addr string) {
	conn, err := net.ListenPacket("udp", addr)
	if err != nil {
		log.Fatalf("UDP Echo Listen failed: %v", err)
	}
	buf := make([]byte, 1024)
	for {
		n, peer, err := conn.ReadFrom(buf)
		if err != nil {
			continue
		}
		conn.WriteTo(buf[:n], peer)
	}
}
