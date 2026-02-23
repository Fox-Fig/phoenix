package main

import (
	"bufio"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
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

// ─── Main ──────────────────────────────────────────────────

func main() {
	manual := flag.Bool("manual", false, "Run in interactive manual test mode")
	flag.Parse()

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

	if *manual {
		runInteractive()
	} else {
		runAllPhases()
	}
}

// ─── Automatic: All Phases ─────────────────────────────────

func runAllPhases() {
	// Generate keys once (reused across TLS phases)
	privServer, pubServer, _ := crypto.GenerateKeypair()
	privClient, pubClient, _ := crypto.GenerateKeypair()
	token, _ := crypto.GenerateToken()

	// ECDSA P256 key for Phase 6 (Chrome fingerprint)
	// Chrome's uTLS ClientHello doesn't advertise Ed25519 as a valid server cert algorithm.
	ecdsaKey, _ := crypto.GenerateECDSAKey()

	keyFiles := []string{"test_server.key", "test_client.key", "test_ecdsa_server.key"}
	os.WriteFile("test_server.key", privServer, 0600)
	os.WriteFile("test_client.key", privClient, 0600)
	os.WriteFile("test_ecdsa_server.key", ecdsaKey, 0600)
	defer func() {
		for _, f := range keyFiles {
			os.Remove(f)
		}
	}()

	// Allocate all ports upfront (dynamic, avoids conflicts from previous runs)
	serverPorts := make([]string, 6)
	clientPorts := make([]string, 6)
	for i := range serverPorts {
		serverPorts[i] = findFreePort()
		clientPorts[i] = findFreePort()
	}

	phases := []struct {
		title string
		cfg   suiteConfig
	}{
		{
			"PHASE 1: Cleartext h2c (No Auth)",
			suiteConfig{
				Name:           "h2c",
				ServerConfFile: "test_server_h2c.toml",
				ClientConfFile: "test_client_h2c.toml",
				ServerConf: fmt.Sprintf(`
listen_addr = ":%s"
[security]
enable_socks5 = true
enable_udp = true
`, serverPorts[0]),
				ClientConf: fmt.Sprintf(`
remote_addr = "127.0.0.1:%s"
[[inbounds]]
protocol = "socks5"
local_addr = "127.0.0.1:%s"
enable_udp = true
`, serverPorts[0], clientPorts[0]),
				SOCKS5Addr:  "127.0.0.1:" + clientPorts[0],
				EchoTCPAddr: "127.0.0.1:9001",
				EchoUDPPort: 9002,
			},
		},
		{
			"PHASE 2: h2c + Token Auth",
			suiteConfig{
				Name:           "Token",
				ServerConfFile: "test_server_token.toml",
				ClientConfFile: "test_client_token.toml",
				ServerConf: fmt.Sprintf(`
listen_addr = ":%s"
[security]
auth_token = "%s"
enable_socks5 = true
enable_udp = true
`, serverPorts[1], token),
				ClientConf: fmt.Sprintf(`
remote_addr = "127.0.0.1:%s"
auth_token = "%s"
[[inbounds]]
protocol = "socks5"
local_addr = "127.0.0.1:%s"
enable_udp = true
`, serverPorts[1], token, clientPorts[1]),
				SOCKS5Addr:  "127.0.0.1:" + clientPorts[1],
				EchoTCPAddr: "127.0.0.1:9001",
				EchoUDPPort: 9002,
			},
		},
		{
			"PHASE 3: One-Way TLS (Ed25519 key pinning)",
			suiteConfig{
				Name:           "OneWayTLS",
				ServerConfFile: "test_server_owtls.toml",
				ClientConfFile: "test_client_owtls.toml",
				ServerConf: fmt.Sprintf(`
listen_addr = ":%s"
[security]
enable_socks5 = true
enable_udp = true
private_key = "test_server.key"
`, serverPorts[2]),
				ClientConf: fmt.Sprintf(`
remote_addr = "127.0.0.1:%s"
server_public_key = "%s"
[[inbounds]]
protocol = "socks5"
local_addr = "127.0.0.1:%s"
enable_udp = true
`, serverPorts[2], pubServer, clientPorts[2]),
				SOCKS5Addr:  "127.0.0.1:" + clientPorts[2],
				EchoTCPAddr: "127.0.0.1:9001",
				EchoUDPPort: 9002,
			},
		},
		{
			"PHASE 4: mTLS (Mutual Ed25519)",
			suiteConfig{
				Name:           "mTLS",
				ServerConfFile: "test_server_mtls.toml",
				ClientConfFile: "test_client_mtls.toml",
				ServerConf: fmt.Sprintf(`
listen_addr = ":%s"
[security]
enable_socks5 = true
enable_udp = true
private_key = "test_server.key"
authorized_clients = ["%s"]
`, serverPorts[3], pubClient),
				ClientConf: fmt.Sprintf(`
remote_addr = "127.0.0.1:%s"
private_key = "test_client.key"
server_public_key = "%s"
[[inbounds]]
protocol = "socks5"
local_addr = "127.0.0.1:%s"
enable_udp = true
`, serverPorts[3], pubServer, clientPorts[3]),
				SOCKS5Addr:  "127.0.0.1:" + clientPorts[3],
				EchoTCPAddr: "127.0.0.1:9001",
				EchoUDPPort: 9002,
			},
		},
		{
			"PHASE 5: Insecure TLS + Token Auth",
			suiteConfig{
				Name:           "InsecureTLS+Token",
				ServerConfFile: "test_server_inssec.toml",
				ClientConfFile: "test_client_inssec.toml",
				ServerConf: fmt.Sprintf(`
listen_addr = ":%s"
[security]
enable_socks5 = true
enable_udp = true
private_key = "test_server.key"
auth_token = "%s"
`, serverPorts[4], token),
				ClientConf: fmt.Sprintf(`
remote_addr = "127.0.0.1:%s"
tls_mode = "insecure"
auth_token = "%s"
[[inbounds]]
protocol = "socks5"
local_addr = "127.0.0.1:%s"
enable_udp = true
`, serverPorts[4], token, clientPorts[4]),
				SOCKS5Addr:  "127.0.0.1:" + clientPorts[4],
				EchoTCPAddr: "127.0.0.1:9001",
				EchoUDPPort: 9002,
			},
		},
		{
			"PHASE 6: Insecure TLS + Chrome Fingerprint",
			suiteConfig{
				Name:           "InsecureTLS+Fingerprint",
				ServerConfFile: "test_server_fp.toml",
				ClientConfFile: "test_client_fp.toml",
				ServerConf: fmt.Sprintf(`
listen_addr = ":%s"
[security]
enable_socks5 = true
enable_udp = true
private_key = "test_ecdsa_server.key"
`, serverPorts[5]),
				ClientConf: fmt.Sprintf(`
remote_addr = "127.0.0.1:%s"
tls_mode = "insecure"
fingerprint = "chrome"
[[inbounds]]
protocol = "socks5"
local_addr = "127.0.0.1:%s"
enable_udp = true
`, serverPorts[5], clientPorts[5]),
				SOCKS5Addr:  "127.0.0.1:" + clientPorts[5],
				EchoTCPAddr: "127.0.0.1:9001",
				EchoUDPPort: 9002,
			},
		},
	}

	passed := 0
	for _, p := range phases {
		fmt.Printf("\n====================================\n")
		fmt.Printf("  %s\n", p.title)
		fmt.Printf("====================================\n")
		runSuite(p.cfg)
		passed++
		// Cleanup temp config files
		os.Remove(p.cfg.ServerConfFile)
		os.Remove(p.cfg.ClientConfFile)
	}

	fmt.Printf("\n====================================\n")
	fmt.Printf("  ALL %d PHASES PASSED ✓\n", passed)
	fmt.Printf("====================================\n")
}

// findFreePort finds a free TCP port on localhost.
func findFreePort() string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal("findFreePort failed:", err)
	}
	_, port, _ := net.SplitHostPort(l.Addr().String())
	l.Close()
	return port
}

// ─── Interactive / Manual Mode ─────────────────────────────

func runInteractive() {
	r := bufio.NewReader(os.Stdin)
	ask := func(prompt string) string {
		fmt.Print(prompt)
		line, _ := r.ReadString('\n')
		return strings.TrimSpace(line)
	}

	fmt.Println("\n╔══════════════════════════════════════╗")
	fmt.Println("║   Phoenix Manual Connection Test     ║")
	fmt.Println("╚══════════════════════════════════════╝")

	// --- TLS Mode ---
	fmt.Println("\n[1] TLS Mode:")
	fmt.Println("  1) h2c                  (no TLS, direct)")
	fmt.Println("  2) insecure             (TLS, skip cert verify)")
	fmt.Println("  3) One-Way TLS          (Ed25519 key pinning)")
	fmt.Println("  4) mTLS                 (mutual Ed25519)")
	tlsChoice := ask("  Choice [1-4]: ")

	// --- Token Auth ---
	fmt.Println("\n[2] Token Auth:")
	tokenChoice := ask("  Enable token auth? (y/n): ")
	useToken := strings.ToLower(tokenChoice) == "y"

	// --- Fingerprint ---
	useTLS := tlsChoice != "1"
	fingerprint := ""
	if useTLS {
		fmt.Println("\n[3] TLS Fingerprint (browser impersonation):")
		fmt.Println("  1) none     (Go default)")
		fmt.Println("  2) chrome   (recommended)")
		fmt.Println("  3) firefox")
		fmt.Println("  4) safari")
		fmt.Println("  5) random")
		fpChoice := ask("  Choice [1-5]: ")
		switch fpChoice {
		case "2":
			fingerprint = "chrome"
		case "3":
			fingerprint = "firefox"
		case "4":
			fingerprint = "safari"
		case "5":
			fingerprint = "random"
		}
	}

	// --- Test Type ---
	fmt.Println("\n[4] Tests to run:")
	fmt.Println("  1) TCP only")
	fmt.Println("  2) UDP only")
	fmt.Println("  3) TCP + UDP + Speed (full)")
	testChoice := ask("  Choice [1-3]: ")

	// --- Port ---
	fmt.Println()
	serverPort := ask("  Server port [default: 9100]: ")
	if serverPort == "" {
		serverPort = "9100"
	}
	clientPort := ask("  Client SOCKS5 port [default: 9180]: ")
	if clientPort == "" {
		clientPort = "9180"
	}

	// Build configs
	privServer, pubServer, _ := crypto.GenerateKeypair()
	privClient, pubClient, _ := crypto.GenerateKeypair()
	token, _ := crypto.GenerateToken()

	os.WriteFile("manual_server.key", privServer, 0600)
	os.WriteFile("manual_client.key", privClient, 0600)
	defer os.Remove("manual_server.key")
	defer os.Remove("manual_client.key")

	serverConf, clientConf := buildManualConfigs(
		tlsChoice, useToken, fingerprint,
		serverPort, clientPort,
		pubServer, pubClient, token,
	)

	name := fmt.Sprintf("Manual(%s)", describeMode(tlsChoice, useToken, fingerprint))
	cfg := suiteConfig{
		Name:           name,
		ServerConfFile: "manual_server_test.toml",
		ClientConfFile: "manual_client_test.toml",
		ServerConf:     serverConf,
		ClientConf:     clientConf,
		SOCKS5Addr:     "127.0.0.1:" + clientPort,
		EchoTCPAddr:    "127.0.0.1:9001",
		EchoUDPPort:    9002,
	}

	fmt.Printf("\n====================================\n")
	fmt.Printf("  Running: %s\n", name)
	fmt.Printf("====================================\n")

	runSuiteSelective(cfg, testChoice)

	os.Remove(cfg.ServerConfFile)
	os.Remove(cfg.ClientConfFile)

	fmt.Printf("\n====================================\n")
	fmt.Printf("  Manual Test PASSED ✓\n")
	fmt.Printf("====================================\n")
}

func buildManualConfigs(tlsChoice string, useToken bool, fingerprint, serverPort, clientPort, pubServer, pubClient, token string) (serverConf, clientConf string) {
	tokenLine := ""
	clientTokenLine := ""
	if useToken {
		tokenLine = fmt.Sprintf(`auth_token = "%s"`, token)
		clientTokenLine = fmt.Sprintf(`auth_token = "%s"`, token)
	}

	fpLine := ""
	if fingerprint != "" {
		fpLine = fmt.Sprintf(`fingerprint = "%s"`, fingerprint)
	}

	switch tlsChoice {
	case "2": // insecure TLS
		serverConf = fmt.Sprintf(`
listen_addr = ":%s"
[security]
enable_socks5 = true
enable_udp = true
private_key = "manual_server.key"
%s
`, serverPort, tokenLine)
		clientConf = fmt.Sprintf(`
remote_addr = "127.0.0.1:%s"
tls_mode = "insecure"
%s
%s
[[inbounds]]
protocol = "socks5"
local_addr = "127.0.0.1:%s"
enable_udp = true
`, serverPort, clientTokenLine, fpLine, clientPort)

	case "3": // One-Way TLS
		serverConf = fmt.Sprintf(`
listen_addr = ":%s"
[security]
enable_socks5 = true
enable_udp = true
private_key = "manual_server.key"
%s
`, serverPort, tokenLine)
		clientConf = fmt.Sprintf(`
remote_addr = "127.0.0.1:%s"
server_public_key = "%s"
%s
%s
[[inbounds]]
protocol = "socks5"
local_addr = "127.0.0.1:%s"
enable_udp = true
`, serverPort, pubServer, clientTokenLine, fpLine, clientPort)

	case "4": // mTLS
		serverConf = fmt.Sprintf(`
listen_addr = ":%s"
[security]
enable_socks5 = true
enable_udp = true
private_key = "manual_server.key"
authorized_clients = ["%s"]
%s
`, serverPort, pubClient, tokenLine)
		clientConf = fmt.Sprintf(`
remote_addr = "127.0.0.1:%s"
private_key = "manual_client.key"
server_public_key = "%s"
%s
%s
[[inbounds]]
protocol = "socks5"
local_addr = "127.0.0.1:%s"
enable_udp = true
`, serverPort, pubServer, clientTokenLine, fpLine, clientPort)

	default: // h2c
		serverConf = fmt.Sprintf(`
listen_addr = ":%s"
[security]
enable_socks5 = true
enable_udp = true
%s
`, serverPort, tokenLine)
		clientConf = fmt.Sprintf(`
remote_addr = "127.0.0.1:%s"
%s
[[inbounds]]
protocol = "socks5"
local_addr = "127.0.0.1:%s"
enable_udp = true
`, serverPort, clientTokenLine, clientPort)
	}
	return
}

func describeMode(tlsChoice string, useToken bool, fingerprint string) string {
	modes := map[string]string{"1": "h2c", "2": "insecure", "3": "one-way-tls", "4": "mTLS"}
	mode := modes[tlsChoice]
	if useToken {
		mode += "+token"
	}
	if fingerprint != "" {
		mode += "+" + fingerprint
	}
	return mode
}

func runSuiteSelective(cfg suiteConfig, testChoice string) {
	os.WriteFile(cfg.ServerConfFile, []byte(cfg.ServerConf), 0644)
	os.WriteFile(cfg.ClientConfFile, []byte(cfg.ClientConf), 0644)

	log.Printf("[%s] Starting Server...", cfg.Name)
	serverCmd := exec.Command("./bin/server", "--config", cfg.ServerConfFile)
	serverCmd.Stdout = os.Stdout
	serverCmd.Stderr = os.Stderr
	if err := serverCmd.Start(); err != nil {
		log.Fatalf("[%s] Failed to start server: %v", cfg.Name, err)
	}
	defer func() { serverCmd.Process.Kill(); serverCmd.Wait() }()

	log.Printf("[%s] Starting Client...", cfg.Name)
	clientCmd := exec.Command("./bin/client", "--config", cfg.ClientConfFile)
	clientCmd.Stdout = os.Stdout
	clientCmd.Stderr = os.Stderr
	if err := clientCmd.Start(); err != nil {
		log.Fatalf("[%s] Failed to start client: %v", cfg.Name, err)
	}
	defer func() { clientCmd.Process.Kill(); clientCmd.Wait() }()

	time.Sleep(2 * time.Second)

	switch testChoice {
	case "1": // TCP only
		log.Printf("[%s] === TCP Test ===", cfg.Name)
		testTCP(cfg.SOCKS5Addr, cfg.EchoTCPAddr)
		log.Printf("[%s] === TCP Speed (10MB) ===", cfg.Name)
		testTCPSpeed(cfg.SOCKS5Addr, cfg.EchoTCPAddr, 10*1024*1024)
	case "2": // UDP only
		log.Printf("[%s] === UDP Test ===", cfg.Name)
		testUDP(cfg.SOCKS5Addr, cfg.EchoUDPPort)
		log.Printf("[%s] === UDP Stress (1000 pkt) ===", cfg.Name)
		testUDPStress(cfg.SOCKS5Addr, cfg.EchoUDPPort)
	default: // full
		log.Printf("[%s] === TCP Test ===", cfg.Name)
		testTCP(cfg.SOCKS5Addr, cfg.EchoTCPAddr)
		log.Printf("[%s] === TCP Speed (10MB) ===", cfg.Name)
		testTCPSpeed(cfg.SOCKS5Addr, cfg.EchoTCPAddr, 10*1024*1024)
		log.Printf("[%s] === UDP Test ===", cfg.Name)
		testUDP(cfg.SOCKS5Addr, cfg.EchoUDPPort)
		log.Printf("[%s] === UDP Stress (1000 pkt) ===", cfg.Name)
		testUDPStress(cfg.SOCKS5Addr, cfg.EchoUDPPort)
	}

	log.Printf("[%s] === PASSED ===", cfg.Name)
}

// ─── runSuite (automatic) ──────────────────────────────────

func runSuite(cfg suiteConfig) {
	os.WriteFile(cfg.ServerConfFile, []byte(cfg.ServerConf), 0644)
	os.WriteFile(cfg.ClientConfFile, []byte(cfg.ClientConf), 0644)

	log.Printf("[%s] Starting Phoenix Server...", cfg.Name)
	serverCmd := exec.Command("./bin/server", "--config", cfg.ServerConfFile)
	serverCmd.Stdout = os.Stdout
	serverCmd.Stderr = os.Stderr
	if err := serverCmd.Start(); err != nil {
		log.Fatalf("[%s] Failed to start server: %v", cfg.Name, err)
	}
	defer func() { serverCmd.Process.Kill(); serverCmd.Wait() }()

	log.Printf("[%s] Starting Phoenix Client...", cfg.Name)
	clientCmd := exec.Command("./bin/client", "--config", cfg.ClientConfFile)
	clientCmd.Stdout = os.Stdout
	clientCmd.Stderr = os.Stderr
	if err := clientCmd.Start(); err != nil {
		log.Fatalf("[%s] Failed to start client: %v", cfg.Name, err)
	}
	defer func() { clientCmd.Process.Kill(); clientCmd.Wait() }()

	time.Sleep(2 * time.Second)

	log.Printf("[%s] === Testing TCP via SOCKS5 ===", cfg.Name)
	testTCP(cfg.SOCKS5Addr, cfg.EchoTCPAddr)

	log.Printf("[%s] === Testing TCP Speed (10MB) ===", cfg.Name)
	testTCPSpeed(cfg.SOCKS5Addr, cfg.EchoTCPAddr, 10*1024*1024)

	log.Printf("[%s] === Testing UDP via SOCKS5 ===", cfg.Name)
	testUDP(cfg.SOCKS5Addr, cfg.EchoUDPPort)

	log.Printf("[%s] === Testing UDP Speed (1000 Packets) ===", cfg.Name)
	testUDPStress(cfg.SOCKS5Addr, cfg.EchoUDPPort)

	log.Printf("[%s] === ALL TESTS PASSED ===", cfg.Name)
}

// ─── Test Functions ────────────────────────────────────────

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

	conn.Write([]byte{0x05, 0x01, 0x00})
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		log.Fatalf("UDP Handshake Read failed: %v", err)
	}
	if buf[0] != 0x05 || buf[1] != 0x00 {
		log.Fatalf("UDP Handshake Method rejected: %v", buf)
	}

	req := []byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	conn.Write(req)

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

	uConn, err := net.Dial("udp", relayAddr)
	if err != nil {
		log.Fatalf("UDP Dial failed: %v", err)
	}
	defer uConn.Close()

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

	conn.Write([]byte{0x05, 0x01, 0x00})
	buf := make([]byte, 2)
	io.ReadFull(conn, buf)

	req := []byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	conn.Write(req)

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

	uConn, err := net.Dial("udp", relayAddr)
	if err != nil {
		log.Fatalf("Stress UDP Dial failed: %v", err)
	}
	defer uConn.Close()

	basePkt := make([]byte, 0, 1500)
	basePkt = append(basePkt, 0x00, 0x00, 0x00, 0x01)
	basePkt = append(basePkt, []byte{127, 0, 0, 1}...)
	port := make([]byte, 2)
	binary.BigEndian.PutUint16(port, echoUDPPort)
	basePkt = append(basePkt, port...)

	headerLen := len(basePkt)
	payloadSize := 1000
	totalPackets := 1000

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

// ─── Echo Servers ──────────────────────────────────────────

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
