package testutils

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/proxy"
)

func getProjectRoot() string {
	_, b, _, _ := runtime.Caller(0)
	return filepath.Dir(filepath.Dir(filepath.Dir(b)))
}

// setupE2EEnvironment prepares config files and processes for a specific protocol and security scenario.
func setupE2EEnvironment(t testing.TB, protocol string, tc SecurityScenario) (func(), string) {
	serverPort, _ := ParsePort(FindFreeAddr())
	socks5Port, _ := ParsePort(FindFreeAddr())

	tmpDir := t.TempDir()
	serverConfigPath := filepath.Join(tmpDir, "server.toml")
	clientConfigPath := filepath.Join(tmpDir, "client.toml")

	serverConfig := fmt.Sprintf(`
listen_addr = "127.0.0.1:%s"
protocol = "%s"
api_paths = ["/fake"]
`, serverPort, protocol)

	serverConfig += "\n[security]\nenable_socks5 = true\nallow_empty_sni = true\n"

	if tc.ServerAuthToken != "" {
		serverConfig += fmt.Sprintf("auth_token = \"%s\"\n", tc.ServerAuthToken)
	}
	if tc.ServerPrivateKey != "" {
		absKey, _ := filepath.Abs(tc.ServerPrivateKey)
		serverConfig += fmt.Sprintf("private_key = \"%s\"\n", absKey)
	}
	if len(tc.AuthorizedClientKeys) > 0 {
		serverConfig += "authorized_client_keys = [\n"
		for _, k := range tc.AuthorizedClientKeys {
			serverConfig += fmt.Sprintf("  \"%s\",\n", k)
		}
		serverConfig += "]\n"
	}

	clientConfig := fmt.Sprintf(`
remote_addr = "127.0.0.1:%s"
protocol = "%s"
api_paths = ["/fake"]
tls_mode = "%s"
`, serverPort, protocol, tc.TLSMode)

	if tc.ClientAuthToken != "" {
		clientConfig += fmt.Sprintf("auth_token = \"%s\"\n", tc.ClientAuthToken)
	}
	if tc.ClientPrivateKey != "" {
		absKey, _ := filepath.Abs(tc.ClientPrivateKey)
		clientConfig += fmt.Sprintf("private_key = \"%s\"\n", absKey)
	}
	if tc.ServerPublicKey != "" {
		clientConfig += fmt.Sprintf("server_public_key = \"%s\"\n", tc.ServerPublicKey)
	}
	if tc.CustomSNI != "" {
		clientConfig += fmt.Sprintf("custom_sni = \"%s\"\n", tc.CustomSNI)
	}
	
	// Always write fingerprint to override the default "chrome_dynamic" if empty
	clientConfig += fmt.Sprintf("fingerprint = \"%s\"\n", tc.Fingerprint)

	clientConfig += fmt.Sprintf(`
[[inbounds]]
protocol = "socks5"
local_addr = "127.0.0.1:%s"
`, socks5Port)

	err := os.WriteFile(serverConfigPath, []byte(serverConfig), 0644)
	if err != nil {
		t.Fatalf("Failed to write server config: %v", err)
	}

	err = os.WriteFile(clientConfigPath, []byte(clientConfig), 0644)
	if err != nil {
		t.Fatalf("Failed to write client config: %v", err)
	}

	projectRoot := getProjectRoot()
	serverCmd := exec.Command(filepath.Join(projectRoot, "bin", "server"), "-config", serverConfigPath)
	serverCmd.Dir = projectRoot

	clientCmd := exec.Command(filepath.Join(projectRoot, "bin", "client"), "-config", clientConfigPath)
	clientCmd.Dir = projectRoot

	var serverOut, clientOut bytes.Buffer
	serverCmd.Stdout = &serverOut
	serverCmd.Stderr = &serverOut
	clientCmd.Stdout = &clientOut
	clientCmd.Stderr = &clientOut

	err = serverCmd.Start()
	if err != nil {
		t.Fatalf("Failed to start server binary: %v\nServer output:\n%s", err, serverOut.String())
	}

	err = clientCmd.Start()
	if err != nil {
		serverCmd.Process.Kill()
		t.Fatalf("Failed to start client binary: %v\nClient output:\n%s", err, clientOut.String())
	}

	// Give them time to start
	time.Sleep(1 * time.Second)

	cleanup := func() {
		serverCmd.Process.Kill()
		clientCmd.Process.Kill()
		if t.Failed() {
			t.Logf("--- Server Output ---\n%s\n-------------------", serverOut.String())
			t.Logf("--- Client Output ---\n%s\n-------------------", clientOut.String())
		}
	}

	return cleanup, socks5Port
}

func ParsePort(addr string) (string, error) {
	parts := strings.Split(addr, ":")
	return parts[len(parts)-1], nil
}

// dialSOCKS5 is a helper to dial through our real SOCKS5 client port to the target.
func dialSOCKS5(socks5Port string, targetAddr string) (net.Conn, error) {
	dialer, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%s", socks5Port), nil, proxy.Direct)
	if err != nil {
		return nil, err
	}
	return dialer.Dial("tcp", targetAddr)
}

// RunE2EFunctionalSuite runs E2E connection tests for all scenarios
func RunE2EFunctionalSuite(t *testing.T, transportProto string, scenarios []SecurityScenario) {
	for _, tc := range scenarios {
		t.Run(tc.Name, func(t *testing.T) {
			cleanup, socks5Port := setupE2EEnvironment(t, transportProto, tc)
			defer cleanup()
			
			echoAddr := StartEchoServer()
			time.Sleep(100 * time.Millisecond)

			conn, err := dialSOCKS5(socks5Port, echoAddr)
			if err != nil {
				t.Fatalf("Failed to dial SOCKS5 proxy: %v", err)
			}
			defer conn.Close()

			msg := []byte("hello E2E real simulation test!")
			_, err = conn.Write(msg)
			if err != nil {
				t.Fatalf("Failed to write: %v", err)
			}

			buf := make([]byte, len(msg))
			_, err = io.ReadFull(conn, buf)
			if err != nil {
				t.Fatalf("Failed to read: %v", err)
			}

			if !bytes.Equal(buf, msg) {
				t.Fatalf("Echo mismatch: expected %q, got %q", msg, buf)
			}
		})
	}
}

// RunE2EBenchmarkSuite executes speed tests for all scenarios using E2E binaries
func RunE2EBenchmarkSuite(b *testing.B, transportProto string, scenarios []SecurityScenario) {
	echoAddr := StartEchoServer()
	sinkAddr := StartSinkServer()
	sourceAddr := StartSourceServer(50 * 1024 * 1024)

	for _, tc := range scenarios {
		b.Run(tc.Name+"_Latency", func(b *testing.B) {
			cleanup, socks5Port := setupE2EEnvironment(b, transportProto, tc)
			defer cleanup()

			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				conn, err := dialSOCKS5(socks5Port, echoAddr)
				if err != nil {
					b.Fatalf("Failed to dial: %v", err)
				}
				
				conn.Write([]byte("ping"))
				buf := make([]byte, 4)
				conn.Read(buf)
				conn.Close()
			}
		})

		b.Run(tc.Name+"_Upload", func(b *testing.B) {
			cleanup, socks5Port := setupE2EEnvironment(b, transportProto, tc)
			defer cleanup()

			dataSize := 10 * 1024 * 1024 // 10MB
			chunk := make([]byte, 32*1024)

			b.SetBytes(int64(dataSize))
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				conn, err := dialSOCKS5(socks5Port, sinkAddr)
				if err != nil {
					b.Fatalf("Failed to dial: %v", err)
				}
				
				totalWritten := 0
				for totalWritten < dataSize {
					n, err := conn.Write(chunk)
					totalWritten += n
					if err != nil {
						b.Fatalf("write failed: %v", err)
						break
					}
				}
				conn.Close()
			}
		})

		b.Run(tc.Name+"_Download", func(b *testing.B) {
			cleanup, socks5Port := setupE2EEnvironment(b, transportProto, tc)
			defer cleanup()

			dataSize := 10 * 1024 * 1024 // 10MB
			buf := make([]byte, 32*1024)

			b.SetBytes(int64(dataSize))
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				conn, err := dialSOCKS5(socks5Port, sourceAddr)
				if err != nil {
					b.Fatalf("Failed to dial: %v", err)
				}
				
				received := 0
				for received < dataSize {
					n, err := conn.Read(buf)
					if n > 0 {
						received += n
					}
					if err != nil && err != io.EOF {
						b.Fatalf("read failed: %v", err)
						break
					}
				}
				conn.Close()
			}
		})
	}
}
