package testutils

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"testing"
	"time"

	"phoenix/pkg/config"
	"phoenix/pkg/crypto"
	"phoenix/pkg/protocol"
	"phoenix/pkg/transport"
)

// SecurityScenario defines a combination of security parameters for testing.
type SecurityScenario struct {
	Name                 string
	ServerAuthToken      string
	ClientAuthToken      string
	ServerPrivateKey     string
	ServerPublicKey      string
	ClientPrivateKey     string
	AuthorizedClientKeys []string
	TLSMode              string
	CustomSNI            string
	Fingerprint          string
}

// GenerateTestScenarios creates a standard list of security modes.
func GenerateTestScenarios() []SecurityScenario {
	privServer, pubServer, _ := crypto.GenerateKeypair()
	privClient, pubClient, _ := crypto.GenerateKeypair()
	privECDSA, _ := crypto.GenerateECDSAKey()
	token, _ := crypto.GenerateToken()

	// Write keys to temp files (will be cleaned up by the test caller ideally, but this is fine for now)
	os.WriteFile("test_server.key", privServer, 0600)
	os.WriteFile("test_client.key", privClient, 0600)
	os.WriteFile("test_server_ecdsa.key", privECDSA, 0600)

	return []SecurityScenario{
		{
			Name: "Cleartext (No Auth)",
		},
		{
			Name:            "Cleartext (Token Auth)",
			ServerAuthToken: token,
			ClientAuthToken: token,
		},
		{
			Name:             "One-Way TLS (No Client Auth)",
			ServerPrivateKey: "test_server.key",
			ServerPublicKey:  pubServer,
		},
		{
			Name:                 "mTLS",
			ServerPrivateKey:     "test_server.key",
			ServerPublicKey:      pubServer,
			ClientPrivateKey:     "test_client.key",
			AuthorizedClientKeys: []string{pubClient},
		},
		{
			Name:             "Insecure TLS + Custom SNI",
			ServerPrivateKey: "test_server_ecdsa.key",
			TLSMode:          "insecure",
			CustomSNI:        "cloudflare.com",
		},
		{
			Name:             "Insecure TLS + Fingerprint",
			ServerPrivateKey: "test_server_ecdsa.key",
			TLSMode:          "insecure",
			Fingerprint:      "chrome",
		},
	}
}

// RunTransportFunctionalSuite executes functional tests against the configured transport.
func RunTransportFunctionalSuite(t *testing.T, transportProto string, scenarios []SecurityScenario) {
	echoAddr := StartEchoServer()

	for _, tc := range scenarios {
		t.Run(tc.Name, func(t *testing.T) {
			serverCfg := config.DefaultServerConfig()
			serverCfg.Protocol = transportProto
			serverCfg.ListenAddr = FindFreeAddr()
			serverCfg.Security.EnableSSH = true
			serverCfg.Security.AuthToken = tc.ServerAuthToken
			serverCfg.Security.PrivateKeyPath = tc.ServerPrivateKey
			serverCfg.Security.AuthorizedClientKeys = tc.AuthorizedClientKeys

			// Start the server
			go func() {
				if err := transport.StartServer(serverCfg); err != nil {
					// Tests might fail if port is in use, but standard go tests will capture logs
					fmt.Printf("[%s] Server error: %v\n", tc.Name, err)
				}
			}()

			time.Sleep(500 * time.Millisecond) // Give server time to start

			clientCfg := config.DefaultClientConfig()
			clientCfg.Protocol = transportProto
			clientCfg.RemoteAddr = serverCfg.ListenAddr
			clientCfg.AuthToken = tc.ClientAuthToken
			clientCfg.PrivateKeyPath = tc.ClientPrivateKey
			clientCfg.ServerPublicKey = tc.ServerPublicKey
			clientCfg.TLSMode = tc.TLSMode
			clientCfg.CustomSNI = tc.CustomSNI
			clientCfg.Fingerprint = tc.Fingerprint

			client := transport.NewClient(clientCfg)
			
			stream, err := client.Dial(protocol.ProtocolSSH, echoAddr)
			if err != nil {
				t.Fatalf("Failed to dial: %v", err)
			}
			defer stream.Close()

			// Test Echo Data
			msg := []byte("hello modular tests!")
			if _, err := stream.Write(msg); err != nil {
				t.Fatalf("Failed to write to stream: %v", err)
			}

			buf := make([]byte, len(msg))
			if _, err := io.ReadFull(stream, buf); err != nil {
				t.Fatalf("Failed to read from stream: %v", err)
			}

			if !bytes.Equal(buf, msg) {
				t.Fatalf("Echo mismatch. Expected %s, got %s", msg, buf)
			}
		})
	}
}

// RunTransportBenchmarkSuite executes speed tests and benchmarks (formerly cmd/speedtest).
func RunTransportBenchmarkSuite(b *testing.B, transportProto string, scenarios []SecurityScenario) {
	echoAddr := StartEchoServer()
	sinkAddr := StartSinkServer()
	// Limit source to 50MB for benchmark iterations
	sourceAddr := StartSourceServer(50 * 1024 * 1024)

	for _, tc := range scenarios {
		b.Run(tc.Name+"_Latency", func(b *testing.B) {
			serverCfg := config.DefaultServerConfig()
			serverCfg.Protocol = transportProto
			serverCfg.ListenAddr = FindFreeAddr()
			serverCfg.Security.EnableSSH = true
			serverCfg.Security.AuthToken = tc.ServerAuthToken
			serverCfg.Security.PrivateKeyPath = tc.ServerPrivateKey
			serverCfg.Security.AuthorizedClientKeys = tc.AuthorizedClientKeys

			go transport.StartServer(serverCfg)
			time.Sleep(500 * time.Millisecond)

			clientCfg := config.DefaultClientConfig()
			clientCfg.Protocol = transportProto
			clientCfg.RemoteAddr = serverCfg.ListenAddr
			clientCfg.AuthToken = tc.ClientAuthToken
			clientCfg.PrivateKeyPath = tc.ClientPrivateKey
			clientCfg.ServerPublicKey = tc.ServerPublicKey
			clientCfg.TLSMode = tc.TLSMode
			clientCfg.CustomSNI = tc.CustomSNI
			clientCfg.Fingerprint = tc.Fingerprint

			client := transport.NewClient(clientCfg)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				stream, err := client.Dial(protocol.ProtocolSSH, echoAddr)
				if err != nil {
					b.Fatalf("Failed to dial: %v", err)
				}
				stream.Write([]byte("ping"))
				buf := make([]byte, 4)
				stream.Read(buf)
				stream.Close()
			}
		})

		b.Run(tc.Name+"_Upload", func(b *testing.B) {
			serverCfg := config.DefaultServerConfig()
			serverCfg.Protocol = transportProto
			serverCfg.ListenAddr = FindFreeAddr()
			serverCfg.Security.EnableSSH = true
			serverCfg.Security.AuthToken = tc.ServerAuthToken
			serverCfg.Security.PrivateKeyPath = tc.ServerPrivateKey
			serverCfg.Security.AuthorizedClientKeys = tc.AuthorizedClientKeys

			go transport.StartServer(serverCfg)
			time.Sleep(500 * time.Millisecond)

			clientCfg := config.DefaultClientConfig()
			clientCfg.Protocol = transportProto
			clientCfg.RemoteAddr = serverCfg.ListenAddr
			clientCfg.AuthToken = tc.ClientAuthToken
			clientCfg.PrivateKeyPath = tc.ClientPrivateKey
			clientCfg.ServerPublicKey = tc.ServerPublicKey
			clientCfg.TLSMode = tc.TLSMode
			clientCfg.CustomSNI = tc.CustomSNI
			clientCfg.Fingerprint = tc.Fingerprint

			client := transport.NewClient(clientCfg)
			dataSize := 10 * 1024 * 1024 // 10MB per iteration
			chunk := make([]byte, 32*1024)

			b.SetBytes(int64(dataSize))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				stream, err := client.Dial(protocol.ProtocolSSH, sinkAddr)
				if err != nil {
					b.Fatalf("Failed to dial: %v", err)
				}
				totalWritten := 0
				for totalWritten < dataSize {
					n, err := stream.Write(chunk)
					totalWritten += n
					if err != nil {
						b.Fatalf("write failed after %d bytes: %v", totalWritten, err)
						break
					}
				}
				stream.Close()
			}
		})

		b.Run(tc.Name+"_Download", func(b *testing.B) {
			serverCfg := config.DefaultServerConfig()
			serverCfg.Protocol = transportProto
			serverCfg.ListenAddr = FindFreeAddr()
			serverCfg.Security.EnableSSH = true
			serverCfg.Security.AuthToken = tc.ServerAuthToken
			serverCfg.Security.PrivateKeyPath = tc.ServerPrivateKey
			serverCfg.Security.AuthorizedClientKeys = tc.AuthorizedClientKeys

			go transport.StartServer(serverCfg)
			time.Sleep(500 * time.Millisecond)

			clientCfg := config.DefaultClientConfig()
			clientCfg.Protocol = transportProto
			clientCfg.RemoteAddr = serverCfg.ListenAddr
			clientCfg.AuthToken = tc.ClientAuthToken
			clientCfg.PrivateKeyPath = tc.ClientPrivateKey
			clientCfg.ServerPublicKey = tc.ServerPublicKey
			clientCfg.TLSMode = tc.TLSMode
			clientCfg.CustomSNI = tc.CustomSNI
			clientCfg.Fingerprint = tc.Fingerprint

			client := transport.NewClient(clientCfg)
			dataSize := 10 * 1024 * 1024 // 10MB per iteration
			buf := make([]byte, 32*1024)

			b.SetBytes(int64(dataSize))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				stream, err := client.Dial(protocol.ProtocolSSH, sourceAddr)
				if err != nil {
					b.Fatalf("Failed to dial: %v", err)
				}
				received := 0
				for received < dataSize {
					n, err := stream.Read(buf)
					if n > 0 {
						received += n
					}
					if err != nil {
						break
					}
				}
				stream.Close()
			}
		})
	}
}
