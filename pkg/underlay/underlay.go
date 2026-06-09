package underlay

import (
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net"

	"phoenix/pkg/crypto"

	utls "github.com/refraction-networking/utls"
)

// ServerConfig contains the underlay settings for the server
type ServerConfig struct {
	TLSEnabled           bool
	PrivateKeyPath       string
	AuthorizedClientKeys []string
	AllowedSNI           []string
	AllowEmptySNI        bool
	NextProtos           []string
}

// ClientConfig contains the underlay settings for the client
type ClientConfig struct {
	TLSEnabled      bool
	TLSMode         string // "system", "insecure", "" (pinning)
	PrivateKeyPath  string
	ServerPublicKey string
	Fingerprint     string
	CustomSNI       string
	NextProtos      []string
}

// Listen opens a net.Listener based on the underlay configuration (TLS or Cleartext).
func Listen(addr string, cfg ServerConfig) (net.Listener, error) {
	if !cfg.TLSEnabled {
		log.Printf("[Underlay] Starting in CLEARTEXT mode on %s", addr)
		return net.Listen("tcp", addr)
	}

	if cfg.PrivateKeyPath == "" {
		return nil, errors.New("TLS is enabled but private_key is not specified")
	}

	priv, err := crypto.LoadPrivateKey(cfg.PrivateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load private key: %v", err)
	}

	cert, err := crypto.GenerateTLSCertificate(priv)
	if err != nil {
		return nil, fmt.Errorf("failed to generate TLS certificate: %v", err)
	}

	authorizedKeys := make(map[string]bool)
	for _, k := range cfg.AuthorizedClientKeys {
		authorizedKeys[k] = true
	}

	var clientAuth tls.ClientAuthType
	var verifyPeer func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error

	if len(authorizedKeys) > 0 {
		log.Printf("[Underlay] SECURE mode (mTLS) with %d authorized clients", len(authorizedKeys))
		clientAuth = tls.RequireAnyClientCert
		verifyPeer = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("no client certificate provided")
			}
			leaf, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return fmt.Errorf("failed to parse client certificate: %v", err)
			}

			pub := leaf.PublicKey
			pubBytes, ok := pub.(ed25519.PublicKey)
			if !ok {
				return errors.New("unsupported public key type (expected Ed25519)")
			}

			pubStr := base64.StdEncoding.EncodeToString(pubBytes)
			if !authorizedKeys[pubStr] {
				return fmt.Errorf("unauthorized client key: %s", pubStr)
			}
			return nil
		}
	} else {
		log.Println("[Underlay] ONE-WAY TLS mode (No Client Auth)")
		clientAuth = tls.NoClientCert
	}

	protos := cfg.NextProtos
	if len(protos) == 0 {
		protos = []string{"h2"} // Default for compatibility
	}

	tlsConfig := &tls.Config{
		Certificates:          []tls.Certificate{cert},
		ClientAuth:            clientAuth,
		NextProtos:            protos,
		VerifyPeerCertificate: verifyPeer,
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			if len(cfg.AllowedSNI) > 0 {
				allowed := false
				if hello.ServerName == "" && cfg.AllowEmptySNI {
					allowed = true
				} else {
					for _, sni := range cfg.AllowedSNI {
						if sni == "*" || hello.ServerName == sni {
							allowed = true
							break
						}
					}
				}

				if !allowed {
					log.Printf("[TLS] Dropped connection with unauthorized SNI: '%s'", hello.ServerName)
					return nil, fmt.Errorf("unrecognized SNI: %s", hello.ServerName)
				}
			} else if !cfg.AllowEmptySNI && hello.ServerName == "" {
				log.Printf("[TLS] Dropped connection with empty SNI (not allowed by config)")
				return nil, fmt.Errorf("empty SNI not allowed")
			}
			return nil, nil
		},
	}

	log.Printf("[Underlay] Listening (TLS) on %s", addr)
	return tls.Listen("tcp", addr, tlsConfig)
}

// Dial opens a net.Conn based on the client underlay configuration (TLS with uTLS or Cleartext).
func Dial(addr string, cfg ClientConfig) (net.Conn, error) {
	if !cfg.TLSEnabled {
		return net.Dial("tcp", addr)
	}

	host, _, _ := net.SplitHostPort(addr)
	if host == "" {
		host = addr
	}
	if cfg.CustomSNI != "" {
		host = cfg.CustomSNI
	}

	protos := cfg.NextProtos
	if len(protos) == 0 {
		protos = []string{"h2"} // Default
	}

	var baseTLS *tls.Config

	if cfg.TLSMode == "system" {
		baseTLS = &tls.Config{}
	} else if cfg.TLSMode == "insecure" {
		baseTLS = &tls.Config{InsecureSkipVerify: true} //nolint:gosec
	} else {
		// Secure Pinning Mode
		var certs []tls.Certificate
		if cfg.PrivateKeyPath != "" {
			priv, err := crypto.LoadPrivateKey(cfg.PrivateKeyPath)
			if err == nil {
				cert, err := crypto.GenerateTLSCertificate(priv)
				if err == nil {
					certs = []tls.Certificate{cert}
				}
			}
		}

		baseTLS = &tls.Config{
			Certificates:       certs,
			InsecureSkipVerify: true,
			VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
				if cfg.ServerPublicKey == "" {
					return nil
				}
				if len(rawCerts) == 0 {
					return errors.New("no server certificate presented")
				}
				leaf, err := x509.ParseCertificate(rawCerts[0])
				if err != nil {
					return err
				}
				pubBytes, ok := leaf.PublicKey.(ed25519.PublicKey)
				if !ok {
					return errors.New("server key is not Ed25519")
				}
				pubStr := base64.StdEncoding.EncodeToString(pubBytes)
				if pubStr != cfg.ServerPublicKey {
					return fmt.Errorf("server key verification failed")
				}
				return nil
			},
		}
	}

	baseTLS.NextProtos = protos
	baseTLS.ServerName = host

	if cfg.Fingerprint == "" {
		return tls.Dial("tcp", addr, baseTLS)
	}

	rawConn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}

	utlsCfg := &utls.Config{
		ServerName:         host,
		InsecureSkipVerify: baseTLS.InsecureSkipVerify, //nolint:gosec
		NextProtos:         baseTLS.NextProtos,
	}
	if baseTLS.RootCAs != nil {
		utlsCfg.RootCAs = baseTLS.RootCAs
	}

	uConn := utls.UClient(rawConn, utlsCfg, pickHelloID(cfg.Fingerprint))

	if cfg.Fingerprint == "chrome_dynamic" {
		if err := uConn.BuildHandshakeState(); err == nil {
			for _, ext := range uConn.Extensions {
				if greaseExt, ok := ext.(*utls.UtlsGREASEExtension); ok {
					greaseValues := []uint16{
						0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
						0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
					}
					greaseExt.Value = greaseValues[rand.Intn(len(greaseValues))]
				}
			}
		}
	}

	if err := uConn.Handshake(); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("utls handshake failed: %v", err)
	}

	if baseTLS.VerifyPeerCertificate != nil {
		state := uConn.ConnectionState()
		rawCerts := make([][]byte, len(state.PeerCertificates))
		for i, c := range state.PeerCertificates {
			rawCerts[i] = c.Raw
		}
		if err := baseTLS.VerifyPeerCertificate(rawCerts, nil); err != nil {
			uConn.Close()
			return nil, err
		}
	}

	return uConn, nil
}

func pickHelloID(fp string) utls.ClientHelloID {
	switch fp {
	case "firefox":
		return utls.HelloFirefox_Auto
	case "safari":
		return utls.HelloSafari_Auto
	case "random":
		return utls.HelloRandomized
	case "random_chrome":
		chromeVersions := []utls.ClientHelloID{
			utls.HelloChrome_133,
			utls.HelloChrome_131,
			utls.HelloChrome_120,
		}
		return chromeVersions[rand.Intn(len(chromeVersions))]
	case "chrome_dynamic":
		return utls.HelloChrome_Auto
	default:
		return utls.HelloChrome_Auto
	}
}
