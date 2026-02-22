package crypto

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"
)

// GenerateToken generates a cryptographically secure random token (32 bytes, hex encoded).
func GenerateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// GenerateKeypair generates a new Ed25519 keypair.
// Returns PEM encoded private key and Base64 encoded public key.
func GenerateKeypair() (privPEM []byte, pubKeyStr string, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", err
	}

	// Encode Private Key to PEM
	pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, "", err
	}
	privPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkcs8Bytes,
	})

	// Encode Public Key to Base64
	pubKeyStr = base64.StdEncoding.EncodeToString(pub)
	return privPEM, pubKeyStr, nil
}

// LoadPrivateKey loads a private key from a PEM file.
func LoadPrivateKey(path string) (crypto.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block containing private key")
	}

	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %v", err)
	}

	return priv, nil
}

// GenerateTLSCertificate creates a self-signed TLS certificate using the given private key.
func GenerateTLSCertificate(priv crypto.PrivateKey) (tls.Certificate, error) {
	// Determine public key
	var pub crypto.PublicKey
	switch k := priv.(type) {
	case ed25519.PrivateKey:
		pub = k.Public()
	default:
		return tls.Certificate{}, fmt.Errorf("unsupported key type")
	}

	// Create Certificate Template
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Phoenix Secure Tunnel"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(100 * 365 * 24 * time.Hour), // 100 years

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, pub, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	// Create tls.Certificate
	cert := tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}
	return cert, nil
}

// ParsePublicKey parses a Base64 encoded public key.
func ParsePublicKey(pubKeyStr string) (crypto.PublicKey, error) {
	pubBytes, err := base64.StdEncoding.DecodeString(pubKeyStr)
	if err != nil {
		return nil, err
	}
	if len(pubBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key size")
	}
	return ed25519.PublicKey(pubBytes), nil
}
