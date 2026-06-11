package ssh

import (
	"fmt"
	"io"
	"net"
	"phoenix/pkg/utils"
)

// Dialer abstracts the connection creation for SSH tunnels.
type Dialer interface {
	Dial(network, addr string) (net.Conn, error)
}

// NetDialer implements Dialer using standard net.Dial.
type NetDialer struct{}

func (d *NetDialer) Dial(network, addr string) (net.Conn, error) {
	return net.Dial(network, addr)
}

// HandleConnection receives an SSH connection from the client and proxies it to the target.
// Note: Standard SSH connects to a specific server.
// If the H2C stream contains an SSH handshake, we need to know WHERE to connect.
// SSH protocol itself has a destination host in the initial packet? No.
// SSH connects to a *server*. The server must be the endpoint.
// So, if the client connects to Phoenix Client (SSH Inbound),
// Phoenix Client connects to Phoenix Server (H2C Tunnel).
// Phoenix Server effectively BECOMES the SSH server endpoint.
// OR, Phoenix Server forwards the SSH traffic to a specific backend SSH server (e.g. localhost:22).
//
// In this implementation, we assume the Server IS the SSH endpoint or forwards to localhost:22.
// Alternatively, if the client provides a target address (TargetAddr in config),
// the client sends it in a header? No, SSH protocol doesn't include target.
//
// BUT `client.toml` has `target_addr` (optional).
// If `target_addr` is set on Client Inbound, the client sends this target to Server in a header.
// The Server uses this target to dial the real SSH server.
//
// Let's modify the H2C protocol to include a Target header.
// `X-Nerve-Target: host:port`
func HandleConnection(rw io.ReadWriteCloser, target string, dialer Dialer) error {
	defer rw.Close()

	if target == "" {
		// Default to localhost SSH if no target specified?
		target = "127.0.0.1:22"
	}

	// log.Printf("[SSH] Tunneling to %s", target)
	destConn, err := dialer.Dial("tcp", target)
	if err != nil {
		return fmt.Errorf("failed to dial SSH target %s: %v", target, err)
	}
	defer destConn.Close()

	// Bidirectional copy using high-throughput 128KB relay buffer
	return utils.Relay(rw, destConn)
}
