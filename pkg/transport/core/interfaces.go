package core

import (
	"io"
	"net"

	"phoenix/pkg/protocol"
)

// StreamHandler is the callback function that the transport protocol
// invokes when a new, fully established stream is ready.
type StreamHandler func(stream io.ReadWriteCloser, target string, innerProtocol protocol.ProtocolType)

// ServerTransport defines the standard interface for any transport protocol server (e.g., H2, WebSocket, SSH).
type ServerTransport interface {
	// Serve begins accepting connections on the provided net.Listener.
	// It extracts inner streams and passes them to the StreamHandler.
	Serve(l net.Listener, handler StreamHandler) error

	// Close shuts down the server.
	Close() error
}

// ClientTransport defines the standard interface for any transport protocol client.
type ClientTransport interface {
	// Dial connects to the target server and establishes a new multiplexed stream.
	// In the new architecture, the ClientTransport manages its own connections via the Underlay.
	Dial(innerProtocol protocol.ProtocolType, target string) (io.ReadWriteCloser, error)

	// Close shuts down the client and any idle connections.
	Close() error
}
