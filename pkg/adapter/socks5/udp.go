package socks5

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
)

// HandleUDP establishes a UDP relay.
// conn: The client TCP connection (must stay open).
// dialer: The strategy to verify target connectivity (or tunnel).
// clientAddr: The address of the client requesting UDP.
// header: The client's UDP request header containing initial destination (optional/ignored for ASSOCIATE usually).
func HandleUDP(conn io.ReadWriteCloser, dialer Dialer) error {
	// 1. Listen on a random UDP port
	udpConn, err := net.ListenPacket("udp", ":0")
	if err != nil {
		return fmt.Errorf("failed to listen on UDP: %v", err)
	}
	defer udpConn.Close()

	if c, ok := udpConn.(*net.UDPConn); ok {
		c.SetReadBuffer(4 * 1024 * 1024)
		c.SetWriteBuffer(4 * 1024 * 1024)
	}

	addr := udpConn.LocalAddr().(*net.UDPAddr)
	log.Printf("[SOCKS5] UDP Associate bound to %s", addr)

	// 2. Send Reply: BND.ADDR and BND.PORT
	// We need IP and Port separate.
	// Assume IPv4 for simplicity or extract from addr.
	ip := addr.IP.To4()
	if ip == nil {
		ip = addr.IP.To16()
	}
	// Reply format: [VER, REP, RSV, ATYP, BND.ADDR, BND.PORT]
	// REP=00 (Success)
	reply := make([]byte, 4+len(ip)+2)
	reply[0] = 0x05
	reply[1] = 0x00
	reply[2] = 0x00
	if len(ip) == 4 {
		reply[3] = 0x01
	} else {
		reply[3] = 0x04
	}
	copy(reply[4:], ip)
	binary.BigEndian.PutUint16(reply[4+len(ip):], uint16(addr.Port))

	if _, err := conn.Write(reply); err != nil {
		return fmt.Errorf("failed to write UDP reply: %v", err)
	}

	// 3. Keep TCP Connection open and monitor UDP
	// The TCP connection serves as a keep-alive signal.

	// Create a tunnel stream to Server for UDP traffic
	// We initiate ONE stream for this association.
	stream, err := dialer.Dial("udp-tunnel")
	if err != nil {
		return fmt.Errorf("failed to dial UDP tunnel: %v", err)
	}
	defer stream.Close()

	// 4. Relay Loop
	errChan := make(chan error, 2)

	// Address Cache: To know where to send responses back to (Client UDP Addr)
	var clientUDPAddr net.Addr
	var mu sync.Mutex

	// UDP -> Stream
	go func() {
		buf := make([]byte, 65535) // Max UDP size
		for {
			n, peerAddr, err := udpConn.ReadFrom(buf)
			if err != nil {
				errChan <- err
				return
			}

			// Store Client Address
			mu.Lock()
			if clientUDPAddr == nil || clientUDPAddr.String() != peerAddr.String() {
				clientUDPAddr = peerAddr
				log.Printf("[SOCKS5-UDP] Client Address set to: %s", peerAddr)
			}
			mu.Unlock()

			// Validate packet
			if n < 3 {
				continue // Too short
			}
			frag := buf[2]
			if frag != 0x00 {
				log.Printf("[SOCKS5] UDP Frag %d not supported", frag)
				continue
			}

			// Encapsulate into Stream: [Length (2 bytes)][Packet]
			// Packet is buf[:n] (the SOCKS5 UDP request as is).

			// Write length
			packet := make([]byte, 2+n)
			binary.BigEndian.PutUint16(packet, uint16(n))
			copy(packet[2:], buf[:n])

			if _, err := stream.Write(packet); err != nil {
				log.Printf("[SOCKS5-UDP] Failed to write to stream: %v", err)
				errChan <- err
				return
			}
		}
	}()

	// Stream -> UDP
	go func() {
		header := make([]byte, 2)
		for {
			// Read Length
			if _, err := io.ReadFull(stream, header); err != nil {
				errChan <- err
				return
			}
			pktLen := int(binary.BigEndian.Uint16(header))
			if pktLen > 65535 {
				errChan <- fmt.Errorf("packet too large: %d", pktLen)
				return
			}

			pktBuf := make([]byte, pktLen)
			if _, err := io.ReadFull(stream, pktBuf); err != nil {
				log.Printf("[SOCKS5-UDP] Failed to read packet body from stream: %v", err)
				errChan <- err
				return
			}

			// The packet is a SOCKS5 UDP header + Data.
			// Currently we trust Server to send correct packets.

			// Send to Client
			mu.Lock()
			target := clientUDPAddr
			mu.Unlock()

			if target != nil {
				if _, err := udpConn.WriteTo(pktBuf, target); err != nil {
					log.Printf("[SOCKS5-UDP] WriteTo error: %v", err)
					// Don't error out on single packet failure
				}
			} else {
				log.Printf("[SOCKS5-UDP] Dropped packet, client address unknown")
			}
		}
	}()

	// Wait for TCP close
	go func() {
		buf := make([]byte, 1024)
		for {
			_, err := conn.Read(buf)
			if err != nil {
				// EOF or Connection Reset
				errChan <- fmt.Errorf("tcp control connection closed: %v", err)
				return
			}
			// If data is received (e.g. Keep-Alive), ignore it and continue reading.
			// RFC 1928 doesn't specify data on control conn, but robustness is key.
		}
	}()

	return <-errChan
}
