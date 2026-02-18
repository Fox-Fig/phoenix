package socks5

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
)

// HandleUDPTunnel handles the server-side logic for a UDP tunnel stream.
// It reads encapsulated UDP packets from the stream, sends them to the target,
// and relays responses back.
func HandleUDPTunnel(stream io.ReadWriteCloser) error {
	defer stream.Close()

	// 1. Create a local UDP socket for this session
	udpConn, err := net.ListenPacket("udp", ":0")
	if err != nil {
		return fmt.Errorf("failed to bind udp socket: %v", err)
	}
	defer udpConn.Close()

	// Increase socket buffers to handle bursts (e.g. YouTube QUIC)
	if c, ok := udpConn.(*net.UDPConn); ok {
		c.SetReadBuffer(4 * 1024 * 1024)
		c.SetWriteBuffer(4 * 1024 * 1024)
	}

	// 2. Stream -> UDP Loop
	errChan := make(chan error, 2)
	go func() {
		header := make([]byte, 2)
		for {
			// Read Length
			if _, err := io.ReadFull(stream, header); err != nil {
				log.Printf("[SOCKS5-UDP-Server] Stream read error: %v", err)
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
				errChan <- err
				return
			}

			// Parse SOCKS5 UDP Header to extract Destination
			// Format: [RSV][FRAG][ATYP][DST.ADDR][DST.PORT][DATA]
			if len(pktBuf) < 10 { // Min header size (IPv4)
				log.Printf("[SOCKS5-UDP] Packet too short")
				continue
			}

			// Offset 3 is ATYP
			atyp := pktBuf[3]
			var destAddr string
			var dataOffset int

			switch atyp {
			case 0x01: // IPv4
				if len(pktBuf) < 10 {
					continue
				}
				ip := net.IP(pktBuf[4:8])
				port := binary.BigEndian.Uint16(pktBuf[8:10])
				destAddr = fmt.Sprintf("%s:%d", ip, port)
				dataOffset = 10
			case 0x03: // Domain
				if len(pktBuf) < 5 {
					continue
				}
				domainLen := int(pktBuf[4])
				if len(pktBuf) < 5+domainLen+2 {
					continue
				}
				domain := string(pktBuf[5 : 5+domainLen])
				port := binary.BigEndian.Uint16(pktBuf[5+domainLen : 5+domainLen+2])
				destAddr = fmt.Sprintf("%s:%d", domain, port)
				dataOffset = 5 + domainLen + 2
			case 0x04: // IPv6
				if len(pktBuf) < 22 {
					continue
				}
				ip := net.IP(pktBuf[4:20])
				port := binary.BigEndian.Uint16(pktBuf[20:22])
				destAddr = fmt.Sprintf("[%s]:%d", ip, port)
				dataOffset = 22
			default:
				log.Printf("[SOCKS5-UDP] Unknown ATYP %d", atyp)
				continue
			}

			// Resolve Address
			uAddr, err := net.ResolveUDPAddr("udp", destAddr)
			if err != nil {
				log.Printf("[SOCKS5-UDP] Resolve error for %s: %v", destAddr, err)
				continue
			}

			// Payload
			payload := pktBuf[dataOffset:]

			// Write to Target
			if _, err := udpConn.WriteTo(payload, uAddr); err != nil {
				log.Printf("[SOCKS5-UDP] WriteTo error: %v", err)
				// Don't kill stream on single packet error
				continue
			}
		}
	}()

	// 3. UDP -> Stream Loop
	go func() {
		buf := make([]byte, 65535)
		for {
			n, peerAddr, err := udpConn.ReadFrom(buf)
			if err != nil {
				log.Printf("[SOCKS5-UDP-Server] ReadFrom UDP error: %v", err)
				errChan <- err
				return
			}

			// Construct SOCKS5 UDP Packet
			// We need to encode peerAddr back into SOCKS5 headers.
			// Format: [RSV=0][FRAG=0][ATYP][ADDR][PORT][DATA]
			//
			// peerAddr is net.Addr. usually *net.UDPAddr.
			udpAddr, ok := peerAddr.(*net.UDPAddr)
			if !ok {
				continue
			}

			ip := udpAddr.IP
			port := udpAddr.Port

			var header []byte
			if ip4 := ip.To4(); ip4 != nil {
				header = make([]byte, 10)
				header[3] = 0x01 // IPv4
				copy(header[4:], ip4)
				binary.BigEndian.PutUint16(header[8:], uint16(port))
			} else {
				header = make([]byte, 22) // IPv6
				header[3] = 0x04
				copy(header[4:], ip)
				binary.BigEndian.PutUint16(header[20:], uint16(port))
			}

			// Pkt = Header + Data
			totalLen := len(header) + n

			// Write Stream: [Len][Header][Data] in single write for atomicity
			packet := make([]byte, 2+len(header)+n)
			binary.BigEndian.PutUint16(packet, uint16(totalLen))
			copy(packet[2:], header)
			copy(packet[2+len(header):], buf[:n])

			if _, err := stream.Write(packet); err != nil {
				log.Printf("[SOCKS5-UDP-Server] Failed to write to stream: %v", err)
				errChan <- err
				return
			}
		}
	}()

	err = <-errChan
	log.Printf("[SOCKS5-UDP-Server] Closing session due to: %v", err)
	return err
}
