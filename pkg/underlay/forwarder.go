package underlay

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"phoenix/pkg/utils"
)

// StartPortForwarder starts both TCP and UDP forwarders on the same port.
func StartPortForwarder(listenAddr, targetAddr string) error {
	var wg sync.WaitGroup
	wg.Add(2)

	errChan := make(chan error, 2)

	go func() {
		defer wg.Done()
		errChan <- startTCPForwarder(listenAddr, targetAddr)
	}()

	go func() {
		defer wg.Done()
		errChan <- startUDPForwarder(listenAddr, targetAddr)
	}()

	// If any of the listeners fail to start, return the error.
	err := <-errChan
	return err
}

func startTCPForwarder(listenAddr, targetAddr string) error {
	l, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("TCP listen failed: %v", err)
	}
	defer l.Close()
	log.Printf("[Forwarder] TCP listening on %s", listenAddr)

	for {
		conn, err := l.Accept()
		if err != nil {
			log.Printf("[Forwarder] TCP accept error: %v", err)
			continue
		}
		go handleTCPForward(conn, targetAddr)
	}
}

func handleTCPForward(src net.Conn, targetAddr string) {
	defer src.Close()

	dst, err := net.Dial("tcp", targetAddr)
	if err != nil {
		log.Printf("[Forwarder] TCP dial to %s failed: %v", targetAddr, err)
		return
	}
	defer dst.Close()

	// utils.Relay handles bidirectional copy between the connections.
	err = utils.Relay(src, dst)
	if err != nil && !utils.ContainsExpectedTeardownError(err.Error()) {
		log.Printf("[Forwarder] TCP relay error: %v", err)
	}
}

// udpSession holds the connection to the target for a specific client.
type udpSession struct {
	dstConn *net.UDPConn
	lastUse time.Time
}

func startUDPForwarder(listenAddr, targetAddr string) error {
	addr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return fmt.Errorf("UDP resolve failed: %v", err)
	}

	l, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("UDP listen failed: %v", err)
	}
	defer l.Close()
	log.Printf("[Forwarder] UDP listening on %s", listenAddr)

	targetUDPAddr, err := net.ResolveUDPAddr("udp", targetAddr)
	if err != nil {
		return fmt.Errorf("UDP target resolve failed: %v", err)
	}

	sessions := sync.Map{} // map[string]*udpSession

	// Cleanup goroutine to remove inactive UDP sessions
	go func() {
		for {
			time.Sleep(1 * time.Minute)
			now := time.Now()
			sessions.Range(func(key, value interface{}) bool {
				session := value.(*udpSession)
				if now.Sub(session.lastUse) > 5*time.Minute {
					session.dstConn.Close()
					sessions.Delete(key)
				}
				return true
			})
		}
	}()

	buf := make([]byte, 65535)
	for {
		n, clientAddr, err := l.ReadFromUDP(buf)
		if err != nil {
			log.Printf("[Forwarder] UDP read error: %v", err)
			continue
		}

		clientKey := clientAddr.String()
		val, ok := sessions.Load(clientKey)

		var session *udpSession
		if !ok {
			// Create a new session for this client to the target
			dstConn, err := net.DialUDP("udp", nil, targetUDPAddr)
			if err != nil {
				log.Printf("[Forwarder] UDP dial to %s failed: %v", targetAddr, err)
				continue
			}

			session = &udpSession{
				dstConn: dstConn,
				lastUse: time.Now(),
			}
			sessions.Store(clientKey, session)

			// Start a dedicated goroutine to read from target and send back to this specific client
			go func(cAddr *net.UDPAddr, dConn *net.UDPConn) {
				dBuf := make([]byte, 65535)
				for {
					dConn.SetReadDeadline(time.Now().Add(5 * time.Minute))
					dn, err := dConn.Read(dBuf)
					if err != nil {
						// Timeout or connection closed
						dConn.Close()
						sessions.Delete(cAddr.String())
						return
					}

					// Send response back to the client using the main listener
					l.WriteToUDP(dBuf[:dn], cAddr)

					// Update last use timestamp
					if s, ok := sessions.Load(cAddr.String()); ok {
						s.(*udpSession).lastUse = time.Now()
					}
				}
			}(clientAddr, dstConn)
		} else {
			session = val.(*udpSession)
			session.lastUse = time.Now()
		}

		// Forward the incoming packet to the target
		_, err = session.dstConn.Write(buf[:n])
		if err != nil {
			log.Printf("[Forwarder] UDP write to target error: %v", err)
			session.dstConn.Close()
			sessions.Delete(clientKey)
		}
	}
}
