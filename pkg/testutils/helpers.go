package testutils

import (
	"io"
	"log"
	"net"
)

// StartEchoServer starts a local TCP server that echoes back all received data.
func StartEchoServer() string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go io.Copy(c, c)
		}
	}()
	return ln.Addr().String()
}

// StartSinkServer starts a local TCP server that reads and discards all received data.
func StartSinkServer() string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go io.Copy(io.Discard, c)
		}
	}()
	return ln.Addr().String()
}

// StartSourceServer starts a local TCP server that endlessly writes data up to a limit.
func StartSourceServer(limit int) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				data := make([]byte, 32*1024)
				written := 0
				for written < limit {
					n, err := conn.Write(data)
					if err != nil {
						return
					}
					written += n
				}
			}(c)
		}
	}()
	return ln.Addr().String()
}

// FindFreeAddr returns an available TCP address on localhost.
func FindFreeAddr() string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	return addr
}
