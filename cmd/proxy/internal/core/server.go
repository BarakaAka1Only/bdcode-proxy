package core

import (
	"context"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

// Server is the generic TCP proxy server.
// It depends ONLY on interfaces, not concrete implementations.
type Server struct {
	Listener        net.Listener
	Resolver        BackendResolver
	ProtocolHandler ProtocolHandler
}

// Serve starts accepting connections.
func (s *Server) Serve() error {
	for {
		conn, err := s.Listener.Accept()
		if err != nil {
			return err
		}
		go s.handleConnection(conn)
	}
}

func (s *Server) handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	// 1. Protocol Handshake (Protocol Logic)
	// The proxy doesn't know if this is Postgres or MySQL.
	metadata, clientConn, err := s.ProtocolHandler.Handshake(clientConn)
	if err != nil {
		log.Printf("Handshake failed: %v", err)
		return
	}

	// 2. Resolve Backend (Discovery Logic)
	// The proxy doesn't know if this is Kubernetes or a static file.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	backendAddr, err := s.Resolver.Resolve(ctx, metadata)
	if err != nil {
		log.Printf("Resolution failed: %v", err)
		return
	}

	// 3. Dial Backend (Network Logic)
	backendConn, err := net.Dial("tcp", backendAddr)
	if err != nil {
		log.Printf("Dial failed to %s: %v", backendAddr, err)
		return
	}
	defer backendConn.Close()

	// 3.5. Forward Startup Message (if present in metadata)
	if rawMsg, ok := metadata["_raw_startup_message"]; ok {
		if _, err := backendConn.Write([]byte(rawMsg)); err != nil {
			log.Printf("Failed to forward startup message: %v", err)
			return
		}
	}

	// 4. Pipe Data (Proxy Logic)
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(backendConn, clientConn)
	}()

	go func() {
		defer wg.Done()
		io.Copy(clientConn, backendConn)
	}()

	wg.Wait()
}
