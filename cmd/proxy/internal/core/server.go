package core

import (
	"context"
	"io"
	"net"
	"sync"
	"time"

	"github.com/hasirciogluhq/xdatabase-proxy/cmd/proxy/internal/logger"
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
		logger.Error("Handshake failed", "error", err, "remote_addr", clientConn.RemoteAddr())
		return
	}

	// 2. Resolve Backend (Discovery Logic)
	// The proxy doesn't know if this is Kubernetes or a static file.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	backendAddr, err := s.Resolver.Resolve(ctx, metadata)
	if err != nil {
		logger.Error("Resolution failed", "error", err, "remote_addr", clientConn.RemoteAddr())
		return
	}

	// 3. Dial Backend (Network Logic)
	backendConn, err := net.Dial("tcp", backendAddr)
	if err != nil {
		logger.Error("Dial failed", "backend_addr", backendAddr, "error", err, "remote_addr", clientConn.RemoteAddr())
		return
	}
	defer backendConn.Close()

	// 3.5. Forward Startup Message (if present in metadata)
	if rawMsg, ok := metadata["_raw_startup_message"]; ok {
		if _, err := backendConn.Write([]byte(rawMsg)); err != nil {
			logger.Error("Failed to forward startup message", "error", err, "remote_addr", clientConn.RemoteAddr())
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
