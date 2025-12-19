package postgresql

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"

	"strings"

	"github.com/hasirciogluhq/xdatabase-proxy/cmd/proxy/internal/core"
)

const (
	sslRequestCode = 80877103
)

type PostgresHandler struct {
	TLSConfig *tls.Config
}

func (h *PostgresHandler) Handshake(conn net.Conn) (core.RoutingMetadata, net.Conn, error) {
	// Read message length (4 bytes)
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, nil, fmt.Errorf("failed to read message length: %w", err)
	}

	length := int32(binary.BigEndian.Uint32(header))
	if length < 4 {
		return nil, nil, fmt.Errorf("invalid message length: %d", length)
	}

	// Read message body
	payload := make([]byte, length-4)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return nil, nil, fmt.Errorf("failed to read message body: %w", err)
	}

	// Check for SSLRequest
	if len(payload) >= 4 {
		code := int32(binary.BigEndian.Uint32(payload[0:4]))
		if code == sslRequestCode {
			// Send 'S' to accept SSL
			if _, err := conn.Write([]byte{'S'}); err != nil {
				return nil, nil, fmt.Errorf("failed to write SSL response: %w", err)
			}

			// Upgrade connection
			tlsConn := tls.Server(conn, h.TLSConfig)
			if err := tlsConn.Handshake(); err != nil {
				return nil, nil, fmt.Errorf("tls handshake failed: %w", err)
			}

			// Recursively parse the StartupMessage from the encrypted stream
			return h.Handshake(tlsConn)
		}
	}

	// Parse StartupMessage
	// Format: Protocol(4 bytes) + Key\0Value\0...
	if len(payload) < 4 {
		return nil, nil, fmt.Errorf("payload too short")
	}

	params := make(map[string]string)
	buf := bytes.NewBuffer(payload[4:]) // Skip protocol version

	for {
		key, err := buf.ReadString(0)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, err
		}
		key = key[:len(key)-1] // Trim null byte

		if key == "" {
			break
		}

		value, err := buf.ReadString(0)
		if err != nil {
			return nil, nil, fmt.Errorf("malformed startup message")
		}
		value = value[:len(value)-1] // Trim null byte

		params[key] = value
	}

	// Parse username to extract deployment_id and pool status
	// Format: username.deployment_id[.pool]
	if user, ok := params["user"]; ok {
		parts := strings.Split(user, ".")
		if len(parts) >= 2 {
			// Check for .pool suffix
			if parts[len(parts)-1] == "pool" {
				params["pooled"] = "true"
				if len(parts) >= 3 {
					params["deployment_id"] = parts[len(parts)-2]
					params["username"] = strings.Join(parts[:len(parts)-2], ".")
				}
			} else {
				params["pooled"] = "false"
				params["deployment_id"] = parts[len(parts)-1]
				params["username"] = strings.Join(parts[:len(parts)-1], ".")
			}
		} else {
			// Fallback or default behavior if format doesn't match
			// Maybe treat the whole user as username and no deployment_id?
			// Or fail? For now, let's just keep it as is, resolver might fail.
			params["pooled"] = "false"
		}
	}

	return core.RoutingMetadata(params), conn, nil
}
