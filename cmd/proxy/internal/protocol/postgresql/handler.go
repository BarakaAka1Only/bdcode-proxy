package postgresql

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"

	"log"
	"strings"

	"github.com/hasirciogluhq/xdatabase-proxy/cmd/proxy/internal/core"
)

const (
	sslRequestCode = 80877103
)

// ErrorResponse represents a PostgreSQL error response
type ErrorResponse struct {
	Severity string
	Code     string
	Message  string
}

type PostgresHandler struct {
	TLSConfig *tls.Config
}

func (h *PostgresHandler) sendErrorResponse(conn net.Conn, errResp *ErrorResponse) error {
	var msgData []byte
	msgData = append(msgData, 'S')
	msgData = append(msgData, []byte(errResp.Severity)...)
	msgData = append(msgData, 0)
	msgData = append(msgData, 'C')
	msgData = append(msgData, []byte(errResp.Code)...)
	msgData = append(msgData, 0)
	msgData = append(msgData, 'M')
	msgData = append(msgData, []byte(errResp.Message)...)
	msgData = append(msgData, 0)
	msgData = append(msgData, 0) // Final null terminator

	msg := make([]byte, 1+4+len(msgData))
	msg[0] = 'E'
	binary.BigEndian.PutUint32(msg[1:5], uint32(4+len(msgData)))
	copy(msg[5:], msgData)

	_, writeErr := conn.Write(msg)
	if writeErr != nil {
		log.Printf("Error sending error response to %s: %v", conn.RemoteAddr(), writeErr)
	} else {
		log.Printf("Sent error response to %s: Sev=%s Code=%s Msg=%s", conn.RemoteAddr(), errResp.Severity, errResp.Code, errResp.Message)
	}
	return writeErr
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
				_ = h.sendErrorResponse(conn, &ErrorResponse{
					Severity: "FATAL",
					Code:     "08006",
					Message:  fmt.Sprintf("TLS handshake failed: %v", err),
				})
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

	// Rebuild startup message with modified username if needed
	// Note: The current implementation returns metadata and the connection.
	// The actual forwarding logic (which needs the rebuilt message) is likely in the Server loop.
	// However, the ProtocolHandler interface currently only returns metadata and conn.
	// If we need to modify the startup message sent to the backend, we might need to store it in metadata
	// or change the interface.
	// For now, let's store the raw rebuilt message in metadata with a special key if we modified the user.

	if originalUser, ok := params["user"]; ok {
		if newUser, ok := params["username"]; ok && newUser != originalUser {
			// We modified the username, so we need to rebuild the startup message
			// Use the original protocol version from payload
			protocolVersion := binary.BigEndian.Uint32(payload[0:4])

			// Create a copy of params for rebuilding to avoid modifying the map used for metadata
			buildParams := make(map[string]string)
			for k, v := range params {
				// Filter out internal metadata keys
				if k != "deployment_id" && k != "pooled" && k != "username" {
					buildParams[k] = v
				}
			}
			// Use the new username
			buildParams["user"] = newUser

			rebuiltMsg := rebuildStartupMessage(protocolVersion, buildParams)
			params["_raw_startup_message"] = string(rebuiltMsg)
		} else {
			// If we didn't modify the username, we can just use the original payload (plus header)
			// But wait, the payload variable doesn't include the length header.
			// And the Server likely expects to just forward bytes?
			// The current Server implementation probably reads from the returned conn.
			// But we have already read the startup message from the conn!
			// So the Server cannot read it again from the conn.
			// We must return a connection that "replays" the startup message, OR
			// the Server must accept the startup message as data to send.

			// Looking at the provided old handler:
			// It calls `forwardConnection(conn, startupMsg, svc)`
			// And `forwardConnection` writes `startupMsg.RawMessage` to the backend.

			// Our current architecture separates Handshake from Proxying.
			// The `Server.Serve` loop likely calls `Handshake`, gets metadata, resolves backend,
			// and then... it needs to send the startup message to the backend.

			// If the `ProtocolHandler` interface doesn't support returning the startup message,
			// we have a problem.
			// Let's check `cmd/proxy/internal/core/types.go` again.
			// It returns `(RoutingMetadata, net.Conn, error)`.

			// If we return the original `conn`, the startup message bytes are already consumed.
			// We need to wrap the connection to replay the bytes, OR pass the bytes in metadata.
			// Let's pass the bytes in metadata for now, as it's the least invasive change to the interface.
			// We'll use the key "_raw_startup_message".

			// If we didn't modify the user, we reconstruct the raw message from header + payload
			fullMsg := make([]byte, len(header)+len(payload))
			copy(fullMsg, header)
			copy(fullMsg[4:], payload)
			params["_raw_startup_message"] = string(fullMsg)
		}
	}

	return core.RoutingMetadata(params), conn, nil
}

func rebuildStartupMessage(protocolVersion uint32, params map[string]string) []byte {
	// Calculate total length needed
	totalLength := 4 + 4 // Length field + protocol version
	for key, value := range params {
		totalLength += len(key) + 1 + len(value) + 1
	}
	totalLength++ // Final null byte

	newMessage := make([]byte, totalLength)
	binary.BigEndian.PutUint32(newMessage[0:4], uint32(totalLength))
	binary.BigEndian.PutUint32(newMessage[4:8], protocolVersion)

	offset := 8
	for key, value := range params {
		copy(newMessage[offset:], key)
		offset += len(key)
		newMessage[offset] = 0
		offset++
		copy(newMessage[offset:], value)
		offset += len(value)
		newMessage[offset] = 0
		offset++
	}
	newMessage[offset] = 0
	return newMessage
}
