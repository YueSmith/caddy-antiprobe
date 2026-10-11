// Copyright 2015 Matthew Holt and The Caddy Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package antiprobe

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

// dropRead pushes input through a dropNonTLSConn over an in-memory pipe and
// returns what the TLS stack would read back.
func dropRead(t *testing.T, input []byte, reset bool, chunkSize int) ([]byte, error) {
	t.Helper()

	clientSide, serverSide := net.Pipe()
	conn := &dropNonTLSConn{Conn: serverSide, reset: reset, r: bufio.NewReader(serverSide)}

	go func() {
		for i := 0; i < len(input); i += chunkSize {
			if _, err := clientSide.Write(input[i:min(i+chunkSize, len(input))]); err != nil {
				return
			}
		}
		_ = clientSide.Close()
	}()

	out, err := io.ReadAll(conn)
	_ = serverSide.Close()
	return out, err
}

func TestDropNonTLSConnRead(t *testing.T) {
	realClientHello := clientHelloRecord(t, "allowed.example.com")

	for i, tc := range []struct {
		name    string
		input   []byte
		wantErr bool
		chunk   int
	}{
		{
			name:  "real ClientHello passes through untouched",
			input: realClientHello,
			chunk: len(realClientHello),
		},
		{
			name:  "fragmented ClientHello passes through untouched",
			input: realClientHello,
			chunk: 3,
		},
		{
			name:    "plaintext HTTP is dropped",
			input:   []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			wantErr: true,
			chunk:   64,
		},
		{
			name:    "plaintext HTTP with an unlisted method is dropped",
			input:   []byte("DELETE / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			wantErr: true,
			chunk:   64,
		},
		{
			name:    "h2c connection preface is dropped",
			input:   []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"),
			wantErr: true,
			chunk:   64,
		},
		{
			name:    "legacy SSLv2-style hello is dropped",
			input:   append([]byte{0x80, 0x2e, 0x01, 0x03, 0x01, 0x00, 0x2d}, make([]byte, 0x2d)...),
			wantErr: true,
			chunk:   64,
		},
		{
			name:    "random bytes are dropped",
			input:   []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07},
			wantErr: true,
			chunk:   8,
		},
		{
			name:    "handshake content type with an implausible version is dropped",
			input:   []byte{0x16, 0x02, 0x00, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00},
			wantErr: true,
			chunk:   64,
		},
		{
			name:    "oversized record is dropped",
			input:   []byte{0x16, 0x03, 0x01, 0xff, 0xff, 0x01, 0x00, 0x00, 0x10},
			wantErr: true,
			chunk:   64,
		},
		{
			// the handshake message type is not ClientHello
			name:    "non-ClientHello handshake message is dropped",
			input:   []byte{0x16, 0x03, 0x01, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00},
			wantErr: true,
			chunk:   64,
		},
		{
			// a record too short to hold a handshake header
			name:    "record too short for a handshake header is dropped",
			input:   []byte{0x16, 0x03, 0x01, 0x00, 0x03, 0x01, 0x00, 0x00},
			wantErr: true,
			chunk:   64,
		},
		{
			name:    "empty record is dropped",
			input:   []byte{0x16, 0x03, 0x01, 0x00, 0x00},
			wantErr: true,
			chunk:   64,
		},
		{
			// only the record header and the handshake message type are
			// inspected; a ClientHello-typed message with a junk body still
			// reaches the TLS stack
			name:  "ClientHello type with junk body is passed through",
			input: []byte{0x16, 0x03, 0x01, 0x00, 0x08, 0x01, 0x00, 0x00, 0x04, 0xff, 0xff, 0xff, 0xff},
			chunk: 64,
		},
		{
			name:  "short read is passed through",
			input: []byte("GET"),
			chunk: 4,
		},
	} {
		out, err := dropRead(t, tc.input, true, tc.chunk)

		if tc.wantErr {
			if !errors.Is(err, errNotTLS) {
				t.Errorf("Test %d (%s): expected errNotTLS, got %v", i, tc.name, err)
			}
			if len(out) != 0 {
				t.Errorf("Test %d (%s): expected no bytes written back, got %d", i, tc.name, len(out))
			}
			continue
		}

		if err != nil {
			t.Errorf("Test %d (%s): unexpected error: %v", i, tc.name, err)
			continue
		}
		if !bytes.Equal(out, tc.input) {
			t.Errorf("Test %d (%s): bytes were modified: got %d bytes, want %d", i, tc.name, len(out), len(tc.input))
		}
	}
}

// TestDropNonTLSConnReset verifies that reset makes the peer observe an abrupt
// termination instead of a graceful close, even when the TCP connection is
// wrapped by another listener wrapper.
func TestDropNonTLSConnReset(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %s", err)
	}
	defer ln.Close()

	clientSide, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("failed to dial: %s", err)
	}
	defer clientSide.Close()

	serverSide, err := ln.Accept()
	if err != nil {
		t.Fatalf("failed to accept: %s", err)
	}

	conn := &dropNonTLSConn{
		Conn:  unwrapTestConn{serverSide},
		reset: true,
		r:     bufio.NewReader(serverSide),
	}

	go func() {
		_, _ = clientSide.Write([]byte("GET / HTTP/1.0\r\n\r\n"))
	}()

	if _, err := io.ReadAll(conn); !errors.Is(err, errNotTLS) {
		t.Fatalf("expected errNotTLS, got %v", err)
	}

	// the peer must not receive anything (not even a TLS alert)
	if err := clientSide.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("failed to set read deadline: %s", err)
	}
	buf := make([]byte, 8)
	n, err := clientSide.Read(buf)
	if n != 0 {
		t.Fatalf("expected no bytes from the server, got % x", buf[:n])
	}
	if err == nil {
		t.Fatal("expected the connection to be reset, but the read succeeded")
	}
	if errors.Is(err, io.EOF) {
		t.Fatal("expected a connection reset (RST), got a graceful close (EOF)")
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		t.Fatalf("expected a connection reset (RST), got a timeout: %v", err)
	}
}

func TestDropNonTLSListenerWrapperUnmarshalCaddyfile(t *testing.T) {
	reset, fin := true, false

	for i, tc := range []struct {
		name    string
		input   string
		wantErr bool
		want    *bool
	}{
		{name: "no argument defaults to reset", input: "drop_non_tls", want: &reset},
		{name: "explicit reset", input: "drop_non_tls reset", want: &reset},
		{name: "explicit fin", input: "drop_non_tls fin", want: &fin},
		{name: "case insensitive", input: "drop_non_tls FIN", want: &fin},
		{name: "unrecognized close mode", input: "drop_non_tls maybe", wantErr: true},
		{name: "too many arguments", input: "drop_non_tls reset fin", wantErr: true},
		{name: "block is rejected", input: "drop_non_tls {\n\treset\n}", wantErr: true},
	} {
		var h DropNonTLSListenerWrapper
		err := h.UnmarshalCaddyfile(caddyfile.NewTestDispenser(tc.input))
		if tc.wantErr {
			if err == nil {
				t.Errorf("Test %d (%s): expected error but got none", i, tc.name)
			}
			continue
		}
		if err != nil {
			t.Errorf("Test %d (%s): unexpected error: %v", i, tc.name, err)
			continue
		}
		if shouldReset(h.Reset) != shouldReset(tc.want) {
			t.Errorf("Test %d (%s): expected reset=%v, got %v", i, tc.name, shouldReset(tc.want), shouldReset(h.Reset))
		}
	}
}
