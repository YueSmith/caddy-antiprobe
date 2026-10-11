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
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

// clientHelloRecord returns the bytes of a real ClientHello record produced
// by crypto/tls for the given server name.
func clientHelloRecord(t *testing.T, serverName string) []byte {
	t.Helper()

	serverSide, clientSide := net.Pipe()
	defer serverSide.Close()
	defer clientSide.Close()

	go func() {
		cfg := &tls.Config{ServerName: serverName, InsecureSkipVerify: true}
		_ = tls.Client(clientSide, cfg).Handshake() // blocks; torn down below
	}()

	hello := make([]byte, 0, 4096)
	buf := make([]byte, 4096)
	for len(hello) < tlsRecordHeaderLen || len(hello) < tlsRecordHeaderLen+recordLen(hello) {
		n, err := serverSide.Read(buf)
		hello = append(hello, buf[:n]...)
		if err != nil || n == 0 {
			break
		}
	}

	if !bytes.Contains(hello, []byte(serverName)) {
		t.Fatalf("generated ClientHello does not contain %q: % x", serverName, hello)
	}
	return hello
}

func recordLen(record []byte) int {
	if len(record) < tlsRecordHeaderLen {
		return 0
	}
	return int(record[3])<<8 | int(record[4])
}

// filterRead pushes input through a sniWhitelistConn over an in-memory pipe and
// returns what the TLS stack would read back.
func filterRead(t *testing.T, input []byte, allowed []string, chunkSize int) ([]byte, error) {
	t.Helper()

	clientSide, serverSide := net.Pipe()
	conn := &sniWhitelistConn{Conn: serverSide, l: &sniWhitelistListener{allowed: normalizeServerNames(allowed)}}

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

func TestSNIWhitelistConnRead(t *testing.T) {
	helloAllowed := clientHelloRecord(t, "allowed.example.com")
	helloBlocked := clientHelloRecord(t, "blocked.example.com")
	helloSingle := clientHelloRecord(t, "a.allowed.example.com")

	for i, tc := range []struct {
		name    string
		input   []byte
		allowed []string
		wantErr bool
		chunk   int
	}{
		{
			name:    "allowed name passes through untouched",
			input:   helloAllowed,
			allowed: []string{"allowed.example.com"},
			chunk:   len(helloAllowed),
		},
		{
			name:    "wildcard allows subdomain",
			input:   helloSingle,
			allowed: []string{"*.allowed.example.com"},
			chunk:   len(helloSingle),
		},
		{
			name:    "disallowed name is dropped",
			input:   helloBlocked,
			allowed: []string{"allowed.example.com"},
			wantErr: true,
			chunk:   len(helloBlocked),
		},
		{
			name:    "case and trailing dot are ignored",
			input:   helloAllowed,
			allowed: []string{"Allowed.Example.Com."},
			chunk:   len(helloAllowed),
		},
		{
			name:    "client without SNI is dropped",
			input:   clientHelloRecord(t, ""),
			allowed: []string{"allowed.example.com"},
			wantErr: true,
			chunk:   len(helloAllowed),
		},
		{
			name:    "plaintext is not inspected",
			input:   []byte("GET / HTTP/1.1\r\nHost: allowed.example.com\r\n\r\n"),
			allowed: []string{"allowed.example.com"},
			chunk:   64,
		},
		{
			name:    "fragmented ClientHello is still inspected",
			input:   helloBlocked,
			allowed: []string{"allowed.example.com"},
			wantErr: true,
			chunk:   16,
		},
		{
			name:    "truncated ClientHello is not inspected",
			input:   helloAllowed[:len(helloAllowed)-20],
			allowed: []string{"blocked.example.com"},
			chunk:   len(helloAllowed),
		},
	} {
		out, err := filterRead(t, tc.input, tc.allowed, tc.chunk)

		if tc.wantErr {
			if !errors.Is(err, errSNINotAllowed) {
				t.Errorf("Test %d (%s): expected errSNINotAllowed, got %v", i, tc.name, err)
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

// TestSNIWhitelistConnReset verifies that reset makes the peer observe an abrupt
// termination instead of a graceful close, even when the TCP connection is
// wrapped by another listener wrapper (as it is when wrappers are chained).
func TestSNIWhitelistConnReset(t *testing.T) {
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

	conn := &sniWhitelistConn{Conn: unwrapTestConn{serverSide}, l: &sniWhitelistListener{
		allowed: []string{"allowed.example.com"},
		reset:   true,
	}}

	go func() {
		_, _ = clientSide.Write(clientHelloRecord(t, "blocked.example.com"))
	}()

	if _, err := io.ReadAll(conn); !errors.Is(err, errSNINotAllowed) {
		t.Fatalf("expected errSNINotAllowed, got %v", err)
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

// unwrapTestConn stands in for another listener wrapper's connection, to make
// sure the RST path can find the TCP connection underneath a wrapper.
type unwrapTestConn struct{ net.Conn }

func (c unwrapTestConn) Unwrap() net.Conn { return c.Conn }

func TestSNIWhitelistListenerWrapperUnmarshalCaddyfile(t *testing.T) {
	reset, fin := true, false

	for i, tc := range []struct {
		name    string
		input   string
		wantErr bool
		want    SNIWhitelistListenerWrapper
	}{
		{
			name:  "names one per line, reset by default",
			input: "sni_whitelist {\n\tYue-Game\n\tA.somesni.local\n\tB.somesni.local\n\t*.wildcard.local\n}",
			want: SNIWhitelistListenerWrapper{
				AllowedSNIs: []string{"Yue-Game", "A.somesni.local", "B.somesni.local", "*.wildcard.local"},
				Reset:       &reset,
			},
		},
		{
			name:  "explicit reset",
			input: "sni_whitelist reset {\n\tallowed.example.com\n}",
			want: SNIWhitelistListenerWrapper{
				AllowedSNIs: []string{"allowed.example.com"},
				Reset:       &reset,
			},
		},
		{
			name:  "explicit fin",
			input: "sni_whitelist fin {\n\tallowed.example.com\n}",
			want: SNIWhitelistListenerWrapper{
				AllowedSNIs: []string{"allowed.example.com"},
				Reset:       &fin,
			},
		},
		{
			name:  "no names is not a parse error (Provision rejects it)",
			input: "sni_whitelist",
			want:  SNIWhitelistListenerWrapper{Reset: &reset},
		},
		{
			name:    "unrecognized close mode",
			input:   "sni_whitelist maybe {\n\tallowed.example.com\n}",
			wantErr: true,
		},
		{
			name:    "too many arguments",
			input:   "sni_whitelist reset fin {\n\tallowed.example.com\n}",
			wantErr: true,
		},
	} {
		var h SNIWhitelistListenerWrapper
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
		if h.resetConn() != tc.want.resetConn() {
			t.Errorf("Test %d (%s): expected reset=%v, got %v", i, tc.name, tc.want.resetConn(), h.resetConn())
		}
		if len(h.AllowedSNIs) != len(tc.want.AllowedSNIs) {
			t.Errorf("Test %d (%s): expected names %q, got %q", i, tc.name, tc.want.AllowedSNIs, h.AllowedSNIs)
			continue
		}
		for j, n := range tc.want.AllowedSNIs {
			if h.AllowedSNIs[j] != n {
				t.Errorf("Test %d (%s): expected name %q, got %q", i, tc.name, n, h.AllowedSNIs[j])
			}
		}
	}
}

// TestSNIWhitelistListenerWrapperProvision verifies that an empty allowlist is
// rejected at provision time, and that names are normalized.
func TestSNIWhitelistListenerWrapperProvision(t *testing.T) {
	empty := new(SNIWhitelistListenerWrapper)
	if err := empty.Provision(caddy.Context{}); err == nil {
		t.Error("expected an error for an empty allowlist")
	}

	wrapper := &SNIWhitelistListenerWrapper{AllowedSNIs: []string{"Allowed.Example.Com.", "  "}}
	if err := wrapper.Provision(caddy.Context{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(wrapper.allowed) != 1 || wrapper.allowed[0] != "allowed.example.com" {
		t.Fatalf("expected normalized allowlist, got %q", wrapper.allowed)
	}

	// reset is the default connection mode
	if !new(SNIWhitelistListenerWrapper).resetConn() {
		t.Error("expected reset to be the default connection mode")
	}
	fin := false
	if (&SNIWhitelistListenerWrapper{Reset: &fin}).resetConn() {
		t.Error("expected fin to be honored when configured")
	}
}
