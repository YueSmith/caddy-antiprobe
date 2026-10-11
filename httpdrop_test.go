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
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func TestHTTPDropConnReset(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %s", err)
	}
	defer ln.Close()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("failed to dial: %s", err)
	}
	defer client.Close()

	server, err := ln.Accept()
	if err != nil {
		t.Fatalf("failed to accept: %s", err)
	}

	conn := &httpDropConn{Conn: server, reset: true, r: bufio.NewReader(server)}

	go func() {
		_, _ = client.Write([]byte("GET / HTTP/1.0\r\nHost: example.com\r\n\r\n"))
	}()

	if _, err := io.ReadAll(conn); !errors.Is(err, errHTTPOnHTTPSPort) {
		t.Fatalf("expected errHTTPOnHTTPSPort, got %v", err)
	}

	// with reset enabled, the peer should observe an abrupt termination
	// (RST) rather than a graceful close (EOF). Note the error value for a
	// reset is platform-specific (syscall.ECONNRESET vs. its Windows
	// equivalent), so only rule out the graceful close and timeouts.
	if err := client.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("failed to set read deadline: %s", err)
	}
	buf := make([]byte, 1)
	_, err = client.Read(buf)
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

func TestHTTPDropListenerWrapperUnmarshalCaddyfile(t *testing.T) {
	for i, tc := range []struct {
		name    string
		input   string
		wantErr bool
		want    HTTPDropListenerWrapper
	}{
		{
			name:  "no options",
			input: "http_drop",
			want:  HTTPDropListenerWrapper{},
		},
		{
			name:  "reset",
			input: "http_drop {\n\treset\n}",
			want:  HTTPDropListenerWrapper{Reset: true},
		},
		{
			name:    "stray inline argument",
			input:   "http_drop reset",
			wantErr: true,
		},
		{
			name:    "reset with stray argument",
			input:   "http_drop {\n\treset yes\n}",
			wantErr: true,
		},
		{
			name:    "unrecognized subdirective",
			input:   "http_drop {\n\tnope\n}",
			wantErr: true,
		},
	} {
		var h HTTPDropListenerWrapper
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
		if h != tc.want {
			t.Errorf("Test %d (%s): expected %+v, got %+v", i, tc.name, tc.want, h)
		}
	}
}

func TestHTTPDropConnRead(t *testing.T) {
	for i, tc := range []struct {
		name     string
		input    string
		wantErr  bool
		wantData string
	}{
		{
			name:    "plaintext GET is dropped",
			input:   "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
			wantErr: true,
		},
		{
			name:    "plaintext POST is dropped",
			input:   "POST /x HTTP/1.1\r\n\r\n",
			wantErr: true,
		},
		{
			name:     "TLS handshake bytes pass through",
			input:    "\x16\x03\x01\x02\x00\x01\x00",
			wantData: "\x16\x03\x01\x02\x00\x01\x00",
		},
		{
			name:     "short non-HTTP garbage passes through",
			input:    "\x00\x01\x02\x03\x04",
			wantData: "\x00\x01\x02\x03\x04",
		},
	} {
		server, client := net.Pipe()

		go func() {
			_, _ = client.Write([]byte(tc.input))
			_ = client.Close()
		}()

		conn := &httpDropConn{Conn: server, r: bufio.NewReader(server)}
		data, err := io.ReadAll(conn)
		_ = server.Close()

		if tc.wantErr {
			if !errors.Is(err, errHTTPOnHTTPSPort) {
				t.Errorf("Test %d (%s): expected errHTTPOnHTTPSPort, got %v", i, tc.name, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("Test %d (%s): unexpected error: %v", i, tc.name, err)
			continue
		}
		if string(data) != tc.wantData {
			t.Errorf("Test %d (%s): expected data %q, got %q", i, tc.name, tc.wantData, string(data))
		}
	}
}
