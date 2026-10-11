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
	"net"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func init() {
	caddy.RegisterModule(HTTPDropListenerWrapper{})
}

// HTTPDropListenerWrapper aborts connections that arrive on a TLS port
// as plaintext HTTP requests, without sending any response.
//
// Without it, a plaintext HTTP request to a TLS port makes the Go
// standard library's net/http server write an "HTTP/1.0 400 Bad Request"
// response containing "Client sent an HTTP request to an HTTPS server."
// That response reveals that an HTTPS server is listening and is written
// by the standard library with no way to configure it away. This wrapper
// intercepts the connection before the TLS handshake, so the client is
// disconnected instead of answered. As a result the client observes only
// a reset (or EOF), not an HTTP response.
//
// This listener wrapper must be placed BEFORE the "tls" listener
// wrapper, for it to work properly.
type HTTPDropListenerWrapper struct {
	// Reset, if true, closes the underlying TCP connection with a reset
	// (RST) instead of a graceful close (FIN), interrupting the
	// connection immediately rather than performing the normal close
	// handshake. Only applies to TCP connections. Default: false.
	Reset bool `json:"reset,omitempty"`
}

func (HTTPDropListenerWrapper) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.listeners.http_drop",
		New: func() caddy.Module { return new(HTTPDropListenerWrapper) },
	}
}

func (h *HTTPDropListenerWrapper) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume wrapper name

	if d.NextArg() {
		return d.ArgErr()
	}

	for nesting := d.Nesting(); d.NextBlock(nesting); {
		switch d.Val() {
		case "reset":
			if d.NextArg() {
				return d.ArgErr()
			}
			h.Reset = true
		default:
			return d.Errf("unrecognized subdirective: %s", d.Val())
		}
	}

	return nil
}

func (h *HTTPDropListenerWrapper) WrapListener(l net.Listener) net.Listener {
	return &httpDropListener{Listener: l, reset: h.Reset}
}

// httpDropListener wraps a listener that is expected to receive TLS
// handshakes, and drops connections whose first bytes are a plaintext
// HTTP request.
type httpDropListener struct {
	net.Listener
	reset bool
}

// Accept waits for and returns the next connection to the listener,
// wrapping it with an httpDropConn.
func (l *httpDropListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	return &httpDropConn{
		Conn:  c,
		reset: l.reset,
		r:     bufio.NewReader(c),
	}, nil
}

type httpDropConn struct {
	net.Conn
	reset bool
	once  bool
	r     *bufio.Reader
}

// Read peeks at the first few bytes of the connection, and if they look
// like a plaintext HTTP request rather than a TLS handshake, closes the
// connection (with a RST if configured) and returns an error, so that no
// response is sent to the client.
func (c *httpDropConn) Read(p []byte) (int, error) {
	if c.once {
		return c.r.Read(p)
	}
	// no need to use sync.Once - net.Conn is not read from concurrently.
	c.once = true

	firstBytes, err := c.r.Peek(5)
	if err != nil {
		return c.r.Read(p)
	}

	// If the request doesn't look like HTTP, then it's probably
	// TLS bytes, and we don't need to do anything.
	if !firstBytesLookLikeHTTP(firstBytes) {
		return c.r.Read(p)
	}

	// From now on, we can be almost certain the request is HTTP.
	// The returned error will be non nil and callers are expected
	// to close the connection.
	//
	// Returning an error instead of leaving the bytes for the TLS
	// stack is deliberate: net/http only writes its own "Client sent
	// an HTTP request to an HTTPS server." response when the handshake
	// fails with a tls.RecordHeaderError carrying those bytes, so
	// failing the read here suppresses that response entirely.
	if c.reset {
		if tc := unwrapTCPConn(c.Conn); tc != nil {
			// linger 0 makes Close send a RST instead of a FIN
			_ = tc.SetLinger(0)
		}
	}
	_ = c.Conn.Close()

	return 0, errHTTPOnHTTPSPort
}

// Unwrap returns the connection this one wraps, so that other listener
// wrappers can reach the underlying TCP connection.
func (c *httpDropConn) Unwrap() net.Conn { return c.Conn }

// unwrapTCPConn returns the underlying *net.TCPConn of c, unwrapping any
// wrapper connections that expose an Unwrap method. It returns nil when there
// is no TCP connection underneath (for example a Unix socket).
func unwrapTCPConn(c net.Conn) *net.TCPConn {
	for c != nil {
		if tc, ok := c.(*net.TCPConn); ok {
			return tc
		}
		unwrapper, ok := c.(interface{ Unwrap() net.Conn })
		if !ok {
			return nil
		}
		c = unwrapper.Unwrap()
	}
	return nil
}

// errHTTPOnHTTPSPort is returned from reads on connections that sent a
// plaintext HTTP request to a TLS port.
var errHTTPOnHTTPSPort = errors.New("plaintext HTTP request on HTTPS port")

var (
	_ caddy.ListenerWrapper = (*HTTPDropListenerWrapper)(nil)
	_ caddyfile.Unmarshaler = (*HTTPDropListenerWrapper)(nil)
)

// firstBytesLookLikeHTTP reports whether a TLS record header looks like it
// might've been a misdirected plaintext HTTP request.
//
// This is a copy of the unexported helper of the same name in Caddy core
// (modules/caddyhttp/httpredirectlistener.go); external modules cannot reach
// unexported core helpers.
func firstBytesLookLikeHTTP(hdr []byte) bool {
	switch string(hdr[:5]) {
	case "GET /", "HEAD ", "POST ", "PUT /", "OPTIO":
		return true
	}
	return false
}
