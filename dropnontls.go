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
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func init() {
	caddy.RegisterModule(DropNonTLSListenerWrapper{})
}

// DropNonTLSListenerWrapper closes connections that do not begin with a TLS
// handshake record carrying a ClientHello, without writing anything to them.
//
// On a port that is meant to speak TLS only, it makes the port stop answering
// anything else — plaintext HTTP (which would otherwise get Go's
// `400 Client sent an HTTP request to an HTTPS server.`), the h2c connection
// preface, legacy SSLv2-style hellos, bare port scans, random bytes — with
// zero bytes written back, instead of the responses the TLS stack would
// otherwise emit (a fatal alert for some of those shapes).
//
// The check is on the first six bytes only: the five-byte record header
// (content type handshake 0x16, record-layer major version 3 — SSL 3.0 through
// TLS 1.3 all use 0x03 there — and a record length that fits in a TLS record
// and can hold a handshake header) plus the handshake message type, which must
// be ClientHello (0x01): the only message a client is allowed to send first.
// Nothing else is parsed, and a connection that passes is handed to the TLS
// stack untouched, so a real client cannot be affected. A crafted header that
// is plausible but followed by a malformed ClientHello body still reaches
// crypto/tls; this is a cheap "is this a TLS client" filter, not a TLS
// validator.
//
// Plaintext HTTP is covered as a side effect: a request line always starts
// with an ASCII method name, so it can never begin with 0x16.
//
// This listener wrapper must be placed BEFORE the "tls" listener wrapper, for
// it to work properly.
type DropNonTLSListenerWrapper struct {
	// Reset tears down the connection with a TCP reset (RST) instead of a
	// graceful close (FIN), so the client learns nothing beyond "the
	// connection went away". Only applies to TCP connections.
	// Default: true.
	Reset *bool `json:"reset,omitempty"`
}

func (DropNonTLSListenerWrapper) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.listeners.drop_non_tls",
		New: func() caddy.Module { return new(DropNonTLSListenerWrapper) },
	}
}

// UnmarshalCaddyfile sets up the wrapper from Caddyfile tokens. Syntax:
//
//	drop_non_tls [reset|fin]
//
// The optional argument selects how a rejected connection is torn down; it
// defaults to reset.
func (h *DropNonTLSListenerWrapper) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume directive name

	if d.NextArg() {
		switch strings.ToLower(d.Val()) {
		case "reset":
			reset := true
			h.Reset = &reset
		case "fin":
			reset := false
			h.Reset = &reset
		default:
			return d.Errf("unrecognized close mode: %s (expected reset or fin)", d.Val())
		}
		if d.NextArg() {
			return d.ArgErr()
		}
	} else {
		// no argument means reset, which is also the default
		reset := true
		h.Reset = &reset
	}

	if d.NextBlock(0) {
		return d.Err("drop_non_tls takes no block")
	}

	return nil
}

func (h *DropNonTLSListenerWrapper) WrapListener(l net.Listener) net.Listener {
	return &dropNonTLSListener{Listener: l, reset: shouldReset(h.Reset)}
}

// dropNonTLSListener drops connections that are not TLS.
type dropNonTLSListener struct {
	net.Listener
	reset bool
}

// Accept waits for and returns the next connection to the listener,
// wrapping it with a dropNonTLSConn.
func (l *dropNonTLSListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &dropNonTLSConn{Conn: c, reset: l.reset, r: bufio.NewReader(c)}, nil
}

type dropNonTLSConn struct {
	net.Conn
	reset bool
	once  bool
	r     *bufio.Reader
}

// Read peeks at the connection's record header, and if it cannot be the start
// of a TLS client, closes the connection (with a RST if configured) and
// returns an error, so that no response is sent to the client.
func (c *dropNonTLSConn) Read(p []byte) (int, error) {
	if c.once {
		return c.r.Read(p)
	}
	// no need to use sync.Once - net.Conn is not read from concurrently.
	c.once = true

	hdr, err := c.r.Peek(tlsRecordHeaderLen)
	if err != nil {
		// we could not even read a header; let the TLS stack deal with it
		return c.r.Read(p)
	}

	if !looksLikeTLSHandshakeRecord(hdr) {
		// Closing here rather than letting crypto/tls reject the connection
		// is what keeps the port silent: the TLS stack would answer some of
		// these shapes with a fatal alert.
		dropConn(c.Conn, c.reset)

		return 0, errNotTLS
	}

	// A client's first handshake message is always a ClientHello; the record
	// length was already checked to be long enough for its header, so the
	// message type is the next byte on the wire.
	full, err := c.r.Peek(tlsRecordHeaderLen + 1)
	if err != nil {
		return c.r.Read(p) // could not read the message type; let TLS decide
	}
	if full[tlsRecordHeaderLen] != tlsHandshakeTypeClientHello {
		dropConn(c.Conn, c.reset)

		return 0, errNotTLS
	}

	return c.r.Read(p)
}

// Unwrap returns the connection this one wraps, so that other listener
// wrappers can reach the underlying TCP connection.
func (c *dropNonTLSConn) Unwrap() net.Conn { return c.Conn }

// errNotTLS is returned from reads on connections that were dropped because
// they do not begin with a TLS handshake record.
var errNotTLS = errors.New("connection does not begin with a TLS handshake record")

// maxTLSRecordPayload is a loose upper bound on a TLS record payload. It is the
// same bound crypto/tls uses (maxCiphertext): any header claiming more than
// this is rejected by the TLS stack with a record_overflow alert, so we drop
// it instead.
const maxTLSRecordPayload = 1<<14 + 2048

// looksLikeTLSHandshakeRecord reports whether hdr (the first five bytes of a
// connection) is a plausible TLS handshake record header that is long enough
// to contain a handshake message header.
func looksLikeTLSHandshakeRecord(hdr []byte) bool {
	if len(hdr) < tlsRecordHeaderLen || hdr[0] != tlsRecordTypeHandshake || hdr[1] != 0x03 {
		return false
	}
	recLen := int(hdr[3])<<8 | int(hdr[4])
	return recLen >= handshakeHeaderLen && recLen <= maxTLSRecordPayload
}

// handshakeHeaderLen is the size of a TLS handshake message header (type plus
// length).
const handshakeHeaderLen = 4

var (
	_ caddy.ListenerWrapper = (*DropNonTLSListenerWrapper)(nil)
	_ caddyfile.Unmarshaler = (*DropNonTLSListenerWrapper)(nil)
)
