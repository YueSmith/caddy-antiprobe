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
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/certmagic"
)

func init() {
	caddy.RegisterModule(SNIWhitelistListenerWrapper{})
}

// SNIWhitelistListenerWrapper closes connections whose TLS ClientHello carries a
// server name (SNI) that is not in an allowlist, without writing anything to
// them.
//
// Rejecting a connection later, at certificate selection time, makes the TLS
// stack send a fatal alert ("internal error") before closing; that is a
// well-formed TLS response and it tells the client (and any scanner) that a
// TLS server is present. This wrapper instead makes the decision from the raw
// ClientHello, before the TLS stack sees it, so not a single byte is sent
// back. Rejected connections are torn down with a TCP RST rather than a
// graceful FIN unless the connection mode is set to "fin".
//
// Connections whose ClientHello cannot be inspected (not a TLS handshake
// record, larger than the inspection limit, or malformed) are passed through
// unchanged so that the TLS stack remains the backstop and no legitimate
// client is filtered out by accident. Likewise, a ClientHello that does not
// carry an SNI at all does not match any allowlist entry and is therefore
// rejected.
//
// This listener wrapper must be placed BEFORE the "tls" listener wrapper, for
// it to work properly.
type SNIWhitelistListenerWrapper struct {
	// AllowedSNIs is the list of server names to accept. Entries may use a
	// left-most label wildcard, e.g. "*.example.com" matches
	// "a.example.com" but not "a.b.example.com". "*" accepts any name.
	// Comparison is case-insensitive and a trailing dot is ignored.
	// Required.
	AllowedSNIs []string `json:"allowed_snis,omitempty"`

	// Reset tears down the connection with a TCP reset (RST) instead of a
	// graceful close (FIN), so the client learns nothing beyond "the
	// connection went away". Only applies to TCP connections.
	// Default: true.
	Reset *bool `json:"reset,omitempty"`

	// allowed is the normalized allowlist, built in Provision.
	allowed []string
}

// resetConn reports whether rejected connections should be reset.
func (h *SNIWhitelistListenerWrapper) resetConn() bool {
	return h.Reset == nil || *h.Reset
}

func (SNIWhitelistListenerWrapper) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.listeners.sni_whitelist",
		New: func() caddy.Module { return new(SNIWhitelistListenerWrapper) },
	}
}

// Provision normalizes the allowlist and verifies that it is not empty.
func (h *SNIWhitelistListenerWrapper) Provision(_ caddy.Context) error {
	h.allowed = normalizeServerNames(h.AllowedSNIs)
	if len(h.allowed) == 0 {
		return errors.New("no allowed server names configured")
	}
	return nil
}

// UnmarshalCaddyfile sets up the wrapper from Caddyfile tokens. Syntax:
//
//	sni_whitelist [reset|fin] {
//		<server_name>
//		<server_name>
//		...
//	}
//
// The optional argument selects how rejected connections are torn down;
// it defaults to reset. Every name in the block is one allowed server name,
// one per line.
func (h *SNIWhitelistListenerWrapper) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
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

	for nesting := d.Nesting(); d.NextBlock(nesting); {
		h.AllowedSNIs = append(h.AllowedSNIs, d.Val())
	}

	return nil
}

func (h *SNIWhitelistListenerWrapper) WrapListener(l net.Listener) net.Listener {
	allowed := h.allowed
	if len(allowed) == 0 {
		// Provision should always have run; be defensive anyway.
		allowed = normalizeServerNames(h.AllowedSNIs)
	}
	return &sniWhitelistListener{Listener: l, allowed: allowed, reset: h.resetConn()}
}

// sniWhitelistListener drops TLS connections whose SNI is not allowed.
type sniWhitelistListener struct {
	net.Listener
	allowed []string
	reset   bool
}

// Accept waits for and returns the next connection to the listener,
// wrapping it with a sniWhitelistConn.
func (l *sniWhitelistListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &sniWhitelistConn{Conn: c, l: l}, nil
}

// allows reports whether sni is in the listener's allowlist.
func (l *sniWhitelistListener) allows(sni string) bool {
	for _, pattern := range l.allowed {
		if certmagic.MatchWildcard(sni, pattern) {
			return true
		}
	}
	return false
}

type sniWhitelistConn struct {
	net.Conn
	l *sniWhitelistListener

	once bool
	pre  []byte        // bytes read from the wire that TLS has not seen yet
	r    *bufio.Reader // replays pre, then reads from the connection
}

// Read inspects the connection's ClientHello without consuming it, and if the
// server name it carries is not allowed, closes the connection without
// writing any response.
func (c *sniWhitelistConn) Read(p []byte) (int, error) {
	if !c.once {
		c.once = true

		sni, decided, pre := readClientHelloSNI(c.Conn)
		c.pre = pre

		if decided && !c.l.allows(sni) {
			if c.l.reset {
				if tc := unwrapTCPConn(c.Conn); tc != nil {
					// linger 0 makes Close send a RST instead of a FIN
					_ = tc.SetLinger(0)
				}
			}
			_ = c.Conn.Close()

			return 0, errSNINotAllowed
		}

		// Either allowed, or undecidable (let the TLS stack deal with it).
	}

	return c.buffered().Read(p)
}

// Unwrap returns the connection this one wraps, so that other listener
// wrappers can reach the underlying TCP connection.
func (c *sniWhitelistConn) Unwrap() net.Conn { return c.Conn }

// buffered returns a reader over the bytes we already read from the wire,
// followed by the rest of the connection.
func (c *sniWhitelistConn) buffered() *bufio.Reader {
	if c.r == nil {
		if len(c.pre) > 0 {
			c.r = bufio.NewReader(io.MultiReader(bytes.NewReader(c.pre), c.Conn))
		} else {
			c.r = bufio.NewReader(c.Conn)
		}
	}
	return c.r
}

// errSNINotAllowed is returned from reads on connections that were dropped
// because their SNI is not in the allowlist.
var errSNINotAllowed = errors.New("server name not allowed")

// normalizeServerNames lowercases names, trims a trailing dot and drops
// empties.
func normalizeServerNames(names []string) []string {
	var normalized []string
	for _, name := range names {
		name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
		if name == "" {
			continue
		}
		normalized = append(normalized, name)
	}
	return normalized
}

// TLS wire format constants used to inspect a ClientHello.
const (
	tlsRecordHeaderLen          = 5
	tlsRecordTypeHandshake      = 0x16
	tlsHandshakeTypeClientHello = 0x01
	tlsExtensionServerName      = 0x0000
	tlsServerNameHostName       = 0x00

	// maxClientHelloBytes caps how much we are willing to buffer while
	// inspecting a ClientHello. It is the maximum size of a single TLS
	// record payload, which is far larger than any real ClientHello.
	maxClientHelloBytes = 16*1024 + 5

	// clientHelloInitialBuf is the initial size of the inspection buffer.
	clientHelloInitialBuf = 1024
)

// readClientHelloSNI reads just enough of the connection to parse the
// ClientHello, without consuming any bytes for the caller: everything read is
// returned in pre.
//
// sni is the server name carried by the ClientHello. decided reports whether
// the bytes form an inspectable ClientHello; when it is false, the caller
// must not make a decision based on sni.
func readClientHelloSNI(conn net.Conn) (sni string, decided bool, pre []byte) {
	buf := make([]byte, 0, clientHelloInitialBuf)

	// ensureBuf makes sure buf holds at least n bytes.
	ensureBuf := func(n int) error {
		for len(buf) < n {
			if n > maxClientHelloBytes {
				return errClientHelloTooLarge
			}
			if cap(buf) < n {
				grown := make([]byte, len(buf), min(max(2*cap(buf), n), maxClientHelloBytes))
				copy(grown, buf)
				buf = grown
			}
			nr, err := conn.Read(buf[len(buf):cap(buf)])
			buf = buf[:len(buf)+nr]
			if err != nil {
				return err
			}
		}
		return nil
	}

	// A ClientHello is a handshake message, which may span more than one
	// TLS record (and therefore more than one TCP segment), so collect the
	// record payloads until the whole handshake message is in hand.
	payload := make([]byte, 0, clientHelloInitialBuf)
	for off := 0; ; {
		if err := ensureBuf(off + tlsRecordHeaderLen); err != nil {
			return "", false, buf
		}
		if buf[off] != tlsRecordTypeHandshake {
			return "", false, buf // not a TLS handshake; leave it alone
		}

		recLen := int(buf[off+3])<<8 | int(buf[off+4])
		if recLen == 0 || off+tlsRecordHeaderLen+recLen > maxClientHelloBytes {
			return "", false, buf
		}
		if err := ensureBuf(off + tlsRecordHeaderLen + recLen); err != nil {
			return "", false, buf
		}

		payload = append(payload, buf[off+tlsRecordHeaderLen:off+tlsRecordHeaderLen+recLen]...)
		off += tlsRecordHeaderLen + recLen

		// The handshake message header is its type (1 byte) followed by its
		// length (3 bytes); once we have the whole message, parse it.
		if len(payload) < 4 {
			continue
		}
		if payload[0] != tlsHandshakeTypeClientHello {
			return "", false, buf
		}
		msgLen := int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
		if msgLen > maxClientHelloBytes {
			return "", false, buf
		}
		if len(payload) >= 4+msgLen {
			name, ok := parseClientHelloSNI(payload[:4+msgLen])
			return name, ok, buf
		}
	}
}

// parseClientHelloSNI extracts the server name from a ClientHello handshake
// message. ok is false if the message is malformed; a well-formed message
// without a server_name extension returns ok with an empty name.
func parseClientHelloSNI(msg []byte) (sni string, ok bool) {
	// handshake message: type (1), length (3), then the ClientHello body
	if len(msg) < 4 || msg[0] != tlsHandshakeTypeClientHello {
		return "", false
	}
	body := msg[4:]

	// legacy_version (2), random (32)
	if len(body) < 34 {
		return "", false
	}
	body = body[34:]

	// session_id
	if len(body) < 1 || len(body) < 1+int(body[0]) {
		return "", false
	}
	body = body[1+int(body[0]):]

	// cipher_suites
	if len(body) < 2 {
		return "", false
	}
	n := int(body[0])<<8 | int(body[1])
	if len(body) < 2+n {
		return "", false
	}
	body = body[2+n:]

	// compression_methods
	if len(body) < 1 || len(body) < 1+int(body[0]) {
		return "", false
	}
	body = body[1+int(body[0]):]

	// extensions are optional (absent in SSLv3-era hellos)
	if len(body) == 0 {
		return "", true
	}
	if len(body) < 2 {
		return "", false
	}
	n = int(body[0])<<8 | int(body[1])
	if len(body) < 2+n {
		return "", false
	}
	extensions := body[2 : 2+n]

	for len(extensions) >= 4 {
		extType := int(extensions[0])<<8 | int(extensions[1])
		extLen := int(extensions[2])<<8 | int(extensions[3])
		if len(extensions) < 4+extLen {
			return "", false
		}
		if extType == tlsExtensionServerName {
			return parseServerNameExtension(extensions[4 : 4+extLen])
		}
		extensions = extensions[4+extLen:]
	}

	return "", true // well-formed ClientHello without SNI
}

// parseServerNameExtension extracts the host_name from a server_name
// extension.
func parseServerNameExtension(data []byte) (sni string, ok bool) {
	// ServerNameList: list length (2), then { name_type (1), length (2), name }
	if len(data) < 2 {
		return "", false
	}
	n := int(data[0])<<8 | int(data[1])
	if len(data) < 2+n {
		return "", false
	}

	for list := data[2 : 2+n]; len(list) >= 3; {
		nameType := list[0]
		nameLen := int(list[1])<<8 | int(list[2])
		if len(list) < 3+nameLen {
			return "", false
		}
		if nameType == tlsServerNameHostName {
			return string(list[3 : 3+nameLen]), true
		}
		list = list[3+nameLen:]
	}

	return "", true // no host_name entry
}

// errClientHelloTooLarge is returned when a ClientHello exceeds the
// inspection limit.
var errClientHelloTooLarge = errors.New("ClientHello too large")

var (
	_ caddy.Provisioner     = (*SNIWhitelistListenerWrapper)(nil)
	_ caddy.ListenerWrapper = (*SNIWhitelistListenerWrapper)(nil)
	_ caddyfile.Unmarshaler = (*SNIWhitelistListenerWrapper)(nil)
)
