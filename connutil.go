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

import "net"

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

// dropConn tears a connection down without writing anything to it, so the peer
// learns nothing beyond the fact that the connection went away. If reset is
// true the teardown is a TCP RST instead of a graceful FIN.
func dropConn(c net.Conn, reset bool) {
	if reset {
		if tc := unwrapTCPConn(c); tc != nil {
			// linger 0 makes Close send a RST instead of a FIN
			_ = tc.SetLinger(0)
		}
	}
	_ = c.Close()
}

// shouldReset reports whether a close-mode field means "reset". An unset field
// means reset, which is the default for every wrapper in this module.
func shouldReset(reset *bool) bool {
	return reset == nil || *reset
}
