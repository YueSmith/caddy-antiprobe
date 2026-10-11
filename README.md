# caddy-antiprobe

Two [Caddy](https://caddyserver.com) **listener wrappers** that keep a TLS port from answering probes. Both are [out-of-tree Caddy modules](https://caddyserver.com/docs/extending-caddy): no fork of Caddy is required.

> **This project is AI-generated.** It was written with heavy AI assistance and
> has not been battle-tested. It sits directly in front of your TLS listener, so
> read it before you depend on it — see [AI disclosure](#ai-disclosure).

| Caddyfile directive | Module ID | Effect |
| --- | --- | --- |
| `drop_non_tls` | `caddy.listeners.drop_non_tls` | Closes connections that do not begin with a TLS ClientHello, without writing anything. This is the broad one: plaintext HTTP, the h2c connection preface, legacy SSLv2-style hellos, port scans, random bytes. |
| `sni_whitelist` | `caddy.listeners.sni_whitelist` | Reads the SNI out of the ClientHello **before `crypto/tls` ever sees it**. If the name is not in the whitelist, the connection is torn down without writing a single byte. |

Both wrappers must be placed **before** the `tls` listener wrapper, so that they see the raw bytes of the connection.

## Why

By default a Caddy HTTPS port answers things it should not answer:

- **Plaintext HTTP on a TLS port** makes Go's `net/http` write
  `HTTP/1.0 400 Bad Request` with the body `Client sent an HTTP request to an
  HTTPS server.` That response comes from the standard library and cannot be
  configured away.
- **An SNI that has no certificate** makes `crypto/tls` send a fatal alert
  (`internal error`, alert 80) and close. It is a well-formed TLS response, and
  on Windows it surfaces as the misleading
  `schannel: SEC_E_INTERNAL_ERROR (0x80090304)`.

With these wrappers installed, both cases produce **nothing at all**:

| Situation | Default Caddy | With this plugin |
| --- | --- | --- |
| plaintext HTTP → TLS port | `400 Bad Request` + body | 0 bytes, connection closed |
| h2c preface, SSLv2-style hello, scan garbage | varies (a fatal alert for some shapes, silence for others) | 0 bytes, connection closed |
| SNI not in the whitelist | `alert(2, 80)` | 0 bytes, connection closed (TCP RST by default) |
| SNI is whitelisted | works | works, unchanged |
| connected, then says nothing | held open until the client or the OS gives up | closed by `timeouts`, see below |

## Install

```bash
go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest

xcaddy build --with github.com/YueSmith/caddy-antiprobe
```

While developing on the plugin itself, point xcaddy at your working copy:

```bash
xcaddy build --with github.com/YueSmith/caddy-antiprobe=.
```

Unit tests cover the ClientHello parser (including fragmented records), the
allowlist matching, and the connection teardown:

```bash
go test ./...
```

## Usage

```caddyfile
{
	servers :443 {
		# HTTP/3 must be turned off too -- see "Turn off HTTP/3 as well" below
		protocols h1 h2
		# bound how long a connection may sit there saying nothing; the
		# wrappers below read inside the TLS handshake window, whose deadline
		# is min(ReadHeaderTimeout, ReadTimeout, WriteTimeout)
		timeouts {
			read_header 10s
		}
		listener_wrappers {
			drop_non_tls
			sni_whitelist {
				example.com
				router.example.org
				*.wildcard.example
			}
			tls
		}
	}
}
```

`drop_non_tls` and `sni_whitelist` both take an optional first argument
selecting how a rejected connection is torn down:

- `reset` — close with a TCP RST (**default**, also when the argument is omitted)
- `fin` — close gracefully with a TCP FIN

`drop_non_tls` inspects only the first six bytes of a connection, so it is
harmless to leave in front of `sni_whitelist`: it exists so that non-TLS
traffic never reaches `crypto/tls` at all. `sni_whitelist` then takes an
optional block of allowed server names, one per line.

Every name in the block is one allowed server name, one per line. Names are
compared case-insensitively, a trailing dot is ignored, and a left-most label
wildcard like `*.example.com` matches `a.example.com` but not
`a.b.example.com`. `*` matches any name.

A connection whose ClientHello carries **no SNI at all** matches nothing, so it
is rejected as well.

### Turn off HTTP/3 as well

```caddyfile
servers :443 {
	protocols h1 h2
}
```

`sni_whitelist` works on `net.Listener`, i.e. on TCP. HTTP/3 runs over
QUIC/UDP, which Caddy hands to quic-go through a `net.PacketConn`, so the
wrapper never sees those datagrams. Two things follow, and they are the reason
`protocols h1 h2` belongs in the example above:

1. **The QUIC path cannot be silenced, only answered.** To make the same
   decision on UDP, the plugin would have to peel the QUIC Initial packets
   itself — the Initial keys are derived from the client's DCID, so it would
   need `HKDF-Expand-Label` + AES-GCM + header-protection removal — reassemble
   the ClientHello out of the CRYPTO frames (it routinely spans several
   datagrams), and then drop them. Without that, an unknown SNI over QUIC is
   answered by quic-go with a `CONNECTION_CLOSE`: a ~89-byte Initial packet
   whose error code is `0x100 + TLS alert`, i.e. the same signal as the TCP
   alert this plugin exists to suppress, just moved to UDP. The port keeps
   answering probes.

2. **Without `protocols h1 h2`, Caddy advertises HTTP/3 to your clients.**
   Whenever the h3 server exists, every HTTP/1.1 and HTTP/2 response carries an
   `Alt-Svc: h3=":443"` header, and browsers act on it: they switch to QUIC on
   the next connection. The header therefore routes real traffic onto the one
   path this plugin cannot filter, keeping a second, answering endpoint alive
   next to the silent TCP one.

Turning HTTP/3 off fixes both at once: Caddy never creates the UDP socket at
all, and no `Alt-Svc` header is emitted. A QUIC probe then gets no reply of any
kind — the UDP port looks like nothing is listening on it — and legitimate
clients only ever talk to the TCP port you have private control over.

## How it works

`sni_whitelist` reads from the raw TCP connection only until it has parsed the
ClientHello, and it never consumes those bytes: an allowed connection hands
every byte it read back to the TLS stack, bit for bit. The decision is made
before `crypto/tls` is involved at all, which is why no TLS alert can be sent.

A ClientHello may span several TLS records (and therefore several TCP
segments), so record payloads are collected until the whole handshake message
is available. Anything that cannot be positively inspected — a connection that
does not begin with a TLS handshake record, a malformed ClientHello, or one
larger than the inspection limit (16 KiB + 5 bytes) — is passed through
unchanged, so the TLS stack remains the backstop and no legitimate client is
filtered out by accident.

`drop_non_tls` needs only the first six bytes: the record header (content type
must be handshake `0x16`, the record-layer major version must be `0x03` — SSL
3.0 through TLS 1.3 all use `0x03` there — and the record length must fit
inside a TLS record and be long enough to hold a handshake header), and then
the handshake message type, which must be ClientHello (`0x01`): the only
message a client is allowed to send first. Anything else cannot be the start of
a TLS client, so the connection is closed — before `crypto/tls` gets a chance to
answer with an alert, which is what it does for some of those shapes (SSLv2-style
hello → alert 70, oversized record → alert 22, non-ClientHello handshake message
→ alert 50).

Nothing else is parsed, and a connection that passes is handed on untouched, so
a real client cannot be affected. Deliberately, a ClientHello-typed message with
a malformed body still reaches the TLS stack — this is a cheap "is this a TLS
client" filter, not a TLS validator.

Plaintext HTTP needs no special case: a request line always starts with an
ASCII method name, so it can never begin with `0x16`, and the connection is
closed before Go's `net/http` can write its
`400 Client sent an HTTP request to an HTTPS server.`

## Caveats

- **HTTP/3 is not covered — turn it off.** QUIC runs over UDP and does not go
  through `net.Listener`, so `listener_wrappers` never see it. Use
  `protocols h1 h2` as shown in [Usage](#usage), which also stops Caddy from
  advertising h3 via `Alt-Svc`. See
  [Turn off HTTP/3 as well](#turn-off-http3-as-well) for the details.
- **ECH** encrypts the SNI; only the outer (cover) name is visible, so the
  decision is made on that.
- **The whitelist is a second place to maintain your names.** It must be kept
  in sync with the site addresses that Caddy actually manages certificates for.
- **Timeouts still matter.** The wrappers read inside the TLS handshake window,
  which `net/http` bounds by `min(ReadHeaderTimeout, ReadTimeout, WriteTimeout)`.
  If none of those is set a client that connects and says nothing (or sends half
  a ClientHello) holds the connection open indefinitely, one goroutine and one
  file descriptor each. The example in [Usage](#usage) sets
  `timeouts { read_header 10s }` for this reason.
- Wrappers are HTTP/app-level; they do not affect Caddy's admin endpoint.

## AI disclosure

This project is written with heavy AI assistance, not by hand. The whole
implementation — both listener wrappers, their tests and this document — was
produced with **DeepSeek V4.1 Flash** running in **OpenCode**, driven by a human
operator who set the requirements, made the design decisions (what gets dropped,
alert vs. RST, the HTTP/3 trade-off), reviewed the diffs, and ran the
packet-level tests behind the tables above.

What that means if you are thinking of using it:

- It is security-adjacent code, and it is young. There are no guarantees beyond
  the unit tests in this repository and the packet captures described here.
- Treat what you read as *reviewed by a human, but not proven by time*. Read the
  source before putting it in front of anything that matters. It is small on
  purpose: two wrappers, one shared helper, and their tests.
- Expect the maintainer to verify changes by reading the code rather than by
  trusting whichever model produced it.
- Bug reports, and corrections to the reasoning in this document, are welcome.

## License

[Apache-2.0](LICENSE).

Portions of this code are derived from Caddy
(<https://github.com/caddyserver/caddy>), Copyright 2015 Matthew Holt and The
Caddy Authors, also licensed under Apache-2.0. The original copyright notices
are retained in the source files.
