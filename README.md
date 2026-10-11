# caddy-antiprobe

Two [Caddy](https://caddyserver.com) **listener wrappers** that keep a TLS port from answering probes. Both are [out-of-tree Caddy modules](https://caddyserver.com/docs/extending-caddy): no fork of Caddy is required.

| Caddyfile directive | Module ID | Effect |
| --- | --- | --- |
| `sni_whitelist` | `caddy.listeners.sni_whitelist` | Reads the SNI out of the ClientHello **before `crypto/tls` ever sees it**. If the name is not in the whitelist, the connection is torn down without writing a single byte. |
| `http_drop` | `caddy.listeners.http_drop` | Plaintext HTTP sent to a TLS port is disconnected with no response. |

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
| SNI not in the whitelist | `alert(2, 80)` | 0 bytes, connection closed (TCP RST by default) |
| SNI is whitelisted | works | works, unchanged |

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
		listener_wrappers {
			http_drop
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

`http_drop` takes no arguments. `sni_whitelist` takes an optional first
argument selecting how a rejected connection is torn down:

- `reset` — close with a TCP RST (**default**, also when the argument is omitted)
- `fin` — close gracefully with a TCP FIN

Every name in the block is one allowed server name, one per line. Names are
compared case-insensitively, a trailing dot is ignored, and a left-most label
wildcard like `*.example.com` matches `a.example.com` but not
`a.b.example.com`. `*` matches any name.

A connection whose ClientHello carries **no SNI at all** matches nothing, so it
is rejected as well.

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

`http_drop` does the same thing for the first five bytes of a connection: if
they look like an HTTP request line (`GET /`, `HEAD `, `POST `, `PUT /`,
`OPTIO`) on a listener dedicated to TLS, the connection is closed and no
response is written.

## Caveats

- **HTTP/3 is not covered.** QUIC runs over UDP and does not go through
  `net.Listener`, so `listener_wrappers` never see it. An unknown SNI on QUIC
  still fails the handshake (the certificate lookup fails), just not silently.
  Disable HTTP/3 with `protocols h1 h2` if you need identical behaviour, or add
  a `caddy.packetconns` wrapper.
- **ECH** encrypts the SNI; only the outer (cover) name is visible, so the
  decision is made on that.
- **The whitelist is a second place to maintain your names.** It must be kept
  in sync with the site addresses that Caddy actually manages certificates for.
- **Timeouts still matter.** The inspection happens inside the TLS handshake
  window, which `net/http` bounds by `min(ReadHeaderTimeout, ReadTimeout,
  WriteTimeout)`. If none of those is set, a client that sends half a
  ClientHello can hold the connection open. Configure
  `servers :443 { timeouts { read_header 10s } }` if that matters to you.
- Wrappers are HTTP/app-level; they do not affect Caddy's admin endpoint.

## License

[Apache-2.0](LICENSE).

Portions of this code are derived from Caddy
(<https://github.com/caddyserver/caddy>), Copyright 2015 Matthew Holt and The
Caddy Authors, also licensed under Apache-2.0. The original copyright notices
are retained in the source files.
