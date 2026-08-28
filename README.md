# openssl

TLS for sysl, bound over OpenSSL's memory BIOs.

```
dependencies {
  openssl { git = "github.com/sysl-lang/openssl", version = "0.1.0" }
}
```

## What it is

**OpenSSL is never given the socket.** It is given a pair of in-memory buffers: ciphertext you
received goes in one end and plaintext comes out; plaintext you want to send goes in and ciphertext
comes out to be written. TLS is a *transformation*, and how bytes reach the wire stays entirely
yours.

That is Node's arrangement — `tls.TLSSocket` wraps a `net.Socket` rather than replacing it — and it
is the reason this composes with anything. One binding serves a blocking fetch, a libuv connection,
and a test with no socket at all.

**This is a partial binding.** OpenSSL's surface is thousands of functions; what is here is a TLS
*client*, which is twenty-odd of them. Adding to it is ordinary work — the rule is that what is here
is faithful, not that it is complete.

## Using it

```sysl
import sh.sysl.openssl.*

val cl = client()?
val s = connect(cl, "github.com")?
```

Then a loop of three steps, **and the order is not free**:

1. Ask for progress — `handshake`, `send` or `receive`.
2. Drain `outgoing` and write every byte to the socket.
3. On `Wants`, read from the socket and hand what came to `incoming`. Back to 1.

**Draining before the first ask writes nothing, and then both ends wait forever.** Nothing is in the
outgoing buffer until something has been asked to produce it, so a loop that drains first sends no
ClientHello and then blocks reading a socket the server is also blocked reading. It looks like a
network fault. It cost this package's own first live handshake, and there is a test named for it.

## What it verifies, and what you cannot turn off

- **The machine's certificate store**, via `SSL_CTX_set_default_verify_paths` — Go's answer rather
  than Node's. A certificate the administrator added is trusted; there is no PEM blob shipped here
  to go stale.
- **The host name**, via `SSL_set1_host`. Without it a valid certificate for *any* host would pass.
- **SNI**, so a shared server knows which certificate to send. GitHub answers nothing without it.
- **TLS 1.2 as the floor.**

**There is no way to relax any of it**, and that is deliberate: a verify callback is how a program
overrides OpenSSL's decision, and a package offering one would be offering a way to accept a bad
certificate. If you need that, this is the wrong package.

## Requirements

OpenSSL and its headers, found by pkg-config:

```
brew install openssl@3          # macOS
sudo apt install libssl-dev     # Debian / Ubuntu
sudo pacman -S openssl          # Arch
```

## Testing

`sysl test .` — seven tests, **none of which needs a network.** That is the memory-BIO design paying
for itself: the real OpenSSL is driven through the real buffers and only the peer is missing, so what
is checked is that a ClientHello comes out with the right record header and the host name in it, that
nonsense arriving is reported as a failure rather than as a wait, and that a failure carries
OpenSSL's own words.

**The live handshake is verified by hand rather than by the suite**, because a unit suite that needs
the internet fails on a train. Verified 2026-08-28 against `github.com:443` — handshake completed,
certificate accepted, `HTTP/1.1 200 OK` returned.

## What is missing

Server support (`SSL_accept`, loading a certificate and key), session resumption, ALPN, and client
certificates. None is hard; none had a consumer yet.
