# openssl

TLS for sysl — both ends — bound over OpenSSL's memory BIOs, plus the digest signing a token needs.

```
dependencies {
  openssl { git = "github.com/sysl-lang/openssl", version = "0.2.0" }
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

**It is also why the server side cost almost nothing.** A `Stream` never touches a socket and never
asks which end it is, so accepting is `connect` with one call changed. Nothing in the connection
tier had to move.

**This is a partial binding.** OpenSSL's surface is thousands of functions; what is here is fifty-odd
of them. Adding to it is ordinary work — the rule is that what is here is faithful, not that it is
complete.

## A client

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

### What it verifies, and what you cannot turn off

- **The machine's certificate store**, via `SSL_CTX_set_default_verify_paths` — Go's answer rather
  than Node's. A certificate the administrator added is trusted; there is no PEM blob shipped here
  to go stale.
- **The host name**, via `SSL_set1_host`. Without it a valid certificate for *any* host would pass.
- **SNI**, so a shared server knows which certificate to send. GitHub answers nothing without it.
- **TLS 1.2 as the floor.**

**There is no way to relax any of it**, and that is deliberate: a verify callback is how a program
overrides OpenSSL's decision, and a package offering one would be offering a way to accept a bad
certificate. If you need that, this is the wrong package.

`client.trust(pem)` is the one thing that moves, and it moves **upward**: it adds a certificate
authority to what is already trusted. A private root, a corporate one, or the self-signed
certificate a test stands up are the same case.

## A server

```sysl
val sv = server(certificate_pem, key_pem)?

sv.offer(["h2", "http/1.1"])?

val s = accept(sv)?
```

The driving loop is the client's, unchanged.

**Both arguments are PEM bytes, never a file name.** OpenSSL is not given the socket here and giving
it the filesystem instead would be the same leak wearing a different hat: bytes may have come from a
file, a secret store, an environment variable or a test's own string, and this neither knows nor
asks. The certificate may be a **chain, leaf first**, which is what a public authority hands out.

**A key that does not go with the certificate is caught here and nowhere else.** Both installs
succeed on a mismatched pair, and the handshake then fails at the *peer* with a decrypt error that
says nothing about this end at all.

### ALPN

`offer(protocols)` at either end, most preferred first, and `Stream.protocol()` once the handshake is
done. **The server's own order wins** — it is the end that knows which protocol it serves well — and
two ends with nothing in common fail the handshake, which is what RFC 7301 asks for.

`None` from `protocol()` is an ordinary answer: a peer that offered nothing, or supports no ALPN at
all, leaves it unset and the connection is fine.

## Signing and verifying

Enough to check a JWT's signature. **This is the crypto, not a JWT library** — a token is three
base64url pieces, a JSON header and a set of claims to check against a clock, all of which sysl can
already do. What could not be done anywhere before this was deciding whether a signature over
`header.payload` was made by the key a JWKS document names.

```sysl
val key = public_key(pem)?

if verify(key, Rs256, signing_input, signature)?
    ...
```

RS256/384/512, PS256/384/512 and ES256/384/512. `monocypher` has Ed25519 and nobody issues EdDSA
tokens, which is why this is OpenSSL's job.

**The algorithm is an argument because the `alg` header is not to be trusted.** A verifier that read
the algorithm out of the token it is checking accepts whatever an attacker wrote there — which is how
`alg: none` and the RS256-key-as-an-HMAC-secret confusion both work. The caller says what it expects;
the token gets no vote.

**An ECDSA signature has two representations and JOSE uses the one OpenSSL does not.** RFC 7518
carries it as `r || s`, each coordinate padded to the curve's width; `EVP_DigestVerify` wants the DER
`ECDSA-Sig-Value` everything else uses. Converting is this package's job, and `verify` and `sign`
both speak JOSE's form. A binding that skipped it would **verify nothing and report success**,
because a failed DER parse and a forged signature come back from OpenSSL as the same zero.

`Ok(false)` is a signature that does not check out; `Err` is a question that could not be asked — a
key of the wrong kind, an ECDSA signature of the wrong length, a library failure. Collapsing the two
would make a misconfiguration look like an attack.

## Requirements

OpenSSL and its headers, found by pkg-config:

```
brew install openssl@3          # macOS
sudo apt install libssl-dev     # Debian / Ubuntu
sudo pacman -S openssl          # Arch
```

## Testing

`sysl test .` — 38 tests, **none of which needs a network.**

That is the memory-BIO design paying for itself twice over. The client tests drive the real OpenSSL
through the real buffers with only the peer missing. The server tests stand a `Client` and a `Server`
up **in one process and cross their buffers by hand**: a complete handshake, a self-signed
certificate refused by a client that does not trust it, a certificate for the wrong host refused,
three ALPN outcomes, bytes each way and a close-notify — with no socket, no port, and no permission
to bind one.

The signing tests are checked against **RFC 7515's own worked examples** rather than against
themselves: Appendix A.2's RSA key and its exact RS256 signature, and Appendix A.3's P-256 key and
its exact `r || s`. Signing A.2's input reproduces A.2's signature byte for byte, since
RSASSA-PKCS1-v1_5 is deterministic. A.3's `s` begins with 197 — its top bit is set — so it is
precisely the vector the DER conversion exists for.

**Verified by hand as well, because two implementations that share a bug agree with each other.**
A server built on this package was driven by `curl` and by `openssl s_client` on 2026-08-29: both
completed the handshake, verified the certificate, and were answered; `s_client` offering
`http/1.1,h2` was given `h2`, which is this end's order winning against a real client. The whole
suite and that live server are also clean under AddressSanitizer
(`SYSL_EXTRA_CFLAGS="-fsanitize=address -g"`), with the instrumentation confirmed present rather
than assumed.

## What is missing

Session resumption, client certificates, SNI callbacks on the server side, and building a key from a
JWKS document's `n`/`e` or `x`/`y` rather than from PEM. None is hard; none has a consumer yet.
