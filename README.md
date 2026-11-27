# openssl

TLS for sysl — both ends — bound over OpenSSL's memory BIOs, plus the primitives beside it: keys and
signatures, digests, HMAC, HKDF and authenticated encryption.

*An independent sysl package for OpenSSL. It is not affiliated with or endorsed by OpenSSL's authors or trademark holders.*

```
dependencies {
  openssl { git = "github.com/sysl-lang/openssl", version = "0.4.0" }
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

**This is a partial binding.** OpenSSL's surface is thousands of functions; what is here is about a
hundred of them. Adding to it is ordinary work — the rule is that what is here is faithful, not that
it is complete.

**Everything is one module, `sh.sysl.openssl`**, in a file per subject:

| file | what is in it |
|---|---|
| `openssl.sysl` | TLS: `Client`, `Server`, `Stream`, `Session`, and `Error` |
| `keys.sysl` | `PublicKey` and `PrivateKey`: read from PEM, DER or raw bytes, written back, generated |
| `sign.sysl` | `sign` and `verify` — RSA (PKCS#1 v1.5 and PSS), ECDSA, Ed25519 |
| `digest.sysl` | SHA-1 and SHA-2, one-shot and streaming; `equal` and `wipe` |
| `hmac.sysl` | HMAC, one-shot and streaming; HKDF |
| `aead.sysl` | AES-GCM and ChaCha20-Poly1305 |

Only the EVP tier of OpenSSL 3 is bound — nothing deprecated — and it builds unchanged against
OpenSSL 3 and OpenSSL 4.

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

**A refused certificate says why.** A failed handshake carries `Error.verify`, OpenSSL's X509 verdict
(`0` when the failure was not a certificate refusal), and the message ends with OpenSSL's words for
it. `error.refusal()` turns it into something to `match` on, because a wrong host name and an
untrusted issuer fail with the identical "certificate verify failed" code:

```
handshake() match
    Err(e) -> e.refusal() match
        Some(HostMismatch) -> ...        // trusted chain, different host (62)
        Some(Expired) -> ...             // notAfter is past (10)
        Some(NotYetValid) -> ...         // notBefore is ahead, usually a wrong clock (9)
        Some(Untrusted) -> ...           // unknown issuer or self-signed (2, 18, 19, 20, 21)
        Some(Other(code)) -> ...         // any other X509_V_ERR_* number
        None -> ...                      // not a certificate refusal
```

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

### Protocol versions

TLS 1.2 is the default floor at both ends. `min_version(v)`, `max_version(v)` and `versions(min, max)`
on a `Client` or a `Server` set the range with a `Version` (`Tls10` to `Tls13`); `versions` refuses a
floor above its ceiling. `Stream.version()` answers the negotiated version once the handshake has
finished, and `None` before. TLS 1.0 and 1.1 are nameable, but OpenSSL's default security level
refuses them.

### Keying material and channel binding

`Stream.export_keying_material(label, context, len)` derives `len` bytes from the session's secrets
(RFC 5705, RFC 8446 section 7.5); both ends get the same bytes, and they differ by label, context and
connection. RFC 9266 `tls-exporter` is label `EXPORTER-Channel-Binding`, no context, 32 bytes. Only
after the handshake has finished. `None` and an empty context are different under TLS 1.2 and the
same under TLS 1.3.

### One context, every thread

`client()` answers a `&sync Client` and `server(...)` a `&sync Server`: **build one context and hand it
to every thread that connects.** A client context reads the machine's whole trust store when it is
made, which is most of what a handshake costs; reusing one costs nothing. A `Stream` keeps its context
alive through an atomically counted reference, so the streams of one context may live on any threads,
and the context is freed when the last of them and the last name for it are gone.

**A context is configured before its first connection and never after.** OpenSSL lets `SSL_new` run
on several threads at once, but nothing about changing a setting while another thread's handshake reads
it. So the first `connect` or `accept` seals the context, and every setter after that — `trust`,
`offer`, the version setters and the session settings below — answers an `Error` instead of racing. A
lock makes the seal exact: a setter that began before the first connection has finished before its
`SSL_new`. After the seal nothing takes the lock again.

### Session resumption

A client resumes by keeping the `Session` a connection left and offering it to the next one:

```
val s = connect(cl, "example.com")?
// ... handshake, then at least one receive, then close
val kept = s.session()                     // Option[&sync Session]

val next = connect(cl, "example.com")?
kept match
    Some(k) -> next.resume(k)?             // before the handshake begins
    None -> ()
// ... handshake
next.reused()                              // true when the server accepted it
```

- **Under TLS 1.3 the tickets arrive after the handshake**, so `session()` is `None` until the client
  has called `receive` once with the server's bytes fed in.
- **A connection dropped without `close` loses its session.** OpenSSL treats an end with no
  close-notify as a possible truncation attack and stops resuming its session; `Session.resumable()`
  turns `false`. Close both ends with a goodbye.
- **A `Session` may cross threads** (`&sync Session`): OpenSSL counts its references atomically and a
  resumable session does not change, so one connection's session may be offered from any thread, or
  from several at once.
- `resume` is refused on a server stream and once the handshake has begun, rather than quietly making a
  full handshake.

A server is configured, before its first `accept`, with:

| setting | what it does |
|---|---|
| `session_cache(size)` | remember up to `size` sessions (on by default at OpenSSL's 20480); 0 is refused, since OpenSSL reads it as unlimited |
| `no_session_cache()` | remember none; tickets still resume |
| `session_id_context(id)` | 1 to 32 bytes naming this server; a session is resumed only by a server with the same one |
| `tickets(on)` | issue stateless tickets (default) or not; off, TLS 1.3 sends tickets naming cache entries, and with the cache off as well it sends none |
| `ticket_keys(keys)` | exactly 80 bytes (16-byte name, 32-byte HMAC key, 32-byte AES key); servers given the same keys and id context resume each other's tickets |

**There is no ticket-key rotation in place**, deliberately: OpenSSL reads the keys inside every
handshake with no lock, so rewriting them while another thread decrypts a ticket is a torn read.
Rotating is building a new `Server` with the new keys and accepting on it from then on; connections on
the old one keep it alive until they end.

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

RS256/384/512, PS256/384/512, ES256/384/512 and EdDSA (Ed25519). **The algorithms are named as JOSE
names them and are not JOSE's alone**: `Rs256` is RSASSA-PKCS1-v1_5 with SHA-256 wherever it turns
up, `Ps256` is RSASSA-PSS with MGF1 and a salt as long as the digest, `Es384` is ECDSA over P-384
with SHA-384 — the same choices TLS 1.3, X.509 and COSE make under other names.

**The curve is part of an `Es` algorithm.** RFC 7518 defines ES256 as P-256 and nothing else, so a
P-384 key under `Es256` is refused with an `Err` rather than used.

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
key of the wrong kind, an ECDSA or Ed25519 signature of the wrong length, a library failure.
Collapsing the two would make a misconfiguration look like an attack.

### Signatures in DER

Outside JOSE an ECDSA signature travels as DER — in a certificate, a TLS handshake, the output of
`openssl dgst -sign`. `sign_der` and `verify_der` are the same two directions in that form; for RSA
and Ed25519 they give and take the same bytes `sign` and `verify` do.

```sysl
val signature = sign_der(key, Es256, message)?          // an ECDSA-Sig-Value

if verify_der(public, Es256, message, signature.view())?
    ...
```

**`verify_der` never answers `Err` because of the signature.** It is a blob of no fixed length that
somebody else sent, so one of the wrong size, one that is not DER, and one that is DER written some
non-canonical way are all `Ok(false)`, exactly as a forgery is.

`ecdsa_der(alg, raw)` and `ecdsa_raw(alg, der)` convert between the two forms. `ecdsa_raw` answers
`None` unless its input is one signature in its one canonical encoding, with nothing after it.

## Keys

A `PublicKey` or a `PrivateKey` is one parsed key, freed when its last holder lets go. The encodings
are views of it: read from any, write to any.

```sysl
val key = private_key(pem)?                  // BEGIN PRIVATE KEY
val key = private_key_der(der)?              // PKCS#8, or the traditional RSA / EC form
val key = ed25519_private_key(seed)?         // RFC 8032's 32 bytes
val key = generate_key(KeyKind.EcP256)?      // Ed25519, EcP256, EcP384, EcP521, Rsa(bits)

val public = key.public_key()?               // or public_key(pem), public_key_der(der), ed25519_public_key(raw)

public.der()?                                // SubjectPublicKeyInfo
public.pem()?                                // BEGIN PUBLIC KEY
public.raw()?                                // Ed25519 only: its 32 bytes
key.der()?                                   // unencrypted PKCS#8
key.kind()                                   // Rsa(2048), RsaPss(bits), EcP256, EcP384, EcP521, Ed25519, Other
```

**What is written is SubjectPublicKeyInfo and unencrypted PKCS#8**, the two encodings everything
reads. The traditional forms (`BEGIN RSA PRIVATE KEY`, `BEGIN EC PRIVATE KEY`) are read and never
written.

**DER is read whole or not at all.** DER has no terminator, so bytes after a key are a different
input from the one that was parsed, and `public_key_der` and `private_key_der` refuse them.

**The package reads what OpenSSL reads and leaves policy to its caller.** A 1024-bit RSA key parses,
and `kind()` says `Rsa(1024)`; whether to use it is for whoever knows what the key is for. Making one
is different: `generate_key` makes RSA keys of 2048 to 16384 bits and refuses the rest.

**`public_key()` rebuilds the public half from its encoding**, so nothing reachable from the answer
holds the private half.

**Every encoding of a private key is the secret.** OpenSSL wipes its own copy when the key is
dropped; what `der`, `pem` and `raw` answer is yours to `wipe`.

## Digests, HMAC and HKDF

```sysl
val d = digest(Sha384, bytes)?               // Sha1, Sha224, Sha256, Sha384, Sha512

val h = hasher(Sha256)?
h.update(first)?
h.update(second)?
val d = h.finish()?                          // once: the hasher is then spent

val tag = hmac(Sha256, key, message)?

val m = hmac_begin(Sha512, key)?
m.update(piece)?
val tag = m.finish()?

if equal(tag.view(), received)               // never ==
    ...

val okm = hkdf(Sha256, secret, salt, info, 32)?
val prk = hkdf_extract(Sha256, salt, secret)?
val okm = hkdf_expand(Sha256, prk.view(), info, 32)?
```

**The digest is an argument, as the signing algorithm is**, and one enum names it for digests, HMAC
and HKDF alike.

**Compare a MAC with `equal`.** It takes the same time wherever two strings differ; `==` stops at the
first wrong byte, and how long it took tells whoever is sending forgeries how much they have right.

**SHA-1 is here for what still names it** — HMAC-SHA-1 in HOTP and TOTP — and not as a digest to
choose. Collisions in it can be made on purpose; HMAC over it is unaffected.

**HKDF is for a secret that is already unguessable** (a Diffie-Hellman result, a random master key),
not a password: it is fast on purpose. An empty `salt` is RFC 5869's digest-worth of zeros; `length`
is at most 255 digests; `hkdf_expand` refuses a pseudorandom key shorter than the digest, which is
what the RFC requires of one.

`wipe(bytes)` overwrites a buffer with zeros in a way the optimiser may not remove.

## Authenticated encryption

AES-128-GCM, AES-256-GCM and ChaCha20-Poly1305, each with a 12-byte nonce and a 16-byte tag.

```sysl
val sealed = aead_seal(Aes256Gcm, key, nonce, aad, plaintext)?     // ciphertext, then the tag

aead_open(Aes256Gcm, key, nonce, aad, sealed.view())? match
    Some(plaintext) -> ...
    None -> ...                                                    // it did not authenticate
```

**A message that does not authenticate yields nothing.** `aead_open` decrypts into a buffer the
caller never sees until the tag has checked; when it does not, the buffer is wiped and `None` is the
whole answer.

**`Ok(None)` is a message that does not authenticate; `Err` is a question that could not be asked.**
Anything changed in the ciphertext, the tag or `aad`, another key or nonce, or fewer bytes than a
tag: `None`. A key or a nonce of the wrong length: `Err`.

**A nonce is used once per key, and that is yours to guarantee.** Two messages sealed under one key
and one nonce give away the XOR of their plaintexts and, for GCM, the key that authenticates them.

`aad` is authenticated and not carried: whoever opens the message supplies the same bytes.

## Requirements

OpenSSL and its headers, found by pkg-config:

```
brew install openssl@3          # macOS
sudo apt install libssl-dev     # Debian / Ubuntu
sudo pacman -S openssl          # Arch
```

## Testing

`sysl test .` — 197 tests, **none of which needs a network.**

**The primitives are checked against the documents that define them, not against the `openssl`
command** — two views of one library agree with each other's mistakes.

| what | checked against |
|---|---|
| SHA-1, SHA-224, SHA-256, SHA-384, SHA-512 | FIPS 180's examples: `abc`, the two-block messages, the empty message, and a million `a`s fed a thousand at a time |
| HMAC | RFC 4231's seven cases under all four SHA-2 digests; RFC 2202 for SHA-1 |
| HKDF | RFC 5869's seven cases, with the pseudorandom key checked as well as the output; over SHA-224/384/512, the RFC's definition computed from `hmac` |
| AES-GCM | the GCM specification's test cases 1–4 (128-bit) and 13–16 (256-bit) |
| ChaCha20-Poly1305 | RFC 8439 section 2.8.2 |
| Ed25519 | RFC 8032 section 7.1, tests 1, 2, 3 and SHA(abc): signing reproduces each signature byte for byte |
| ECDSA | RFC 6979 A.2.5 and A.2.6: the RFC's P-256 and P-384 signatures verify, its private scalars derive its public points, and signatures made with its private keys verify under its public ones |
| RSA | RFC 7515 A.2: the RFC's RS256 signature verifies and signing reproduces it; PSS by sign-then-verify |
| key encodings | RFC 8410's wrapping of RFC 8032's key, and RFC 5480 / RFC 5915 wrappings of RFC 6979's, written out by hand |

**Every vector is shown able to fail.** One bit of the key, the nonce, the associated data, the
ciphertext, the tag, the message or the signature — every byte of it, for a sealed message and for an
RSA or Ed25519 signature — and the test asserts the answer changes. The binding itself was then broken
on purpose, one argument at a time (the associated data left out of sealing, and of opening; the salt
or the info dropped from HKDF; the key's length ignored by HMAC; a digest wired to another's name;
the tag check skipped; PSS padding left off; the curve check loosened; the trailing-bytes check
removed), and each break turned a test red.

The sharing tests run one `Client` and one `Server` through eight threads handshaking at once, a
context whose every name is gone before its streams' handshake, and the seal at both ends, including
a connection made on another thread sealing the context here. The session tests resume and decline in
pairs, each setting tested by a pair that would resume without it and does not with it: two servers
sharing ticket keys and an id context resume each other's tickets, and a different id context, different
keys, or tickets off stops it; a cache of one forgets the older session; a session crosses threads both
ways and is offered from eight at once. Every new setting was broken on purpose and seen to turn a test
red. A program sharing both contexts across eight threads with a session offered from each is net zero
on the counted heap (`SYSL_COUNT_ALLOCS=1`).

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

A ticket-key rotation callback (see above for why there is none), client certificates, SNI callbacks on the server side, and building a key from a
JWKS document's `n`/`e` or `x`/`y` rather than from PEM. None is hard; none has a consumer yet.

Among the primitives, deliberately:

- **Encrypted private keys**, read or written. A passphrase prompt is not something a library does,
  and a passphrase argument has no consumer.
- **Streaming authenticated encryption.** Releasing plaintext before the tag has checked is the
  mistake an AEAD exists to prevent; a message too large for memory wants a chunked construction
  with its own framing, which is a design of its own.
- **Nonces and tags of other lengths**, AES-192-GCM, AES-CCM, AES-GCM-SIV and XChaCha20-Poly1305
  (which OpenSSL does not have).
- **Deterministic ECDSA** (RFC 6979). OpenSSL signs with a random nonce; its deterministic mode
  arrived in 3.2 and is not in every OpenSSL 3 a distribution ships.
- **Ed448, X25519 and ECDH, RSA encryption, DSA**, and SHA-3, SHA-512/256, MD5 and BLAKE2.
- **PBKDF2, scrypt and Argon2.** A password is not HKDF's input, and the org's `password` package is
  where stretching one lives.
- **PSS with any salt length but the digest's**, and MGF1 over a different digest from the message's.
