# The Group Space encryption protocol, format v1

This document specifies what the library in `src/` implements, precisely enough
that an independent implementation can be written from this page and verified
against the committed test vectors (`test/vectors/v1.json`) without running our
code. Where this document and the code disagree, the code and its vectors are
the protocol and this document has a bug. Please report it.

**Format v1 is frozen.** Every constant, layout, and serialized shape below
describes ciphertext already at rest in real deployments. A change to any of
them is not a version bump; it is a data migration. See §8.

## 1. Primitives

All cryptography is composition of published, unmodified primitives, as
implemented by libsodium (and, for the decrypt-only worker client,
@stablelib's XChaCha20-Poly1305):

| role | primitive |
| --- | --- |
| authenticated encryption | XChaCha20-Poly1305 (IETF), 24-byte nonce, 16-byte tag |
| password-based key derivation | Argon2id v1.3 (`crypto_pwhash`, alg `ARGON2ID13`) |
| asymmetric sealing | libsodium sealed boxes (`crypto_box_seal`: X25519 + XSalsa20-Poly1305) |
| hashing (vectors only) | BLAKE2b-256 (`crypto_generichash`) |
| randomness | `randombytes_buf` |

There is no bespoke cryptography anywhere in this library. The design work is
in the **key hierarchy**, the **context binding**, and the **wire formats**.

## 2. Encoding

Every value that crosses a storage or transport boundary is a **base64 string,
libsodium `ORIGINAL` variant** (standard alphabet, padded). Raw bytes exist
only inside function boundaries. Text is UTF-8.

## 3. Key hierarchy

```
password ──Argon2id──▶ wrapping key ──AEAD──▶ member/account private key (X25519)
                                                     │
                          sealed box (crypto_box_seal) to the public key
                                                     │
                                                     ▼
                                              Group Key (32 bytes, symmetric)
                                                     │
              ┌──────────────────────────────────────┼─────────────────────┐
              ▼                                      ▼                     ▼
      field AEAD (§5)                        file key wrap (§6)     recovery wrap (§7)
```

- The **Group Key** is 32 random bytes. It never exists server-side in the
  clear; the server stores only sealed grants and ciphertext.
- Each member (and each account, in the multi-group platform) holds an
  **X25519 keypair**. The public key is stored in the clear; the private key is
  stored only as a `WrappedSecret` (§4) under the holder's password.
- A **grant** is `crypto_box_seal(groupKey, recipientPublicKey)`, anonymous
  sealing: anyone can produce a grant, only the holder of the matching private
  key can open it. This one asymmetry powers admission, re-approval, and
  directed pre-approved invites.

## 4. `WrappedSecret`: passphrase wrapping

A symmetric secret (a private key, a Group Key) wrapped under a passphrase:

```jsonc
{
  "salt":       "<base64, crypto_pwhash_SALTBYTES = 16>",
  "nonce":      "<base64, 24 bytes>",
  "ciphertext": "<base64, secret ‖ 16-byte tag>",
  "ops":        2,        // Argon2id opslimit actually used
  "mem":        67108864  // Argon2id memlimit actually used (bytes)
}
```

Derivation: `key = crypto_pwhash(32, passphrase, salt, ops, mem, ARGON2ID13)`,
then `ciphertext = XChaCha20-Poly1305(secret, ad = none, nonce, key)`.

The parameters are **recorded in the blob**, not implied by the library
version. New wraps use libsodium's `INTERACTIVE` limits (mobile-safe, ≈ 64 MB);
old blobs open with whatever they recorded. Raising the defaults never breaks
an existing wrap.

## 5. Field AEAD with context binding

A text field sealed under the Group Key:

```jsonc
{ "nonce": "<base64, 24 bytes>", "ciphertext": "<base64, utf8(plaintext) ‖ tag>" }
```

`ciphertext = XChaCha20-Poly1305(utf8(plaintext), ad = utf8(aad), nonce, key)`.

The **AAD is a context label**, and it is the whole idea of the field
layer: a ciphertext is bound to *what it is*, so a sealed discussion body can
never be replayed as an event title, a member's sealed phone number can never
be presented as an address, and a sealed push attribution can never stand in
for a message. The registry of labels lives in `src/aad.ts` and every label is
unique. Decryption with the wrong label MUST fail (the vectors assert this).

The label is not secret and not stored beside the ciphertext; both sides know
it from context. An empty string is a valid label (meaning "no context") and
is deliberately rare.

## 6. The encrypted media container

Large binaries (photos, video) are sealed under a **per-file key** of 32 random
bytes, itself wrapped under the Group Key as a field with AAD `"filekey"`
(§5). Per-file keys are what make a future single-file re-share or expiry
cheap: revoking or expiring one file never touches another's key.

The container is a sequence of independently sealed **frames**, so a range of
a large video can be fetched and decrypted without the whole file:

```
plaintext:  [ chunk 0: 262144 bytes ][ chunk 1: 262144 bytes ] … [ final chunk: 1..262144 bytes ]
ciphertext: [ frame 0 ][ frame 1 ] … [ final frame ]

frame i  =  nonce_i (24 bytes) ‖ XChaCha20-Poly1305(chunk_i, ad = utf8(context ":" i), nonce_i, fileKey)
         =  24 ‖ len(chunk_i) ‖ 16 bytes
```

| constant | value | meaning |
| --- | --- | --- |
| `MEDIA_CHUNK_SIZE` | 262 144 | plaintext bytes per chunk |
| `NONCE_BYTES` | 24 | per frame, prepended |
| `TAG_BYTES` | 16 | per frame, appended |
| `FULL_FRAME_BYTES` | 262 184 | ciphertext bytes of a full frame |

The AAD binds each frame to its **index within its context** (`"full:0"`,
`"full:1"`, …), so frames cannot be reordered, dropped from the middle,
duplicated, or transplanted between files without the open failing. An empty
file is one frame sealing zero bytes (24 + 0 + 16 = 40 bytes of ciphertext).

Range arithmetic over this geometry (`src/media-range.ts`) is pure integer
math shared by the app, the service worker, and the tests: byte range of the
plaintext → frame span of the ciphertext, and back.

## 7. Recovery codes

A recovery code is 40 characters from the 32-character alphabet
`ABCDEFGHJKMNPQRSTVWXYZ0123456789` (no I, L, O, U), displayed as 8 groups of 5
separated by dashes, for 200 bits. Before use it is **normalized**: uppercased,
and every character outside `[A-Z0-9]` removed, so re-typing with different
dashes or case still opens the wrap. The normalized string is the passphrase
for a standard `WrappedSecret` (§4) over the protected secret.

The code is generated client-side, shown once, and never sent to the server.
There is no server-side reset path; that is the point.

## 8. The freeze, stated as a commitment

The following can never change within format v1:

- the primitives and their parameters' *meaning* (§1),
- the base64 variant (§2),
- the `WrappedSecret` and `SealedField` shapes (§4, §5),
- every AAD label already in the registry (`src/aad.ts`); labels may be
  **added**, never renamed or removed,
- every constant in §6, and the frame layout,
- the recovery alphabet and normalization (§7).

A hypothetical format v2 would be a new container/envelope version negotiated
explicitly, shipped alongside v1 readers, and is out of scope until a
cryptographic break forces it. The committed vectors are the enforcement: a
vector that stops passing is a format break, and CI treats it as one.

## 9. What this library deliberately does not contain

- **No key management policy.** Where wrapped keys are stored, when they are
  unlocked, and what "signed out" means are application decisions.
- **No transport.** Nothing here talks to a network.
- **No metadata protection.** Object sizes, timing, and who-holds-which-grant
  are visible to whoever runs the server. See `docs/threat-model.md`. Those
  limits are part of the protocol's honest description, not a footnote.
