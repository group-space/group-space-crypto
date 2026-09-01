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

### 4.1 The purpose tag

A wrap can name the slot it belongs in. Without one, two blobs wrapped under a
single passphrase are interchangeable: one account holding several membership
private keys under one password is the case that matters, and swapping two of
them hands the holder the wrong key in the right slot. Keys are random, so the
result is a failure somewhere further down rather than a disclosure, which
makes it a robustness problem and an unusually confusing one to diagnose.

The tag is a caller-chosen string, a membership id or a role, and the library
composes it. It must not be empty and must not contain a colon: the colon is
the separator, so `("a:b", "c")` and `("a", "b:c")` would otherwise produce the
same AAD and each blob would open in the other's slot. Both are refused.

```
ad = utf8("wrap.secret" ":" purpose)     when a purpose is given
ad = none                                when it is not
```

Nothing about the `WrappedSecret` shape changes, and the tag is not stored: as
in §5, both sides know the label from context. Naming no purpose behaves
exactly as it did before purposes existed, which is what keeps every previously
wrapped blob openable.

A blob wrapped with a purpose does not open without one, and the reverse, so a
caller upgrading old blobs attempts the purpose first, falls back to none, and
re-wraps whatever it opened. That is a caller's decision and this library does
not make it.

**While that fallback is in place the binding provides no protection.** Nothing
records whether a given blob was wrapped with a purpose, so a caller cannot
tell one presented in the wrong slot from a legacy blob that never had one.
Both fail the first attempt and both succeed on the second. A swap performed
during the migration therefore opens the wrong key, which is the outcome the
purpose exists to prevent. Keep the window short, and treat it as a migration
step rather than a steady state.

Callers must also finish migrating before considering a rollback: a
purpose-bound blob does not open under a release that predates this section.

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

A `context` must not be a bare integer, must not contain a colon, and must not
begin with a label from the registry in `src/aad.ts`. The frame AAD carries no
prefix of its own, so `<context>:<index>` shares a string space with the
composed labels used elsewhere under the same key; a context drawn from outside
that set keeps the two apart. This is a constraint on callers rather than
something the format enforces, because contexts predate it and validating them
now would refuse containers already written. The shipped contexts (`"full"`,
`"thumb"`, and the avatar context) satisfy it.

Range arithmetic over this geometry (`src/media-range.ts`) is pure integer
math shared by the app, the service worker, and the tests: byte range of the
plaintext → frame span of the ciphertext, and back.

### 6.1 The length manifest

The frame AAD binds each frame to its place, and the tag catches any edit
inside a frame. Neither binds **how many frames there are**, so a container
with whole frames removed from the end is a shorter container that opens
without error. A reader holding only the bytes it was handed cannot tell the
difference, because both are internally valid.

The manifest is the missing figure, sealed so the party storing the bytes
cannot rewrite it:

```jsonc
// SealedField (§5) over JSON, under the per-file key,
// with AAD  utf8("media.manifest" ":" context)
{ "bytes": 655370, "frames": 3 }
```

`bytes` is the total plaintext length; `frames` is the number of frames
written. An empty file is one frame, matching §6. The AAD carries the
container's context, so a `full` manifest cannot be presented as a `thumb`.

It is stored beside the container's wrapped file key and supplied by the
caller at open time. Range reads are the reason the count lives in a manifest
rather than in a marker on the final frame: a reader fetching bytes from the
middle of a video legitimately never sees the last frame, and cannot be asked
to require one.

Supplying it is **optional**, which keeps every stored container readable and
is also the limit of what this buys. The manifest is stored in the same record
as the container, so a party willing to remove trailing frames can remove the
manifest along with them, and a reader with no manifest has no way to know one
was ever written. Detection therefore holds only where the reader requires a
manifest and can tell a missing one from a file that never had one. That is a
caller's arrangement, not a property this format supplies on its own, and it is
not yet in place: no caller passes a manifest today.

Closing it means putting the figures somewhere a host cannot strip without
breaking decryption outright, so that a missing manifest is indistinguishable
from a broken file rather than from an ordinary one.

## 7. Recovery codes

A recovery code is 20 characters from the 32-character alphabet
`ABCDEFGHJKMNPQRSTVWXYZ0123456789` (no I, L, O, U), displayed as 4 groups of 5
separated by dashes, for 100 bits. Before use it is **normalized**: uppercased,
and every character outside `[A-Z0-9]` removed, so re-typing with different
dashes or case still opens the wrap. The normalized string is the passphrase
for a standard `WrappedSecret` (§4) over the protected secret.

Codes minted before this shape was adopted were 40 characters over the same
alphabet, for 200 bits. They remain valid indefinitely and require no
migration: a code is only ever a passphrase into `wrapSecret`, so the length of
what is *minted* has no bearing on what can be *opened*. Implementations MUST
accept a normalized code of any length.

The shortening is deliberate rather than a relaxation. 100 bits places an
offline search against a stolen `WrappedSecret` beyond reach by any margin that
matters, and the remaining 100 bits were paid for in transcription: a recovery
code is read off a screen, written down, kept for years, and typed back at the
worst moment its holder has had. A code long enough to be mis-saved is, in
practice, a code that was never saved.

The KDF parameters are deliberately not raised alongside it. The same
`WrappedSecret` wrapper protects membership keys that a phone unwraps on every
session, and its parameters are chosen so that unwrap stays within a mobile
browser's memory budget (§4). At 100 bits of uniform entropy the KDF is not the
binding constraint on this attack.

The code is generated client-side, shown once, and never sent to the server.
There is no server-side reset path; that is the point.

## 8. The freeze, stated as a commitment

The following can never change within format v1:

- the primitives and their parameters' *meaning* (§1),
- the base64 variant (§2),
- the `WrappedSecret` and `SealedField` shapes (§4, §5),
- every AAD label already in the registry (`src/aad.ts`); labels may be
  **added**, never renamed or removed (`media.manifest` in §6.1 and
  `wrap.secret` in §4.1 were both added this way and are now frozen on the same
  terms),
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
