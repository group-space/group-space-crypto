# Threat model

The candid version, because a threat model that flatters the product protects
nobody. This describes what the protocol in `docs/protocol.md` defends against
when correctly deployed, where the line is, and what remains visible on the
wrong side of it.

## Defended: the curious or compromised host

The adversary this design takes seriously is the party operating the server,
or holding what the server holds:

- a nosy or coerced operator reading the database,
- a stolen database backup or object-store bucket,
- a breach of the running server.

Against that adversary, group **content** is ciphertext: discussion titles and
bodies, every event detail including its times, contact phone and address,
children's names and grades, photos and video (full media *and* thumbnails,
which also strips EXIF/GPS from previews), album names and descriptions,
payment-collection details, RSVP answers, and (in push payloads) the message
content and the sender's display name. Keys exist server-side only as wrapped
or sealed blobs the server cannot open.

## Not defended, stated plainly

**A malicious host serving modified code.** This is a web-delivered client.
The party that serves the JavaScript could serve different JavaScript. Open
code, published artifacts, and the verification tiers in `docs/verify.md`
narrow this (a modification would have to be targeted and risks detection);
they do not close it. Anyone whose adversary can compel the operator should
treat that adversary as out of scope for this tool, and for any tool with
this delivery model.

**A compromised member device.** A device that can decrypt is a device that
can leak. Nothing in this repo pretends otherwise.

**Traffic and platform metadata.** TLS protects the wire; the platform still
sees connection metadata as any host does.

## The metadata line

The server necessarily sees, and this protocol does not hide:

- who belongs to which group (the grant table is who-can-open-what),
- when members are active, and from where (ordinary web traffic),
- object sizes and timing: the *shape* of activity, not its content,
- email addresses (they are the login credential and recovery channel),
- in the shipping parent-market product: display names and group names
  (rendered before a viewer holds any key). Narrowing this specific line is
  the active engineering programme; narrowing is not removal, and no copy
  anywhere should imply the metadata line can reach zero.

## Standing limits

- **Not independently audited.** Self-tested (the suites and vectors in this
  repo) and interop-verified across two implementations; no third party has
  yet been paid to attack it.
- **No formal verification.** The compositions are standard; the assurance is
  tests, vectors, and reviewability, not proofs.
- **Password-derived keys are as strong as the password.** Argon2id at
  interactive cost raises the price of guessing; it does not make a weak
  password strong.
- **The AEAD is not key-committing.** XChaCha20-Poly1305 permits a ciphertext
  crafted to decrypt validly under two different keys, the partitioning-oracle
  class of attack. No flow here selects a key by testing which one opens a
  ciphertext, so nothing in the current design turns this into a break, and it
  is accepted rather than mitigated. It is recorded because it constrains what
  can be built later: a key-selection or multi-recipient path would need a
  committing construction, decided at that point and not retrofitted after the
  fact.

If your safety depends on getting this exactly right against a resourced,
targeted adversary, use tools built and audited for that work, and the
operational guidance that goes with them. For everyone who simply refuses to
be the product, this is what honest engineering under this delivery model
looks like.
