# group-space-crypto

The end-to-end encryption core of [Group Space](https://group-space.com):
field encryption with context binding, the account keychain protocol, and the
chunked encrypted media container, extracted from the app so the code that
guards content can be read, tested, and rebuilt by anyone.

**This is composition, not invention.** Every primitive is libsodium (and,
for the decrypt-only worker client, @stablelib's XChaCha20-Poly1305). The
design work is the key hierarchy, the AAD context registry, and the frozen
wire formats. All of it is specified in [`docs/protocol.md`](docs/protocol.md)
precisely enough to reimplement from the page and verify against the
committed vectors.

## What is here

| entry | contents |
| --- | --- |
| `.` / `./e2ee` | primitives: passphrase wraps (Argon2id), keypairs, grants (sealed boxes), field AEAD, the media container |
| `./account-keys` | the account keychain: enrollment, recovery kit, membership rewrap |
| `./aad` | the context-label registry. Every label unique, labels only ever added |
| `./media-format` | the frozen wire constants |
| `./media-range` | pure range arithmetic over the container geometry |
| `./sw-decrypt` | decrypt-only client for service workers: no WASM, no sealer, @stablelib underneath |

Zero-crypto subpaths (`aad`, `media-format`, `media-range`) import neither
crypto library, so a worker bundle can take the geometry without the engine.

## Verify it

```bash
npm ci
npm run typecheck && npm test && npm run test:vectors
```

`test/vectors/v1.json` is the wire-format contract: deterministic seals with
frozen digests, recorded randomized wraps that must open forever, and both
implementations driven against the same bytes. `docs/verify.md` explains what
each verification tier proves, and what it deliberately does not claim.

## What this is not

- **Not a promise about what any server serves you.** An open library does
  not, by itself, prove what a hosted app runs. The honest boundary is
  documented in [`docs/threat-model.md`](docs/threat-model.md) and the
  narrowing plan in [`docs/verify.md`](docs/verify.md).
- **Not audited.** Self-tested and interop-verified; no independent audit
  yet. When that changes, it will say so here with a link, not an adjective.
- **Not a general-purpose crypto library.** It is the specific protocol of a
  specific product, frozen because real deployments hold ciphertext in this
  exact format.

## Provenance

Extracted from the Group Space application. History prior to extraction lives
in the private app repository; this repo starts at the extraction commit and
the app consumes this package, not a private copy.

## License

Apache-2.0. See `LICENSE`.
