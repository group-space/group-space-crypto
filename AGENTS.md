# Working in this repo

Read this before changing anything. This repository is a **published artifact
that strangers audit**, not an internal working copy, and several ordinary
habits are wrong here.

## The three rules that outrank convenience

**1. Format v1 is frozen.** Every constant in `src/media-format.ts`, the frame
layout, the `WrappedSecret` and `SealedField` shapes, the base64 variant, the
recovery alphabet, and every AAD label already in `src/aad.ts` are what
ciphertext at rest in real deployments was written with. Changing one does not orphan a
test; it orphans production data. AAD labels may be **added**, never renamed or
removed. See `docs/protocol.md` §8.

**2. `test/vectors/v1.json` is a contract, not a fixture.** If a vector fails,
the default assumption is that the code broke the wire format, not that the
vector is stale. Regenerating it (`npm run vectors:generate`) is a deliberate
act that needs a reason in the commit message. A vector regenerated to make a
red build green is a data-loss incident with a passing CI badge.

**3. Keep attribution to AI tooling out of the working artifacts.** No
`Co-Authored-By` trailers naming an assistant, no session links, and no
generated-with footers in code, comments, or commit messages. This is a
deliberate difference from the private app repository, which keeps them.

The rule is about not dressing up routine authorship, so it yields where naming
the tool is the honest disclosure rather than a credit. A security review states
how it was produced, because that is what lets a reader weigh it; concealing it
would be the kind of overclaim `SECURITY.md` treats as a bug. Provenance of that
sort belongs in the document. Everything else should stay clean.

## Prose and comment style

Documentation here is read by people deciding whether to trust the
cryptography. It should read like it was written by someone who knows the
system, because it was.

- **No em dashes.** Not in docs, not in comments, not in commit messages, and
  not disguised as a spaced hyphen (` - `) doing the same job. Use a comma, a
  colon, a semicolon, parentheses, or two sentences.
- **No AI tells.** No "it's not X, it's Y" pivots, no rhetorical question
  followed by a fragment, no "here's the thing", no tricolon habit, no
  puffery verbs ("serves as", "stands as", "is a testament to"). Say what is
  true and let it be flat.
- **Not "load-bearing".** A borrowed metaphor that says only "this matters",
  which every sentence in a spec already claims. Name the consequence instead:
  what breaks, and for whom. The check:

  ```bash
  # EM is written as an escape so this file does not itself trip the check
  EM=$(printf '\u2014')
  grep -rn "$EM" --include="*.ts" --include="*.mts" --include="*.md" .
  grep -rnE "[a-z,] - [a-z]" README.md SECURITY.md docs/*.md
  grep -rnEi "not just .{1,40}\bbut\b|isn't just|here's the (thing|kicker)|serves as|testament to" .
  grep -rni "load.bearing" .
  ```

- **Comments explain why, not what.** The existing comments are long on
  purpose: they record the decision and the failure that produced it. Match
  that. A comment that restates the line below it is noise; a comment that
  says which bug this shape prevents is the reason anyone can safely change
  the file later.
- **Claim discipline.** Never write "military-grade", "unhackable", "zero
  knowledge", or any phrasing implying open source alone proves what a served
  app runs. `docs/threat-model.md` and `docs/verify.md` set the tone: volunteer
  the limit first. An overclaim in the docs is a bug, and `SECURITY.md` says so
  in as many words.

## Before you commit

```bash
npm run typecheck
npm test              # crypto, rewrap, media-range, interop
npm run test:vectors
```

## The published artifact

`npm run build` (tsup) emits `dist/`, and the `exports` map points there, not at
`src/`. This matters: the first cut of this package exported raw `.ts` and would
have broken every consumer that does not transpile `node_modules`, which
includes a default Next.js app.

`src/` is still shipped in the tarball on purpose. `dist/` is what runs; `src/`
is what someone reads when deciding whether to trust what they installed. The
build is unminified for the same reason.

`repository` in package.json is **required**, not decoration: npm verifies that
it matches the source named in the provenance attestation and rejects the
publish with a 422 if it does not. Removing it breaks releases.

Every subpath in `exports` needs a **`default`** condition alongside `import`.
Without it, only a pure-ESM resolver can see the subpath: anything reaching the
package through the CJS path, which includes `tsx` and therefore several test
runners, fails with `ERR_PACKAGE_PATH_NOT_EXPORTED` naming a subpath that is
visibly right there in package.json. Found on the first real consumption, in
0.1.0, fixed in 0.1.1.

Do not add `splitting: true` or merge the entries. Each subpath is its own entry
so that `aad`, `media-format` and `media-range` stay free of any crypto import,
which is what lets a service worker take the frame geometry without pulling in
libsodium. Verify after any build change:

```bash
grep -c libsodium dist/media-format.js   # must be 0
grep -c libsodium dist/sw-decrypt.js     # must be 0 (it uses @stablelib)
```

All four suites and the vectors must pass. CI runs exactly these, so a green
local run means a green build.

## Changing the library

- **New AAD label:** add to `src/aad.ts`, never reuse or rename an existing
  string. Add a vector for it in `test/generate-vectors.mts` if it seals a new
  kind of field.
- **New export:** add to the `exports` map in `package.json` and to the barrel
  in `src/index.ts`. Keep `aad`, `media-format`, and `media-range` free of any
  crypto-library import; a worker bundle depends on being able to take the
  geometry without the engine.
- **Touching `sw/decrypt.ts`:** it is decrypt-only on purpose. Do not add a
  sealer. A worker holds keys to reveal content a device is entitled to; it
  composes nothing, so a sealer there only widens what a compromised worker
  context could do.
- **Two implementations, one cipher.** libsodium seals, @stablelib opens in
  restricted runtimes. Any change to either side needs the interop suite and
  the vectors to still agree, in both directions.

## Relationship to the app

The Group Space application consumes this package; the app repository is
private and this one is public. Code flows **outward from here**: once the app
switches to re-export shims, `src/lib/crypto/` there becomes one-line
re-exports and this repo is the only place these modules are edited. Until
that lands, a change here may need mirroring, and the commit should say so.

Never copy anything inward from the app that has not been reviewed for
publication. This repo has no private history and should keep it that way.
