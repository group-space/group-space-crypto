# Verifying what you are running

What this repo lets you check, in increasing strength — and, just as
important, what each step does **not** prove. The one claim we will never
make is that an open library, alone, proves what the hosted app serves you.
It does not, and anyone who says otherwise about their own product is
overreaching.

## Tier 0 — the design is open (this repo)

You can read every line that seals or opens content, run the suites, and
check the committed vectors:

```bash
npm ci
npm run typecheck
npm test            # the four suites: crypto, rewrap, media-range, interop
npm run test:vectors
```

`test/vectors/v1.json` pins the wire format: deterministic seals with exact
digests, and recorded randomized wraps that must open forever. An independent
implementation written from `docs/protocol.md` can be validated against the
same file without running any of our code.

**Proves:** the protocol is what the spec says, two implementations agree,
and the format cannot drift silently.
**Does not prove:** that any particular server is serving you this code.

## Tier 1 — the artifact is what CI built (on publish)

Releases are built and published from CI with npm provenance
(`npm publish --provenance`): the npm registry holds an attestation linking
the artifact to the exact public commit and workflow run, and each GitHub
release states the artifact's SHA-256.

```bash
npm audit signatures @group-space/crypto-core
```

**Proves:** supply-chain integrity — the package on npm came from this repo
at a stated commit, not from someone's laptop.
**Does not prove:** that the app you load in a browser contains it.

## Tier 2 — the served bundle (roadmap)

Web delivery is the honest gap: a served page could always serve something
else. Planned narrowing, in increasing strength: shipping the crypto core as
an integrity-pinned chunk whose hash can be compared against the published
artifact, and build arrangements that make the served crypto chunk
byte-reproducible from a tag. Until something here ships, treat "the served
app uses the audited core" as our statement, not your verification.

## Disclosure

Found something? See `SECURITY.md` in the repo root — we want the report,
including reports that the docs claim more than the code delivers.
