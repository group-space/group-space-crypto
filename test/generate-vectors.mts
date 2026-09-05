/**
 * Generate the committed test vectors. Run this ONCE per format version, never
 * casually.
 *
 *   npx tsx test/generate-vectors.mts > test/vectors/v1.json
 *
 * A vector that changes is a wire-format break: every stored blob in every
 * deployment would be orphaned. The interop suite treats the committed file as
 * the contract, so regenerating it is a deliberate act with a paper trail, not
 * a test fixture refresh.
 *
 * Two kinds of entry, because two kinds of primitive:
 *
 *  - **Deterministic seals** (field AEAD, the media container via
 *    `encryptBytesWithNonces`) record exact expected ciphertext. Both the seal
 *    and the open direction are pinned forever.
 *  - **Randomized seals** (Argon2id wraps, sealed-box grants) cannot promise
 *    bytes: salt and nonce are drawn fresh each time, and libsodium's sealed
 *    box has no seeded variant. For those the vector records ONE historical
 *    output, and pins the OPEN direction: this recorded wrap, under this
 *    password, must yield this secret, in any correct implementation, forever.
 */
import { getSodium } from "../src/sodium.ts";
import * as e2ee from "../src/e2ee.ts";

const sodium = await getSodium();
const b64 = (b: Uint8Array) => sodium.to_base64(b, sodium.base64_variants.ORIGINAL);

/** Deterministic pseudo-random bytes: value = (i * 7 + seed) % 251. */
function pattern(n: number, seed: number): Uint8Array {
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i++) out[i] = (i * 7 + seed) % 251;
  return out;
}

const FIELD_KEY = b64(pattern(32, 3));
const FILE_KEY = b64(pattern(32, 11));

// --- field AEAD, deterministic via decrypt-side check ------------------------
// encryptField draws its own nonce, so seal bytes vary; the vector records one
// output per AAD label and the suite pins that it OPENS to the plaintext.
const fields = [];
for (const [aad, plaintext] of [
  ["discussion.post.body", "Can someone cover carpool Friday? \u{1F697}"],
  ["event.title", "Spring picnic"],
  ["push.sender", "Alice Chen"],
  ["group.name", "Oak Lane Neighbors"],
  ["member.displayName", "Jordan Lee"],
  ["file.name", "budget-2026.pdf"],
  ["file.meta", "{\"mime\":\"application/pdf\"}"],
  ["folder.name", "Witness statements"],
  ["", "no context at all"],
] as const) {
  fields.push({ aad, plaintext, key: FIELD_KEY, sealed: await e2ee.encryptField(FIELD_KEY, plaintext, aad) });
}

// --- media container, fully deterministic ------------------------------------
// Fixed nonces make the seal a pure function, so the vector can state expected
// bytes. Small file = exact base64; the two larger ones pin a SHA-256 plus the
// container-size arithmetic, and the suite re-derives the ciphertext from the
// stated plaintext pattern before opening it with the OTHER implementation.
async function containerVector(name: string, size: number, seed: number) {
  const plain = pattern(size, seed);
  const frames = Math.max(1, Math.ceil(size / e2ee.MEDIA_CHUNK_SIZE));
  const nonces = Array.from({ length: frames }, (_, i) => pattern(24, 100 + i));
  const sealed = await e2ee.encryptBytesWithNonces(FILE_KEY, plain, "full", nonces);
  const digest = sodium.crypto_generichash(32, sealed, null);
  return {
    name,
    context: "full",
    fileKey: FILE_KEY,
    plaintext: { pattern: "byte[i] = (i*7 + seed) % 251", seed, length: size },
    nonces: { pattern: "nonce[f][i] = (i*7 + (100+f)) % 251", perFrame: 24 },
    frames,
    cipherLength: sealed.length,
    cipherBlake2b256: b64(digest),
    ciphertext: size <= 4096 ? b64(sealed) : undefined,
  };
}
const containers = [
  await containerVector("one short frame", 96, 17),
  await containerVector("exactly one full chunk", e2ee.MEDIA_CHUNK_SIZE, 29),
  await containerVector("a boundary-spanning file", e2ee.MEDIA_CHUNK_SIZE + 52, 41),
];

// --- randomized wraps: record one output, pin the open ----------------------
const PASSWORD = "correct horse battery staple";
// wrapSecret takes (secret BYTES, passphrase), in that order. The first cut of
// this generator had them swapped and produced a "vector" that Argon2id'd the
// secret as if it were a password; the suite caught it by failing to open.
const SECRET_BYTES = pattern(32, 53);
const SECRET = b64(SECRET_BYTES);
const wrapped = await e2ee.wrapSecret(SECRET_BYTES, PASSWORD);

// --- media manifest: randomized seal, pin the open --------------------------
// encryptField draws its own nonce, so this records one output and pins the
// OPEN direction: this sealed manifest, under this file key and this context,
// must yield these numbers in any correct implementation, forever.
const MANIFEST_FILE_KEY = b64(pattern(32, 29));
const MANIFEST_CONTEXT = "full";
const MANIFEST = { bytes: 655370, frames: 3 };
const sealedManifest = await e2ee.sealMediaManifest(
  MANIFEST_FILE_KEY,
  MANIFEST,
  MANIFEST_CONTEXT,
);

// --- purpose-bound wrap: randomized seal, pin the open ----------------------
// The compatibility half is already covered by `wrappedSecret` above, which was
// recorded before purposes existed and must keep opening with none given. This
// records the other half: a wrap bound to a slot, which must keep opening under
// that slot and no other.
const BOUND_PURPOSE = "member-vector";
const BOUND_SECRET_BYTES = pattern(32, 97);
const BOUND_SECRET = b64(BOUND_SECRET_BYTES);
const boundWrapped = await e2ee.wrapSecret(BOUND_SECRET_BYTES, PASSWORD, BOUND_PURPOSE);

const pair = await e2ee.generateKeyPair();
const GROUP_KEY = b64(pattern(32, 71));
const grant = await e2ee.grantGroupKey(GROUP_KEY, pair.publicKey);

process.stdout.write(
  JSON.stringify(
    {
      format: "v1",
      generatedBy: "test/generate-vectors.mts",
      note: "Regenerating this file is a wire-format event, not a fixture refresh.",
      fieldAead: fields,
      mediaContainer: { chunkSize: e2ee.MEDIA_CHUNK_SIZE, vectors: containers },
      mediaManifest: {
        fileKey: MANIFEST_FILE_KEY,
        context: MANIFEST_CONTEXT,
        manifest: MANIFEST,
        sealed: sealedManifest,
      },
      wrappedSecret: { password: PASSWORD, secret: SECRET, wrapped },
      wrappedSecretWithPurpose: {
        password: PASSWORD,
        purpose: BOUND_PURPOSE,
        secret: BOUND_SECRET,
        wrapped: boundWrapped,
      },
      sealedGrant: { groupKey: GROUP_KEY, recipient: pair, sealed: grant },
    },
    null,
    2,
  ) + "\n",
);
