/**
 * Self-test for the E2EE crypto core (src/lib/crypto/e2ee.ts).
 *
 * Run with:  npm run test:crypto
 *
 * Exercises every primitive plus the negative cases that actually matter for a
 * crypto module: wrong password/key, context (AAD) swaps, tampering, and chunk
 * reordering must all be *rejected*, not silently accepted. Exits non-zero on any
 * failure so it can gate CI later.
 */
import * as e2ee from "../src/e2ee.ts";
import { FULL_FRAME_BYTES } from "../src/media-format.ts";
import { MEDIA_MANIFEST_AAD } from "../src/aad.ts";

let pass = 0;
let fail = 0;

function ok(cond: boolean, msg: string) {
  if (cond) {
    pass++;
    console.log("  ✓", msg);
  } else {
    fail++;
    console.log("  ✗ FAIL:", msg);
  }
}

async function throws(fn: () => Promise<unknown>, msg: string) {
  try {
    await fn();
    fail++;
    console.log("  ✗ FAIL (did not throw):", msg);
  } catch {
    pass++;
    console.log("  ✓", msg);
  }
}

console.log("wrapSecret / unwrapSecret:");
const secret = await e2ee.randomBytes(32);
const wrapped = await e2ee.wrapSecret(secret, "correct horse");
ok(
  Buffer.from(await e2ee.unwrapSecret(wrapped, "correct horse")).equals(Buffer.from(secret)),
  "roundtrip recovers the secret",
);
await throws(() => e2ee.unwrapSecret(wrapped, "wrong password"), "wrong passphrase throws");

console.log("member key pair + password wrap:");
const kp = await e2ee.generateKeyPair();
const wpk = await e2ee.wrapPrivateKey(kp.privateKey, "hunter2");
ok((await e2ee.unwrapPrivateKey(wpk, "hunter2")) === kp.privateKey, "private key roundtrips via password");
await throws(() => e2ee.unwrapPrivateKey(wpk, "nope"), "wrong password cannot unwrap private key");

console.log("group key granting (sealed boxes):");
const gk = await e2ee.generateGroupKey();
const grant = await e2ee.grantGroupKey(gk, kp.publicKey);
ok((await e2ee.openGroupKeyGrant(grant, kp)) === gk, "recipient opens the grant to the same Group Key");
const other = await e2ee.generateKeyPair();
await throws(() => e2ee.openGroupKeyGrant(grant, other), "a different key pair cannot open the grant");

console.log("field encryption (AEAD + context binding):");
const field = await e2ee.encryptField(gk, "Dana's phone: 555-1234", "member:42:phone");
ok(
  (await e2ee.decryptField(gk, field, "member:42:phone")) === "Dana's phone: 555-1234",
  "field roundtrips",
);
await throws(() => e2ee.decryptField(gk, field, "member:99:phone"), "wrong AAD (context swap) is rejected");
await throws(
  () => e2ee.decryptField(gk, { ...field, ciphertext: field.ciphertext.slice(0, -4) + "AAAA" }, "member:42:phone"),
  "tampered ciphertext is rejected",
);

console.log("per-file keys:");
const fileKey = await e2ee.generateFileKey();
ok(
  (await e2ee.unwrapFileKey(await e2ee.wrapFileKey(fileKey, gk), gk)) === fileKey,
  "file key wraps/unwraps under the Group Key",
);

console.log("whole-file byte encryption (encryptBytes / decryptBytes):");
async function roundtrips(bytes: Uint8Array, ctx: string, label: string) {
  const enc = await e2ee.encryptBytes(fileKey, bytes, ctx);
  const dec = await e2ee.decryptBytes(fileKey, enc, ctx);
  ok(Buffer.from(dec).equals(Buffer.from(bytes)), label);
}
await roundtrips(new Uint8Array(0), "full", "empty file roundtrips");
await roundtrips(new Uint8Array([1, 2, 3, 4, 5]), "full", "tiny file roundtrips");
// Exactly one chunk, and exactly on the chunk boundary (no partial trailer).
await roundtrips(
  Uint8Array.from({ length: e2ee.MEDIA_CHUNK_SIZE }, (_, i) => i % 251),
  "full",
  "single full-chunk file roundtrips",
);
// Multi-chunk with a partial final chunk (2.5 chunks).
const big = Uint8Array.from(
  { length: Math.floor(e2ee.MEDIA_CHUNK_SIZE * 2.5) },
  (_, i) => (i * 7) % 256,
);
await roundtrips(big, "full", "multi-chunk file (2.5 chunks) roundtrips");
// The same file key protects "full" and "thumb"; neither opens under the other.
const fullEnc = await e2ee.encryptBytes(fileKey, big, "full");
await throws(
  () => e2ee.decryptBytes(fileKey, fullEnc, "thumb"),
  "wrong context (full vs thumb) is rejected",
);
// A different file key can't read it.
const otherFileKey = await e2ee.generateFileKey();
await throws(
  () => e2ee.decryptBytes(otherFileKey, fullEnc, "full"),
  "a different file key cannot decrypt",
);
// Tampering with a ciphertext byte is rejected.
const tampered = fullEnc.slice();
tampered[tampered.length - 1] ^= 0x01;
await throws(
  () => e2ee.decryptBytes(fileKey, tampered, "full"),
  "tampered media bytes are rejected",
);

console.log("container completeness (sealed length manifest):");
// `big` is 2.5 chunks, so three frames, the shortest container where dropping a
// whole frame still leaves a valid one behind. That is the case the frames
// cannot catch on their own.
const bigManifest = e2ee.mediaManifestFor(big);
ok(bigManifest.frames === 3, "a 2.5-chunk file is three frames");
ok(bigManifest.bytes === big.length, "the manifest records the plaintext length");
ok(
  e2ee.mediaManifestFor(new Uint8Array(0)).frames === 1,
  "an empty file is still one frame",
);

const sealedManifest = await e2ee.sealMediaManifest(fileKey, bigManifest, "full");
const opened = await e2ee.openMediaManifest(fileKey, sealedManifest, "full");
ok(
  opened.frames === bigManifest.frames && opened.bytes === bigManifest.bytes,
  "the manifest roundtrips under the file key",
);
await throws(
  () => e2ee.openMediaManifest(fileKey, sealedManifest, "thumb"),
  "a manifest sealed for one context does not open for another",
);
const bentManifest = {
  ...sealedManifest,
  ciphertext: sealedManifest.ciphertext.slice(0, -4) + "AAAA",
};
await throws(
  () => e2ee.openMediaManifest(fileKey, bentManifest, "full"),
  "a tampered manifest is rejected",
);

// The finding itself. Cut the container at a frame boundary and it stays
// internally valid: every remaining frame opens, and the shortfall is invisible.
const truncated = fullEnc.subarray(0, 2 * FULL_FRAME_BYTES);
const short = await e2ee.decryptBytes(fileKey, truncated, "full");
ok(
  short.length < big.length,
  "without a manifest a truncated container still opens, and returns less",
);
await throws(
  () => e2ee.decryptBytes(fileKey, truncated, "full", bigManifest),
  "with the manifest, a container truncated at a frame boundary is rejected",
);
const whole = await e2ee.decryptBytes(fileKey, fullEnc, "full", bigManifest);
ok(
  Buffer.from(whole).equals(Buffer.from(big)),
  "a complete container passes the manifest check",
);
// A manifest describing a different file must not wave this one through.
await throws(
  () => e2ee.decryptBytes(fileKey, fullEnc, "full", { bytes: big.length, frames: 4 }),
  "a manifest claiming more frames than the container holds is rejected",
);
await throws(
  () => e2ee.decryptBytes(fileKey, fullEnc, "full", { bytes: big.length - 1, frames: 3 }),
  "a manifest claiming a different length is rejected",
);

// A manifest that opens is not the same as a manifest that means anything. The
// seal proves who wrote it, not that the numbers inside are numbers. Anyone
// holding the file key can seal nonsense, and a zero frame count read as
// authoritative would wave through an empty container.
async function sealRawManifest(value: unknown) {
  return e2ee.encryptField(fileKey, JSON.stringify(value), `${MEDIA_MANIFEST_AAD}:full`);
}
await throws(
  async () => e2ee.openMediaManifest(fileKey, await sealRawManifest({ bytes: 10, frames: 0 }), "full"),
  "a validly sealed manifest claiming zero frames is rejected",
);
await throws(
  async () => e2ee.openMediaManifest(fileKey, await sealRawManifest({ bytes: -1, frames: 3 }), "full"),
  "a validly sealed manifest claiming a negative length is rejected",
);
await throws(
  async () => e2ee.openMediaManifest(fileKey, await sealRawManifest({ bytes: 10, frames: 1.5 }), "full"),
  "a validly sealed manifest claiming a fractional frame count is rejected",
);

console.log("streaming media encryption (encryptBlobFrames / encryptBlobToBlob):");
/**
 * The property that matters is INTERCHANGEABILITY: the streaming path must emit
 * the same container the one-shot path does, or the reader, the range fetcher,
 * and the export all break on anything uploaded after it ships. Nonces are
 * random, so "identical" means same frame count, same total length, and
 * decryptable by the existing decryptBytes, not equal bytes.
 */
async function streamMatchesOneShot(size: number, label: string) {
  const bytes = Uint8Array.from({ length: size }, (_, i) => (i * 31) % 256);
  const oneShot = await e2ee.encryptBytes(fileKey, bytes, "full");
  const streamed = await e2ee.encryptBlobToBlob(fileKey, new Blob([bytes]), "full");
  const streamedBytes = new Uint8Array(await streamed.arrayBuffer());
  ok(
    streamedBytes.length === oneShot.length,
    `${label}: container length matches encryptBytes (${oneShot.length} bytes)`,
  );
  const dec = await e2ee.decryptBytes(fileKey, streamedBytes, "full");
  ok(Buffer.from(dec).equals(Buffer.from(bytes)), `${label}: decryptBytes reads it back`);
}
// The empty case is the easy one to get wrong: chunkCount is max(1, ceil(0/N)),
// so zero bytes must still produce exactly one (empty) frame, not zero frames.
await streamMatchesOneShot(0, "empty");
await streamMatchesOneShot(5, "tiny");
await streamMatchesOneShot(e2ee.MEDIA_CHUNK_SIZE, "exact chunk boundary");
await streamMatchesOneShot(e2ee.MEDIA_CHUNK_SIZE + 1, "one byte past a boundary");
await streamMatchesOneShot(Math.floor(e2ee.MEDIA_CHUNK_SIZE * 2.5), "partial trailing chunk");
// Past FRAME_FOLD_COUNT (64 frames), so the fold path is exercised rather than
// only the single-batch tail.
await streamMatchesOneShot(e2ee.MEDIA_CHUNK_SIZE * 70, "beyond the fold threshold");

// One-shot output must also be readable by whatever reads streamed output, and
// vice versa. The two directions are what "no migration" actually means.
const streamedFull = await e2ee.encryptBlobToBlob(fileKey, new Blob([big]), "full");
const streamedFullBytes = new Uint8Array(await streamedFull.arrayBuffer());
await throws(
  () => e2ee.decryptBytes(fileKey, streamedFullBytes, "thumb"),
  "streamed output still rejects a context swap",
);
await throws(
  () => e2ee.decryptBytes(otherFileKey, streamedFullBytes, "full"),
  "streamed output still rejects a different file key",
);
const streamedTampered = streamedFullBytes.slice();
streamedTampered[streamedTampered.length - 1] ^= 0x01;
await throws(
  () => e2ee.decryptBytes(fileKey, streamedTampered, "full"),
  "streamed output still rejects tampering",
);

// Frame boundaries must land where the decoder expects, or a reader that splits
// by FULL_FRAME_BYTES desynchronises on the second chunk.
const frames: number[] = [];
for await (const f of e2ee.encryptBlobFrames(
  fileKey,
  new Blob([new Uint8Array(e2ee.MEDIA_CHUNK_SIZE * 2 + 10)]),
  "full",
)) {
  frames.push(f.length);
}
ok(frames.length === 3, "frame count is ceil(size / chunk) (3 for 2 chunks + 10 bytes)");
ok(
  frames[0] === frames[1] && frames[2] < frames[0],
  "full frames are uniform and the trailing frame is shorter",
);

// Progress must report plaintext bytes and finish exactly at the file size,
// a bar that stops at 97% or overshoots is worse than no bar.
let lastProgress = 0;
await e2ee.encryptBlobToBlob(
  fileKey,
  new Blob([new Uint8Array(Math.floor(e2ee.MEDIA_CHUNK_SIZE * 3.25))]),
  "full",
  (n) => {
    lastProgress = n;
  },
);
ok(
  lastProgress === Math.floor(e2ee.MEDIA_CHUNK_SIZE * 3.25),
  "progress ends exactly at the plaintext size",
);

console.log("recovery code:");
const code = await e2ee.generateRecoveryCode();
ok(/^[A-Z0-9]{5}(-[A-Z0-9]{5}){7}$/.test(code), `code format is 8x5 groups (${code})`);
const rWrap = await e2ee.wrapGroupKeyForRecovery(gk, code);
ok(
  (await e2ee.openGroupKeyWithRecovery(rWrap, code.toLowerCase().replace(/-/g, " "))) === gk,
  "recovers the Group Key even with re-typed case/spacing",
);
await throws(() => e2ee.openGroupKeyWithRecovery(rWrap, "WRONG-CODE"), "wrong recovery code throws");

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
