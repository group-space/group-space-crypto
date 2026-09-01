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

/**
 * For assertions whose failure mode is a THROW rather than a false. An uncaught
 * throw ends the run where it happens and takes every later section with it, so
 * a single broken AAD hid half this suite.
 */
async function opens(msg: string, f: () => Promise<boolean>) {
  try {
    ok(await f(), msg);
  } catch (e) {
    ok(false, `${msg} (threw: ${e instanceof Error ? e.message : String(e)})`);
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

console.log("wrap purpose (the slot a wrapped blob belongs in):");
// The case the purpose exists for: one password, several membership keys. Two
// blobs with no purpose are interchangeable, so a swap unlocks the wrong key in
// the right slot and the failure surfaces somewhere else entirely.
const memberA = await e2ee.generateKeyPair();
const memberB = await e2ee.generateKeyPair();
const bareA = await e2ee.wrapPrivateKey(memberA.privateKey, "one password", undefined);
const bareB = await e2ee.wrapPrivateKey(memberB.privateKey, "one password", undefined);
ok(
  (await e2ee.unwrapPrivateKey(bareB, "one password")) === memberB.privateKey &&
    (await e2ee.unwrapPrivateKey(bareA, "one password")) === memberA.privateKey,
  "without a purpose, either blob opens in either slot",
);

const boundA = await e2ee.wrapPrivateKey(memberA.privateKey, "one password", "member-A");
const boundB = await e2ee.wrapPrivateKey(memberB.privateKey, "one password", "member-B");
ok(
  (await e2ee.unwrapPrivateKey(boundA, "one password", "member-A")) === memberA.privateKey,
  "a purpose-bound key opens in its own slot",
);
await throws(
  () => e2ee.unwrapPrivateKey(boundB, "one password", "member-A"),
  "B's blob does not open in A's slot",
);
await throws(
  () => e2ee.unwrapPrivateKey(boundA, "one password", "member-B"),
  "A's blob does not open in B's slot",
);

// Both directions of the migration boundary, because a caller upgrading old
// blobs depends on each failing rather than quietly succeeding.
await throws(
  () => e2ee.unwrapPrivateKey(boundA, "one password"),
  "a purpose-bound blob does not open with no purpose given",
);
await throws(
  () => e2ee.unwrapPrivateKey(bareA, "one password", "member-A"),
  "a blob wrapped with no purpose does not open under one",
);

// Omitting the argument has to behave exactly as it did before the argument
// existed, or every blob wrapped up to now stops opening. The committed vectors
// carry the real historical case; this pins the same property at the API.
const explicitNone = await e2ee.wrapSecret(secret, "correct horse");
ok(
  Buffer.from(await e2ee.unwrapSecret(explicitNone, "correct horse")).equals(Buffer.from(secret)),
  "omitting the purpose still wraps and opens",
);

// The purpose is a context label, not a second password. A wrong passphrase
// fails whether or not the slot is right.
await throws(
  () => e2ee.unwrapPrivateKey(boundA, "wrong password", "member-A"),
  "the right slot does not rescue a wrong passphrase",
);

// null counts as absent, so a caller reading a nullable id from a record gets
// the old behaviour instead of a blob sealed under the literal "null" that
// never opens again once the id is real.
const nulled = await e2ee.wrapPrivateKey(memberA.privateKey, "one password", null);
ok(
  (await e2ee.unwrapPrivateKey(nulled, "one password")) === memberA.privateKey,
  "a null purpose wraps as absent, and opens with none given",
);
ok(
  (await e2ee.unwrapPrivateKey(bareA, "one password", null)) === memberA.privateKey,
  "and a null purpose opens a blob wrapped with none",
);
await throws(
  () => e2ee.wrapSecret(secret, "one password", ""),
  "an empty purpose is refused rather than quietly treated as absent",
);
// A colon separates the label from the purpose, so one inside the purpose makes
// the composition ambiguous: ("a:b","c") and ("a","b:c") would collide.
await throws(
  () => e2ee.wrapSecret(secret, "one password", "member:A"),
  "a purpose containing the separator is refused",
);

// The purpose is used verbatim. Nothing normalizes it, and a later tidy-up
// that trimmed or lowercased it would change which blobs open.
const spaced = await e2ee.wrapPrivateKey(memberA.privateKey, "one password", " member-A ");
await throws(
  () => e2ee.unwrapPrivateKey(spaced, "one password", "member-A"),
  "a purpose is not trimmed",
);
const cased = await e2ee.wrapPrivateKey(memberA.privateKey, "one password", "Member-A");
await throws(
  () => e2ee.unwrapPrivateKey(cased, "one password", "member-A"),
  "a purpose is not lowercased",
);

// The group recovery wrap takes one too, so a recovery blob is bound to the
// group it belongs to rather than being a free-floating wrap of a Group Key.
const recoveredGk = await e2ee.generateGroupKey();
const recoveryCode = await e2ee.generateRecoveryCode();
const boundRecovery = await e2ee.wrapGroupKeyForRecovery(recoveredGk, recoveryCode, "group-1");
ok(
  (await e2ee.openGroupKeyWithRecovery(boundRecovery, recoveryCode, "group-1")) === recoveredGk,
  "a recovery wrap opens for its own group",
);
await throws(
  () => e2ee.openGroupKeyWithRecovery(boundRecovery, recoveryCode, "group-2"),
  "a recovery wrap does not open for another group",
);

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
await opens("the manifest roundtrips under the file key", async () => {
  const opened = await e2ee.openMediaManifest(fileKey, sealedManifest, "full");
  return opened.frames === bigManifest.frames && opened.bytes === bigManifest.bytes;
});
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
await opens("without a manifest a truncated container still opens, and returns less", async () => {
  const short = await e2ee.decryptBytes(fileKey, truncated, "full");
  return short.length < big.length;
});
await throws(
  () => e2ee.decryptBytes(fileKey, truncated, "full", bigManifest),
  "with the manifest, a container truncated at a frame boundary is rejected",
);
await opens("a complete container passes the manifest check", async () =>
  Buffer.from(await e2ee.decryptBytes(fileKey, fullEnc, "full", bigManifest)).equals(
    Buffer.from(big),
  ));
// A manifest describing a different file must not wave this one through.
await throws(
  () => e2ee.decryptBytes(fileKey, fullEnc, "full", { bytes: big.length, frames: 4 }),
  "a manifest claiming more frames than the container holds is rejected",
);
await throws(
  () => e2ee.decryptBytes(fileKey, fullEnc, "full", { bytes: big.length - 1, frames: 3 }),
  "a manifest claiming a different length is rejected",
);

// Every manifest assertion above uses one file size. The sizes that actually
// break an off-by-one are the boundaries, and a single-frame container is the
// common case: every thumbnail is one.
const CHUNK = e2ee.MEDIA_CHUNK_SIZE;
for (const [size, label] of [
  [0, "empty"],
  [1, "one byte"],
  [CHUNK - 1, "one under a chunk"],
  [CHUNK, "exactly one chunk"],
  [CHUNK + 1, "one over a chunk"],
  [2 * CHUNK, "exactly two chunks"],
] as [number, string][]) {
  const payload = Uint8Array.from({ length: size }, (_, i) => (i * 13) % 251);
  const manifest = e2ee.mediaManifestFor(payload);
  const container = await e2ee.encryptBytes(fileKey, payload, "full");

  // Nothing previously tied the manifest's frame count to the number of frames
  // the encoder actually emits. A container is frames of FULL_FRAME_BYTES with
  // a shorter trailing one, so the count is derivable from its length.
  const actualFrames = Math.max(1, Math.ceil(container.length / FULL_FRAME_BYTES));
  ok(manifest.frames === actualFrames, `${label}: manifest frame count matches the container`);

  const sealed = await e2ee.sealMediaManifest(fileKey, manifest, "full");
  await opens(`${label}: manifest seals and opens`, async () => {
    const back = await e2ee.openMediaManifest(fileKey, sealed, "full");
    return back.bytes === manifest.bytes && back.frames === manifest.frames;
  });
  await opens(`${label}: the complete container passes its own manifest`, async () =>
    (await e2ee.decryptBytes(fileKey, container, "full", manifest)).length === size);

  // Every size, including the single-frame ones, must reject a manifest that
  // disagrees with the container. Without this the check can be skipped for
  // small media and only the multi-frame sizes would notice.
  await throws(
    () => e2ee.decryptBytes(fileKey, container, "full", { bytes: size + 1, frames: manifest.frames }),
    `${label}: a manifest claiming one byte more is rejected`,
  );

  // Drop the last frame. A one-frame container has nothing left to check, so
  // the assertion there is that the manifest still accepts the whole thing.
  if (manifest.frames > 1) {
    const cut = container.subarray(0, (manifest.frames - 1) * FULL_FRAME_BYTES);
    await throws(
      () => e2ee.decryptBytes(fileKey, cut, "full", manifest),
      `${label}: a container missing its last frame is rejected`,
    );
  }
}

// The seal side never had to use its context argument: every seal above is
// "full", so only the open side was ever varied.
const thumbManifest = e2ee.mediaManifestFor(big);
const thumbSealed = await e2ee.sealMediaManifest(fileKey, thumbManifest, "thumb");
await opens("a manifest sealed for thumb opens for thumb", async () =>
  (await e2ee.openMediaManifest(fileKey, thumbSealed, "thumb")).bytes === big.length);
await throws(
  () => e2ee.openMediaManifest(fileKey, thumbSealed, "full"),
  "a manifest sealed for thumb does not open for full",
);

// The sealed plaintext is a wire shape a second implementation has to
// reproduce, so pin it rather than only round-tripping it.
await opens("the sealed manifest is exactly {bytes,frames} in that order", async () =>
  (await e2ee.decryptField(fileKey, thumbSealed, "media.manifest:thumb")) ===
    JSON.stringify({ bytes: big.length, frames: 3 }));

// mediaManifestForLength is what the streaming writers can call, so it has to
// agree with the byte-array form everywhere.
ok(
  ([0, 1, CHUNK, CHUNK + 1, 5 * CHUNK] as number[]).every((n) => {
    const a = e2ee.mediaManifestForLength(n);
    return a.bytes === n && a.frames === e2ee.mediaManifestFor(new Uint8Array(n)).frames;
  }),
  "mediaManifestForLength agrees with mediaManifestFor at every boundary",
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
for (const [bytes, label] of [
  [1.5, "a fractional length"],
  [Number.NaN, "NaN as a length"],
  [Number.POSITIVE_INFINITY, "an infinite length"],
  ["10", "a length that is a string"],
] as [unknown, string][]) {
  await throws(
    async () => e2ee.openMediaManifest(fileKey, await sealRawManifest({ bytes, frames: 1 }), "full"),
    `a validly sealed manifest claiming ${label} is rejected`,
  );
}
// frames is derivable from bytes, so a figure that disagrees with itself is
// rejected before it can reject a container that was written correctly.
await throws(
  async () => e2ee.openMediaManifest(fileKey, await sealRawManifest({ bytes: 10, frames: 5000 }), "full"),
  "a validly sealed manifest whose frames disagree with its bytes is rejected",
);
await throws(
  async () => e2ee.openMediaManifest(fileKey, await sealRawManifest("not an object"), "full"),
  "a validly sealed manifest that is not an object is rejected",
);
await throws(
  async () => e2ee.openMediaManifest(fileKey, await e2ee.encryptField(fileKey, "{oops", "media.manifest:full"), "full"),
  "a validly sealed manifest that is not JSON is rejected",
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
ok(/^[A-Z0-9]{5}(-[A-Z0-9]{5}){3}$/.test(code), `code format is 4x5 groups (${code})`);
ok(code.replace(/-/g, "").length === 20, `20 characters, ~100 bits (${code.length} with dashes)`);
ok(!/[ILOU]/.test(code), "no I, L, O or U, which are the characters people mis-transcribe");
const rWrap = await e2ee.wrapGroupKeyForRecovery(gk, code);
ok(
  (await e2ee.openGroupKeyWithRecovery(rWrap, code.toLowerCase().replace(/-/g, " "))) === gk,
  "recovers the Group Key even with re-typed case/spacing",
);
await throws(() => e2ee.openGroupKeyWithRecovery(rWrap, "WRONG-CODE"), "wrong recovery code throws");

// A code is only ever a passphrase into wrapSecret, so shortening what we MINT
// must not change what we can OPEN. Codes issued before this change are printed,
// saved in password managers, and are the only way back into groups created
// years earlier. Driven with a real 8x5 code rather than trusted.
const legacyCode = "TMFZJ-RV090-QCN07-Z7A4X-8H3KP-QW2NE-RT6YB-XC4VD";
const legacyWrap = await e2ee.wrapGroupKeyForRecovery(gk, legacyCode);
ok(
  (await e2ee.openGroupKeyWithRecovery(legacyWrap, legacyCode)) === gk,
  "a legacy 8x5 code still wraps and opens",
);
ok(
  (await e2ee.openGroupKeyWithRecovery(legacyWrap, legacyCode.toLowerCase())) === gk,
  "and still tolerates re-typed case",
);

// Uniqueness, cheaply: 200 draws with no collision. A generator that lost its
// entropy source and returned a constant would still satisfy the format check
// above, and would hand every group the same recovery code.
const seen = new Set<string>();
for (let i = 0; i < 200; i++) seen.add(await e2ee.generateRecoveryCode());
ok(seen.size === 200, `200 codes are 200 distinct codes (${seen.size})`);

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
