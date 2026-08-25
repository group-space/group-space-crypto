/**
 * Self-test for the encrypted-media range arithmetic (src/lib/crypto/media-range.ts).
 *
 *   npm run test:media-range
 *
 * The headline test is a PROPERTY test, not a set of examples: encrypt real
 * blobs, then for a spread of ranges walk the whole path a service worker would
 * walk — map the range to frames, slice the ciphertext, decrypt those chunks,
 * concatenate, slice — and assert the bytes equal the plaintext slice. Off by
 * one frame and the player receives plausible-looking garbage rather than an
 * error, which is exactly the class of bug that survives example-based tests.
 */
import * as e2ee from "../src/e2ee.ts";
import {
  chunkRangeFor,
  cipherLength,
  plaintextLength,
  parseRangeHeader,
  FULL_FRAME_BYTES,
  FRAME_OVERHEAD_BYTES,
} from "../src/media-range.ts";
// Spike note: the original selftest also covers presigned-expiry.ts, which is
// URL-freshness plumbing rather than crypto and stays in the app; that section
// is omitted here. Everything else is verbatim.

const CHUNK = e2ee.MEDIA_CHUNK_SIZE;

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

const fileKey = await e2ee.generateFileKey();

console.log("length arithmetic:");
// Round-trip every interesting size class against the real encryptor, so these
// are not two implementations of the same guess agreeing with each other.
for (const size of [0, 1, 40, CHUNK - 1, CHUNK, CHUNK + 1, CHUNK * 3, CHUNK * 3 + 7]) {
  const enc = await e2ee.encryptBytes(fileKey, new Uint8Array(size), "full");
  ok(cipherLength(size) === enc.length, `cipherLength(${size}) matches the encryptor`);
  ok(plaintextLength(enc.length) === size, `plaintextLength() recovers ${size}`);
}
ok(plaintextLength(0) === null, "a zero-length object is not a container");
ok(plaintextLength(FRAME_OVERHEAD_BYTES - 1) === null, "a too-short object is rejected");
ok(plaintextLength(FULL_FRAME_BYTES + 5) === null, "a trailing frame below overhead is rejected");

console.log("\nrange to chunk mapping:");
const total = CHUNK * 3 + 100;
ok(chunkRangeFor(0, 0, total)?.firstChunk === 0, "byte 0 is in chunk 0");
ok(chunkRangeFor(CHUNK, CHUNK, total)?.firstChunk === 1, "the first byte of chunk 1 maps to chunk 1");
ok(chunkRangeFor(CHUNK - 1, CHUNK, total)?.lastChunk === 1, "a range straddling a boundary spans two chunks");
ok(chunkRangeFor(0, total - 1, total)?.lastChunk === 3, "the whole file spans every chunk");
ok(
  chunkRangeFor(0, total - 1, total)?.cipherEnd === cipherLength(total) - 1,
  "the last frame is clamped to the container, not rounded up to a full frame",
);
ok(chunkRangeFor(-1, 5, total) === null, "a negative start is rejected");
ok(chunkRangeFor(total, total, total) === null, "a start past the end is rejected");
ok(chunkRangeFor(5, 4, total) === null, "an inverted range is rejected");
ok(chunkRangeFor(0, total * 2, total)?.sliceLength === total, "an over-long end is clamped");

console.log("\nRange header parsing:");
ok(parseRangeHeader("bytes=0-", 1000)?.end === 999, "open-ended range runs to the end");
ok(parseRangeHeader("bytes=10-20", 1000)?.start === 10, "explicit range keeps its start");
ok(parseRangeHeader("bytes=10-20", 1000)?.end === 20, "explicit range keeps its end");
ok(parseRangeHeader("bytes=-100", 1000)?.start === 900, "suffix range reads the last N bytes");
ok(parseRangeHeader("bytes=-5000", 1000)?.start === 0, "an over-long suffix is the whole file");
ok(parseRangeHeader("bytes=990-5000", 1000)?.end === 999, "an over-long end is clamped");
ok(parseRangeHeader(null, 1000) === null, "no header means no range");
ok(parseRangeHeader("bytes=1000-", 1000) === null, "a start at EOF is unsatisfiable");
ok(parseRangeHeader("bytes=0-10,20-30", 1000) === null, "multi-range is refused, not half-served");
ok(parseRangeHeader("items=0-10", 1000) === null, "a non-bytes unit is refused");

console.log("\nend-to-end: serve a range the way a service worker would");
/** Exactly what the SW will do, so the test exercises the real path. */
async function serveRange(
  cipher: Uint8Array,
  start: number,
  end: number,
  plainTotal: number,
): Promise<Uint8Array> {
  const r = chunkRangeFor(start, end, plainTotal);
  if (!r) throw new Error("unsatisfiable");
  // The byte range a Range request would return.
  const slice = cipher.subarray(r.cipherStart, r.cipherEnd + 1);
  // Split into frames and decrypt each under its own chunk index. Only the last
  // frame of the CONTAINER may be short — a mid-file frame never is.
  const parts: Uint8Array[] = [];
  let offset = 0;
  for (let i = r.firstChunk; i <= r.lastChunk; i++) {
    const frameLen = Math.min(FULL_FRAME_BYTES, slice.length - offset);
    const frame = slice.subarray(offset, offset + frameLen);
    // decryptBytes over a single frame with the right AAD index is the same
    // operation the SW performs per chunk.
    parts.push(await decryptOneFrame(frame, i));
    offset += frameLen;
  }
  const joined = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    joined.set(p, o);
    o += p.length;
  }
  return joined.subarray(r.sliceOffset, r.sliceOffset + r.sliceLength);
}

async function decryptOneFrame(frame: Uint8Array, index: number): Promise<Uint8Array> {
  const sodium = (await import("../src/sodium.ts")).getSodium;
  const s = await sodium();
  const nonce = frame.subarray(0, 24);
  const ct = frame.subarray(24);
  return s.crypto_aead_xchacha20poly1305_ietf_decrypt(
    null,
    ct,
    s.from_string(`full:${index}`),
    nonce,
    s.from_base64(fileKey, s.base64_variants.ORIGINAL),
  );
}

function equal(a: Uint8Array, b: Uint8Array): boolean {
  return Buffer.from(a).equals(Buffer.from(b));
}

for (const size of [1, CHUNK - 1, CHUNK, CHUNK + 1, CHUNK * 2 + 123, CHUNK * 5 + 4096]) {
  const plain = Uint8Array.from({ length: size }, (_, i) => (i * 131 + 7) % 256);
  const cipher = await e2ee.encryptBytes(fileKey, plain, "full");
  // A spread that deliberately includes both boundaries, unaligned interiors,
  // single bytes, and the tail — the ranges a seeking player actually emits.
  const ranges: Array<[number, number]> = [
    [0, 0],
    [0, Math.min(1023, size - 1)],
    [Math.max(0, size - 1), size - 1],
    [Math.floor(size / 2), size - 1],
    [Math.max(0, CHUNK - 5), Math.min(size - 1, CHUNK + 5)],
    [0, size - 1],
  ];
  let allOk = true;
  for (const [s, e] of ranges) {
    if (s > e || s >= size) continue;
    const got = await serveRange(cipher, s, e, size);
    if (!equal(got, plain.subarray(s, e + 1))) {
      allOk = false;
      console.log(`      (size=${size} range=${s}-${e} mismatch)`);
    }
  }
  ok(allOk, `every probed range decrypts to the right bytes (size ${size})`);
}

// Random ranges, because hand-picked cases test what the author thought of.
{
  const size = CHUNK * 4 + 9999;
  const plain = Uint8Array.from({ length: size }, (_, i) => (i * 37) % 256);
  const cipher = await e2ee.encryptBytes(fileKey, plain, "full");
  let allOk = true;
  let seed = 12345;
  const rnd = (n: number) => ((seed = (seed * 1103515245 + 12345) & 0x7fffffff) % n);
  for (let i = 0; i < 200; i++) {
    const s = rnd(size);
    const e = Math.min(size - 1, s + rnd(CHUNK * 2));
    const got = await serveRange(cipher, s, e, size);
    if (!equal(got, plain.subarray(s, e + 1))) {
      allOk = false;
      console.log(`      (random range ${s}-${e} mismatch)`);
      break;
    }
  }
  ok(allOk, "200 pseudo-random ranges all decrypt to the right bytes");
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
