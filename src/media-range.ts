import {
  MEDIA_CHUNK_SIZE,
  FRAME_OVERHEAD_BYTES,
  FULL_FRAME_BYTES,
} from "./media-format";

export { MEDIA_CHUNK_SIZE, FRAME_OVERHEAD_BYTES, FULL_FRAME_BYTES };

/**
 * Range arithmetic for seeking inside encrypted media (#390).
 *
 * Video is currently played by downloading the whole ciphertext, decrypting all
 * of it into memory, and handing a Blob URL to `<video>`. With no size cap on
 * video (`storage.ts` `skipSizeLimit`, #192; paid tiers set `maxVideoSeconds:
 * null`) that means a large clip cannot start until it has fully arrived,
 * cannot be seeked, and will not survive a dropped connection.
 *
 * The container was built for better than that. `e2ee.ts` says so:
 *
 *   > the client fetches a byte range, splits the nonce, and decrypts,
 *   > enabling seek/streaming without the server ever seeing plaintext
 *
 * Every chunk is sealed independently with its own nonce and its index bound as
 * AAD, and every frame but the last is exactly {@link FULL_FRAME_BYTES}. So the
 * map from a plaintext byte range to the ciphertext frames covering it is exact
 * arithmetic: no index, no manifest, no format change.
 *
 * This module is that arithmetic, and nothing else. It is pure and free of
 * crypto, DOM and network on purpose: it is the part that is easy to get subtly
 * wrong (off by one frame and the player gets plausible garbage) and the part
 * that is cheap to test exhaustively.
 */


/**
 * Plaintext length of a container, from its ciphertext length alone.
 *
 * Needed before anything can be served: `<video>` gets `Content-Range:
 * bytes a-b/TOTAL`, and TOTAL is the plaintext size, while all the server knows
 * is the size of the encrypted object.
 *
 * Derivable because full frames are a fixed size and only the last may be
 * short. A remainder of zero means the final chunk happened to be exactly full.
 * An empty file is one empty frame (40 bytes of pure overhead), which lands
 * correctly here rather than needing a special case.
 *
 * Returns null for a length that cannot be a valid container.
 */
export function plaintextLength(cipherLength: number): number | null {
  if (!Number.isInteger(cipherLength) || cipherLength < FRAME_OVERHEAD_BYTES) return null;
  const fullFrames = Math.floor(cipherLength / FULL_FRAME_BYTES);
  const remainder = cipherLength % FULL_FRAME_BYTES;
  if (remainder === 0) return fullFrames * MEDIA_CHUNK_SIZE;
  // A trailing frame must at least carry its own nonce and tag.
  if (remainder < FRAME_OVERHEAD_BYTES) return null;
  return fullFrames * MEDIA_CHUNK_SIZE + (remainder - FRAME_OVERHEAD_BYTES);
}

/** Ciphertext length of a container holding `n` plaintext bytes. */
export function cipherLength(plainLength: number): number {
  const chunks = Math.max(1, Math.ceil(plainLength / MEDIA_CHUNK_SIZE));
  const fullChunks = Math.floor(plainLength / MEDIA_CHUNK_SIZE);
  const tail = plainLength - fullChunks * MEDIA_CHUNK_SIZE;
  // When the length divides exactly there is no short trailing frame, unless
  // the file is empty, which still has one (empty) frame.
  if (plainLength > 0 && tail === 0) return chunks * FULL_FRAME_BYTES;
  return fullChunks * FULL_FRAME_BYTES + (tail + FRAME_OVERHEAD_BYTES);
}

export interface ChunkRange {
  /** First chunk index covering the request (0-based). */
  firstChunk: number;
  /** Last chunk index covering the request, inclusive. */
  lastChunk: number;
  /** Byte offset of `firstChunk`'s frame in the ciphertext. */
  cipherStart: number;
  /** Last ciphertext byte needed, inclusive, ready for a Range header. */
  cipherEnd: number;
  /** Where the answer begins within the decrypted chunk run. */
  sliceOffset: number;
  /** How many plaintext bytes to return. */
  sliceLength: number;
}

/**
 * Which chunks cover plaintext `[start, end]` (inclusive), and where the answer
 * sits once they are decrypted and concatenated.
 *
 * The caller fetches ciphertext `[cipherStart, cipherEnd]`, splits it into
 * frames, decrypts chunks `firstChunk..lastChunk`, concatenates, then slices at
 * `sliceOffset` for `sliceLength`. Almost every request is unaligned at both
 * ends (a player asks for whatever its buffer wants), so the slice is the
 * normal case, not an edge case.
 *
 * Returns null if the range cannot be satisfied.
 */
export function chunkRangeFor(
  start: number,
  end: number,
  plainTotal: number,
): ChunkRange | null {
  if (!Number.isInteger(start) || !Number.isInteger(end)) return null;
  if (start < 0 || start >= plainTotal || end < start) return null;
  const clampedEnd = Math.min(end, plainTotal - 1);

  const firstChunk = Math.floor(start / MEDIA_CHUNK_SIZE);
  const lastChunk = Math.floor(clampedEnd / MEDIA_CHUNK_SIZE);
  const cipherStart = firstChunk * FULL_FRAME_BYTES;
  // The end of the LAST needed frame. That frame may be the short trailing one,
  // so clamp to the container rather than assuming a full frame. Over-asking
  // would request bytes past the object and a strict store 416s.
  const cipherEnd = Math.min(
    (lastChunk + 1) * FULL_FRAME_BYTES - 1,
    cipherLength(plainTotal) - 1,
  );

  return {
    firstChunk,
    lastChunk,
    cipherStart,
    cipherEnd,
    sliceOffset: start - firstChunk * MEDIA_CHUNK_SIZE,
    sliceLength: clampedEnd - start + 1,
  };
}

/**
 * Parse a `Range` header into inclusive plaintext bounds.
 *
 * Handles the three forms `<video>` actually sends: `bytes=0-`, `bytes=a-b`,
 * and the suffix form `bytes=-n` (last n bytes), which Safari uses to read the
 * moov atom at the end of an MP4 and which is therefore not optional if video
 * is to play at all.
 *
 * Multi-range requests are refused deliberately rather than half-served: they
 * require a multipart/byteranges response, no browser media element sends one,
 * and returning a single range for a multi-range request is a silent
 * correctness bug. Null means "fall back to serving the whole thing".
 */
export function parseRangeHeader(
  header: string | null,
  plainTotal: number,
): { start: number; end: number } | null {
  if (!header) return null;
  const m = /^bytes=(\d*)-(\d*)$/.exec(header.trim());
  if (!m) return null;
  const [, rawStart, rawEnd] = m;
  if (rawStart === "" && rawEnd === "") return null;

  if (rawStart === "") {
    // Suffix: the last N bytes. N larger than the file means the whole file.
    const suffix = Number(rawEnd);
    if (!Number.isFinite(suffix) || suffix <= 0) return null;
    return { start: Math.max(0, plainTotal - suffix), end: plainTotal - 1 };
  }

  const start = Number(rawStart);
  if (!Number.isFinite(start) || start >= plainTotal) return null; // unsatisfiable
  const end = rawEnd === "" ? plainTotal - 1 : Math.min(Number(rawEnd), plainTotal - 1);
  if (end < start) return null;
  return { start, end };
}
