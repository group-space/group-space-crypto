import { getSodium } from "./sodium";
import {
  MEDIA_CHUNK_SIZE,
  NONCE_BYTES,
  TAG_BYTES,
  FULL_FRAME_BYTES,
} from "./media-format";

// Re-exported so the many existing `from "./e2ee"` imports keep working; the
// definitions live in media-format.ts, which the service worker can import
// without dragging libsodium into its bundle (#390).
export { MEDIA_CHUNK_SIZE };

/**
 * End-to-end encryption core (see docs/e2ee-design.md).
 *
 * These are pure, framework-agnostic primitives with no app/DB wiring, so they can
 * be audited and tested in isolation before anything depends on them. All values
 * that cross a storage/transport boundary are **base64 strings** (libsodium
 * ORIGINAL variant); raw `Uint8Array` is used only internally.
 *
 * Key hierarchy:
 *   password ──Argon2id──▶ wrapping key ──▶ unwraps member private key
 *   member key pair (X25519) ──▶ opens the Group Key sealed to its public key
 *   Group Key (symmetric) ──▶ encrypts fields + media (XChaCha20-Poly1305 AEAD)
 *
 * Nothing here ever transmits a private key, Group Key, or password in the clear;
 * the server only ever sees the wrapped/sealed blobs these functions produce.
 */

// --- Argon2id parameters ----------------------------------------------------
// Mobile-safe defaults (INTERACTIVE ≈ 64 MB) so a phone browser doesn't OOM at
// unlock. Stored alongside each wrapped secret so we can raise them later
// without breaking existing blobs.
async function argonDefaults() {
  const s = await getSodium();
  return {
    ops: s.crypto_pwhash_OPSLIMIT_INTERACTIVE,
    mem: s.crypto_pwhash_MEMLIMIT_INTERACTIVE,
  };
}

// --- Serialized shapes (all base64) ----------------------------------------

/** A symmetric secret (private key, Group Key, …) wrapped by a passphrase. */
export interface WrappedSecret {
  salt: string; // Argon2id salt
  nonce: string; // AEAD nonce
  ciphertext: string; // AEAD ciphertext (+tag)
  ops: number; // Argon2id opslimit used
  mem: number; // Argon2id memlimit used
}

/** An AEAD ciphertext bound to a context string (AAD). */
export interface SealedField {
  nonce: string;
  ciphertext: string;
}

export interface KeyPair {
  publicKey: string;
  privateKey: string;
}

// --- Low-level helpers ------------------------------------------------------

async function b64encode(bytes: Uint8Array): Promise<string> {
  const s = await getSodium();
  return s.to_base64(bytes, s.base64_variants.ORIGINAL);
}

async function b64decode(str: string): Promise<Uint8Array> {
  const s = await getSodium();
  return s.from_base64(str, s.base64_variants.ORIGINAL);
}

export async function randomBytes(n: number): Promise<Uint8Array> {
  const s = await getSodium();
  return s.randombytes_buf(n);
}

// --- Passphrase-wrapped secrets (password → private key; recovery code → Group Key)

/** Wrap an arbitrary symmetric secret under a passphrase (Argon2id + AEAD). */
export async function wrapSecret(
  secret: Uint8Array,
  passphrase: string,
): Promise<WrappedSecret> {
  const s = await getSodium();
  const { ops, mem } = await argonDefaults();
  const salt = s.randombytes_buf(s.crypto_pwhash_SALTBYTES);
  const key = s.crypto_pwhash(
    s.crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
    passphrase,
    salt,
    ops,
    mem,
    s.crypto_pwhash_ALG_ARGON2ID13,
  );
  const nonce = s.randombytes_buf(s.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
  const ct = s.crypto_aead_xchacha20poly1305_ietf_encrypt(secret, null, null, nonce, key);
  return {
    salt: await b64encode(salt),
    nonce: await b64encode(nonce),
    ciphertext: await b64encode(ct),
    ops,
    mem,
  };
}

/** Reverse of {@link wrapSecret}. Throws if the passphrase is wrong. */
export async function unwrapSecret(
  wrapped: WrappedSecret,
  passphrase: string,
): Promise<Uint8Array> {
  const s = await getSodium();
  const key = s.crypto_pwhash(
    s.crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
    passphrase,
    await b64decode(wrapped.salt),
    wrapped.ops,
    wrapped.mem,
    s.crypto_pwhash_ALG_ARGON2ID13,
  );
  return s.crypto_aead_xchacha20poly1305_ietf_decrypt(
    null,
    await b64decode(wrapped.ciphertext),
    null,
    await b64decode(wrapped.nonce),
    key,
  );
}

// --- Member identity keys ---------------------------------------------------

/** Generate a member's X25519 key pair (used to seal the Group Key to them). */
export async function generateKeyPair(): Promise<KeyPair> {
  const s = await getSodium();
  const kp = s.crypto_box_keypair();
  return { publicKey: await b64encode(kp.publicKey), privateKey: await b64encode(kp.privateKey) };
}

/** Wrap a member's private key under their password (for portable login). */
export async function wrapPrivateKey(privateKey: string, password: string): Promise<WrappedSecret> {
  return wrapSecret(await b64decode(privateKey), password);
}

/** Recover a member's private key from their password. Throws if wrong. */
export async function unwrapPrivateKey(wrapped: WrappedSecret, password: string): Promise<string> {
  return b64encode(await unwrapSecret(wrapped, password));
}

// --- Group key + granting (sealed boxes) ------------------------------------

/** A fresh random Group Key (base64). */
export async function generateGroupKey(): Promise<string> {
  const s = await getSodium();
  return b64encode(s.randombytes_buf(s.crypto_aead_xchacha20poly1305_ietf_KEYBYTES));
}

/**
 * Grant: seal the Group Key to a member's public key. Anyone can produce this
 * (it's anonymous), but only the holder of the matching private key can open it.
 */
export async function grantGroupKey(groupKey: string, recipientPublicKey: string): Promise<string> {
  const s = await getSodium();
  const sealed = s.crypto_box_seal(await b64decode(groupKey), await b64decode(recipientPublicKey));
  return b64encode(sealed);
}

/** Open a grant with the recipient's key pair to recover the Group Key. */
export async function openGroupKeyGrant(sealed: string, recipient: KeyPair): Promise<string> {
  const s = await getSodium();
  const opened = s.crypto_box_seal_open(
    await b64decode(sealed),
    await b64decode(recipient.publicKey),
    await b64decode(recipient.privateKey),
  );
  return b64encode(opened);
}

// --- Field encryption (AEAD with context binding) ---------------------------

/**
 * Encrypt a text field under the Group Key. `aad` binds the ciphertext to its
 * context (e.g. `"post:123:body"`) so it can't be silently moved to another
 * record; the same `aad` must be supplied to decrypt.
 */
export async function encryptField(
  groupKey: string,
  plaintext: string,
  aad: string,
): Promise<SealedField> {
  const s = await getSodium();
  const key = await b64decode(groupKey);
  const nonce = s.randombytes_buf(s.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
  const ct = s.crypto_aead_xchacha20poly1305_ietf_encrypt(
    s.from_string(plaintext),
    s.from_string(aad),
    null,
    nonce,
    key,
  );
  return { nonce: await b64encode(nonce), ciphertext: await b64encode(ct) };
}

/** Reverse of {@link encryptField}. Throws if `aad` or the ciphertext is wrong. */
export async function decryptField(
  groupKey: string,
  field: SealedField,
  aad: string,
): Promise<string> {
  const s = await getSodium();
  const plain = s.crypto_aead_xchacha20poly1305_ietf_decrypt(
    null,
    await b64decode(field.ciphertext),
    s.from_string(aad),
    await b64decode(field.nonce),
    await b64decode(groupKey),
  );
  return s.to_string(plain);
}

// --- Media: chunked AEAD so encrypted blobs stay range-fetchable ------------

/** A per-file key, itself wrapped under the Group Key. */
export async function generateFileKey(): Promise<string> {
  const s = await getSodium();
  return b64encode(s.randombytes_buf(s.crypto_aead_xchacha20poly1305_ietf_KEYBYTES));
}

export async function wrapFileKey(fileKey: string, groupKey: string): Promise<SealedField> {
  return encryptField(groupKey, fileKey, "filekey");
}

export async function unwrapFileKey(wrapped: SealedField, groupKey: string): Promise<string> {
  return decryptField(groupKey, wrapped, "filekey");
}

/**
 * Encrypt one media chunk. The chunk index is bound as AAD so chunks can't be
 * reordered, and a random nonce is stored per chunk. Returns `nonce || ct` as
 * base64; the client fetches a byte range, splits the nonce, and decrypts,
 * enabling seek/streaming without the server ever seeing plaintext.
 */
export async function encryptChunk(
  fileKey: string,
  index: number,
  plaintext: Uint8Array,
): Promise<string> {
  const s = await getSodium();
  const key = await b64decode(fileKey);
  const nonce = s.randombytes_buf(s.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
  const ct = s.crypto_aead_xchacha20poly1305_ietf_encrypt(
    plaintext,
    s.from_string(String(index)),
    null,
    nonce,
    key,
  );
  const packed = new Uint8Array(nonce.length + ct.length);
  packed.set(nonce, 0);
  packed.set(ct, nonce.length);
  return b64encode(packed);
}

/** Reverse of {@link encryptChunk} for a given chunk index. */
export async function decryptChunk(
  fileKey: string,
  index: number,
  packedB64: string,
): Promise<Uint8Array> {
  const s = await getSodium();
  const packed = await b64decode(packedB64);
  const nlen = s.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
  const nonce = packed.subarray(0, nlen);
  const ct = packed.subarray(nlen);
  return s.crypto_aead_xchacha20poly1305_ietf_decrypt(
    null,
    ct,
    s.from_string(String(index)),
    nonce,
    await b64decode(fileKey),
  );
}

/**
 * Whole-file byte encryption for media at rest: a self-framing binary container
 * built on the same per-chunk AEAD as {@link encryptChunk}, but returning raw
 * bytes (no base64 bloat) suitable for writing straight to disk / a Blob.
 *
 * Layout: the concatenation of per-chunk frames, each `nonce || ciphertext`.
 * Every chunk but the last carries exactly {@link MEDIA_CHUNK_SIZE} plaintext,
 * so a decoder splits by the fixed full-frame size and treats the shorter
 * trailing frame as the final chunk, so no length header is needed. The AAD binds
 * both a `context` label (so the same file key can protect, e.g., a photo's
 * "full" and "thumb" without either being swappable for the other) and the
 * chunk index (so chunks can't be reordered). Empty input yields a single empty
 * chunk so the container always has at least one frame.
 *
 * Note (threat model): truncation of trailing chunks by a *malicious* host is
 * out of scope (docs/e2ee-design.md): a curious host sees only ciphertext, and
 * every byte it does serve is authenticated.
 */

export async function encryptBytes(
  fileKey: string,
  bytes: Uint8Array,
  context: string,
): Promise<Uint8Array> {
  return encryptBytesWithNonces(fileKey, bytes, context, null);
}

/**
 * {@link encryptBytes} with the per-frame nonces supplied.
 *
 * **Never call this outside a test.** A nonce must be unique per key for this
 * cipher; reusing one across frames leaks plaintext by XOR and breaks the
 * authenticator. `encryptBytes` is the only correct entry point.
 *
 * It exists because a nonce is the *only* random input to a seal, so fixing it
 * makes the output fully determined, which is what allows a test vector to
 * state expected bytes at all, and therefore what lets the Swift sealer in the
 * iOS Share Extension be checked byte-for-byte against this one
 * (`scripts/media-format-selftest.mts`, `tools/swift-parity`).
 *
 * Exported rather than reimplemented in the test on purpose. A mirror of this
 * loop living in the test file is a second encoder, and a second encoder is
 * precisely what those vectors exist to detect. It would have pinned the mirror
 * while the shipping encoder drifted freely underneath it. One encoder, one set
 * of bytes.
 */
export async function encryptBytesWithNonces(
  fileKey: string,
  bytes: Uint8Array,
  context: string,
  nonces: Uint8Array[] | null,
): Promise<Uint8Array> {
  const s = await getSodium();
  const key = await b64decode(fileKey);
  // At least one (possibly empty) chunk, then one per MEDIA_CHUNK_SIZE slice.
  const chunkCount = Math.max(1, Math.ceil(bytes.length / MEDIA_CHUNK_SIZE));
  if (nonces && nonces.length !== chunkCount) {
    throw new Error(`encryptBytesWithNonces: ${nonces.length} nonces for ${chunkCount} frames`);
  }
  const frames: Uint8Array[] = [];
  let total = 0;
  for (let i = 0; i < chunkCount; i++) {
    const plain = bytes.subarray(i * MEDIA_CHUNK_SIZE, (i + 1) * MEDIA_CHUNK_SIZE);
    const nonce = nonces ? nonces[i] : s.randombytes_buf(NONCE_BYTES);
    const ct = s.crypto_aead_xchacha20poly1305_ietf_encrypt(
      plain,
      s.from_string(`${context}:${i}`),
      null,
      nonce,
      key,
    );
    const frame = new Uint8Array(nonce.length + ct.length);
    frame.set(nonce, 0);
    frame.set(ct, nonce.length);
    frames.push(frame);
    total += frame.length;
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const f of frames) {
    out.set(f, offset);
    offset += f.length;
  }
  return out;
}

/**
 * Streaming counterpart to {@link encryptBytes}: the same container, the same
 * AAD, the same frame layout, but it never holds more than one chunk of
 * plaintext and one frame of ciphertext at a time.
 *
 * `encryptBytes` takes the whole input as a `Uint8Array` and returns the whole
 * output as another, so its caller pays roughly 2x the file in JS heap before
 * the upload has even started. That was fine while media was small. It stopped
 * being fine when video was exempted from the `MAX_UPLOAD_MB` cap
 * (`storage.ts` `skipSizeLimit`, #192) and paid tiers set `maxVideoSeconds:
 * null`; a 2 GB clip off a modern phone is now an ordinary thing to pick.
 *
 * Consumers choose the sink. {@link encryptBlobToBlob} collects into a Blob for
 * the current upload path; the native background uploader (#384) writes frames
 * straight to disk. Both read from this one generator so the container can only
 * ever be produced in one place.
 *
 * Output is the same container {@link encryptBytes} produces: same frame
 * count, same frame sizes, same AAD, differing only in the random nonces, so
 * {@link decryptBytes}, the media reader, and the export path all consume it
 * unchanged. There is no format change and nothing to migrate.
 */
export async function* encryptBlobFrames(
  fileKey: string,
  blob: Blob,
  context: string,
): AsyncGenerator<Uint8Array, void, undefined> {
  const s = await getSodium();
  const key = await b64decode(fileKey);
  // Mirrors encryptBytes: at least one (possibly empty) chunk, so a zero-byte
  // input still yields exactly one frame and the container is never empty.
  const chunkCount = Math.max(1, Math.ceil(blob.size / MEDIA_CHUNK_SIZE));
  for (let i = 0; i < chunkCount; i++) {
    // Blob.slice() is a view, not a copy; the read happens at arrayBuffer(),
    // one chunk at a time, which is the whole point of this function.
    const slice = blob.slice(i * MEDIA_CHUNK_SIZE, (i + 1) * MEDIA_CHUNK_SIZE);
    const plain = new Uint8Array(await slice.arrayBuffer());
    const nonce = s.randombytes_buf(NONCE_BYTES);
    const ct = s.crypto_aead_xchacha20poly1305_ietf_encrypt(
      plain,
      s.from_string(`${context}:${i}`),
      null,
      nonce,
      key,
    );
    const frame = new Uint8Array(nonce.length + ct.length);
    frame.set(nonce, 0);
    frame.set(ct, nonce.length);
    yield frame;
  }
}

/**
 * How many frames to hand to the accumulating Blob at a time. 64 x 256 KB ≈
 * 16 MB: small enough that the JS-side array is never the problem, large
 * enough that we are not rebuilding a Blob per chunk.
 *
 * What the fold does and does not buy, measured rather than assumed:
 *
 *  - It keeps the *JS-side* array of frames small, and it is O(n): folding a
 *    256 MB input costs the same per MB as folding a 16 MB one, so the Blob
 *    references its parts rather than deep-copying them each time.
 *  - It does NOT make total memory independent of file size. The finished Blob
 *    still holds one copy of the ciphertext. Measured under Node (256 MB input,
 *    ~303 MB of growth) that copy is resident, because Node's Blob has no
 *    disk-backed store. Browsers spill large blobs to disk, so the same code is
 *    expected to cost less resident memory there. Expected, not verified here.
 *
 * So the honest claim for this function is that it halves peak memory versus
 * {@link encryptBytes}, which materialises the whole input *and* the whole
 * output. The genuinely size-independent path is the file sink that #384's
 * background uploader needs, which consumes {@link encryptBlobFrames} directly
 * and never builds a Blob at all.
 */
const FRAME_FOLD_COUNT = 64;

/**
 * {@link encryptBlobFrames} collected into a Blob. Peak memory is roughly one
 * copy of the ciphertext rather than {@link encryptBytes}'s two. See
 * {@link FRAME_FOLD_COUNT} for what that does and does not guarantee.
 *
 * `onProgress` reports plaintext bytes consumed, for a progress bar that tracks
 * the encrypt phase rather than jumping from 0 to 100 when the upload starts.
 */
export async function encryptBlobToBlob(
  fileKey: string,
  blob: Blob,
  context: string,
  onProgress?: (bytesRead: number) => void,
): Promise<Blob> {
  let acc = new Blob([]);
  let pending: BlobPart[] = [];
  let read = 0;
  for await (const frame of encryptBlobFrames(fileKey, blob, context)) {
    // Same cast the codebase already uses in media.ts `u8ToBlob`: TS types a
    // Uint8Array as ArrayBufferLike-backed, which does not narrow to BlobPart's
    // ArrayBuffer even though every value we produce here is exactly that.
    pending.push(frame as unknown as BlobPart);
    read = Math.min(read + MEDIA_CHUNK_SIZE, blob.size);
    onProgress?.(read);
    if (pending.length >= FRAME_FOLD_COUNT) {
      acc = new Blob([acc, ...pending]);
      pending = [];
    }
  }
  return pending.length ? new Blob([acc, ...pending]) : acc;
}

/** Reverse of {@link encryptBytes}. Throws if the key, context, or bytes are wrong. */
export async function decryptBytes(
  fileKey: string,
  data: Uint8Array,
  context: string,
): Promise<Uint8Array> {
  const s = await getSodium();
  const key = await b64decode(fileKey);
  const parts: Uint8Array[] = [];
  let offset = 0;
  let index = 0;
  let total = 0;
  do {
    const frameLen = Math.min(FULL_FRAME_BYTES, data.length - offset);
    const frame = data.subarray(offset, offset + frameLen);
    const nonce = frame.subarray(0, NONCE_BYTES);
    const ct = frame.subarray(NONCE_BYTES);
    const plain = s.crypto_aead_xchacha20poly1305_ietf_decrypt(
      null,
      ct,
      s.from_string(`${context}:${index}`),
      nonce,
      key,
    );
    parts.push(plain);
    total += plain.length;
    offset += frameLen;
    index += 1;
  } while (offset < data.length);
  const out = new Uint8Array(total);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

// --- Recovery code ----------------------------------------------------------

/**
 * A human-transcribable recovery code: 8 groups of 5 base32 chars (~200 bits).
 * Shown once to the admin at group setup; wraps a copy of the Group Key.
 */
export async function generateRecoveryCode(): Promise<string> {
  const alphabet = "ABCDEFGHJKMNPQRSTVWXYZ0123456789"; // Crockford-ish, no I/L/O/U
  const bytes = await randomBytes(40);
  let out = "";
  for (let i = 0; i < 40; i++) {
    out += alphabet[bytes[i] % alphabet.length];
    if (i % 5 === 4 && i !== 39) out += "-";
  }
  return out;
}

/** Wrap the Group Key under the recovery code (the group-level total-loss backstop). */
export async function wrapGroupKeyForRecovery(
  groupKey: string,
  recoveryCode: string,
): Promise<WrappedSecret> {
  return wrapSecret(await b64decode(groupKey), normalizeRecoveryCode(recoveryCode));
}

/** Recover the Group Key from the recovery code. Throws if the code is wrong. */
export async function openGroupKeyWithRecovery(
  wrapped: WrappedSecret,
  recoveryCode: string,
): Promise<string> {
  return b64encode(await unwrapSecret(wrapped, normalizeRecoveryCode(recoveryCode)));
}

/** Accept the code regardless of case/dashes/whitespace the user re-typed. */
export function normalizeRecoveryCode(code: string): string {
  return code.toUpperCase().replace(/[^A-Z0-9]/g, "");
}
