/**
 * Wire format constants for encrypted media.
 *
 * Split out of `e2ee.ts` so they can be imported without pulling libsodium in
 * with them. The service worker needs the frame geometry to seek inside a video
 * (#390) and is bundled by esbuild. Importing `e2ee.ts` there would drag the
 * whole WASM crypto core into the service-worker bundle for four integers. The
 * SW does its own AEAD with @stablelib, which is already in that bundle for
 * push decryption.
 *
 * `e2ee.ts` re-exports MEDIA_CHUNK_SIZE, so existing imports are unaffected.
 * These values are the FORMAT: changing any of them invalidates every stored
 * blob, so they are not tunables.
 */

/** Plaintext bytes per chunk. Each chunk is encrypted independently. */
export const MEDIA_CHUNK_SIZE = 256 * 1024; // 256 KB

/** XChaCha20-Poly1305 nonce, prepended to each frame. */
export const NONCE_BYTES = 24; // crypto_aead_xchacha20poly1305_ietf_NPUBBYTES

/** Poly1305 tag, appended by the AEAD. */
export const TAG_BYTES = 16; // crypto_aead_xchacha20poly1305_ietf_ABYTES

/** Ciphertext overhead per frame, whether or not the frame is full. */
export const FRAME_OVERHEAD_BYTES = NONCE_BYTES + TAG_BYTES;

/** Ciphertext bytes for a frame carrying a full MEDIA_CHUNK_SIZE of plaintext. */
export const FULL_FRAME_BYTES = NONCE_BYTES + MEDIA_CHUNK_SIZE + TAG_BYTES;
