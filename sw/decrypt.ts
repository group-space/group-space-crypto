/**
 * Decrypt-only client for restricted runtimes: service workers, notification
 * extensions, anything that must open ciphertext without carrying libsodium.
 *
 * ## Why a second implementation exists at all
 *
 * The main library seals and opens with libsodium (WASM). A service worker
 * wants neither the WASM payload nor an async loader in its startup path, so
 * the app's worker has always decrypted with @stablelib's pure-JS
 * XChaCha20-Poly1305 instead. Two implementations of one cipher is a real
 * risk, which is why the interop suite drives BOTH directions against shared
 * test vectors: libsodium's seal must open here, and a seal produced here (in
 * tests only, since this module deliberately exports no seal) must open there.
 *
 * Everything in this file is decrypt-only on purpose. A worker holds keys to
 * REVEAL content a device is entitled to; it composes nothing, so shipping it
 * a sealer would only widen what a compromised worker context could do.
 *
 * Extracted verbatim from the Group Space service worker; the app's worker now
 * imports these instead of carrying private copies.
 */
import { XChaCha20Poly1305 } from "@stablelib/xchacha20poly1305";
import { NONCE_BYTES } from "../src/media-format";

/** One sealed field as it travels in a push payload or key-wrap message. */
export interface SealedFieldWire {
  ciphertext: string;
  nonce: string;
  /** The context label this ciphertext is bound to. Empty string means none. */
  aad?: string;
}

/** Standard base64 (libsodium ORIGINAL variant, padded) → bytes. */
export function b64ToBytes(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/**
 * Open one `{ciphertext, nonce, aad}` field with a raw 32-byte key. Returns
 * the plaintext string, or null on ANY failure. A worker showing a
 * notification has no better move than falling back to generic copy, so the
 * failure mode is a value, not an exception.
 */
export function decryptField(keyBytes: Uint8Array, enc: SealedFieldWire | null | undefined): string | null {
  if (!enc || typeof enc.ciphertext !== "string" || typeof enc.nonce !== "string") return null;
  try {
    const aead = new XChaCha20Poly1305(keyBytes);
    const opened = aead.open(
      b64ToBytes(enc.nonce),
      b64ToBytes(enc.ciphertext),
      new TextEncoder().encode(enc.aad || ""),
    );
    return opened ? new TextDecoder().decode(opened) : null;
  } catch {
    return null;
  }
}

/**
 * Open one media-container frame under its chunk index. The AAD binds each
 * frame to its position (`context:index`), so frames cannot be reordered,
 * dropped, or transplanted between files without the open failing. Null on
 * any failure, same reasoning as {@link decryptField}.
 */
export function decryptFrame(
  keyBytes: Uint8Array,
  frame: Uint8Array,
  index: number,
  context: string,
): Uint8Array | null {
  try {
    const aead = new XChaCha20Poly1305(keyBytes);
    const opened = aead.open(
      frame.subarray(0, NONCE_BYTES),
      frame.subarray(NONCE_BYTES),
      new TextEncoder().encode(`${context}:${index}`),
    );
    return opened || null;
  } catch {
    return null;
  }
}

/**
 * Unwrap a per-file media key that was sealed under the Group Key with the
 * `filekey` context. Returns raw key bytes ready for {@link decryptFrame},
 * or null.
 */
export function unwrapFileKey(groupKeyBytes: Uint8Array, keyWrap: SealedFieldWire): Uint8Array | null {
  const b64 = decryptField(groupKeyBytes, { ...keyWrap, aad: "filekey" });
  return b64 ? b64ToBytes(b64) : null;
}
