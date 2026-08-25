/**
 * @group-space/crypto-core (spike)
 *
 * The public surface of the candidate extracted library. Three layers:
 *
 *  - e2ee.ts: primitives + the encrypted-media container format
 *    (Argon2id key wrapping, X25519 sealed-box grants, XChaCha20-Poly1305
 *    field/chunk AEAD, recovery codes).
 *  - account-keys.ts: the account-keychain protocol composed from those
 *    primitives (enrollment, recovery restore, reset re-enrollment).
 *  - media-format.ts / media-range.ts: the wire-format constants and the pure
 *    range arithmetic that lets a service worker seek inside encrypted media.
 *  - aad.ts: the context-binding label registry (the ciphertext contract).
 *
 * Everything here is framework-free: no React, no Prisma, no Next.js, no app
 * imports. All values crossing a storage/transport boundary are base64 strings.
 */
export * from "./e2ee";
export * from "./account-keys";
export * from "./media-format";
export * from "./media-range";
export * as aad from "./aad";
export { getSodium, type Sodium } from "./sodium";
