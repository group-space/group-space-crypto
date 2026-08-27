/**
 * Proves the service worker can decrypt (with @stablelib) exactly what the app
 * encrypts (with libsodium). Both implement IETF XChaCha20-Poly1305; this asserts
 * they interoperate on real ciphertext + AAD produced by our own e2ee core, so
 * the SW-side rich-push decrypt can be trusted even though push itself is only
 * testable on a device.
 *
 * Run with:  npx tsx scripts/sw-crypto-interop.mts
 */
import { XChaCha20Poly1305 } from "@stablelib/xchacha20poly1305";
import * as e2ee from "../src/e2ee.ts";
import { openMediaManifest as swOpenMediaManifest } from "../sw/decrypt.ts";

let pass = 0;
let fail = 0;
function ok(cond: boolean, msg: string) {
  if (cond) { pass++; console.log("  ✓", msg); }
  else { fail++; console.log("  ✗ FAIL:", msg); }
}

// Use sodium directly for the base64 helpers so we compare against the exact
// bytes the app stores.
const { getSodium } = await import("../src/sodium.ts");
const sodium = await getSodium();
const b64 = (s: string) => sodium.from_base64(s, sodium.base64_variants.ORIGINAL);

console.log("libsodium → @stablelib interop:");

// Encrypt a field exactly like the app does (Group Key + context AAD).
const groupKey = await e2ee.generateGroupKey();
const aad = "discussion.post.body";
const plaintext = "Can someone cover carpool Friday? 🚗";
const field = await e2ee.encryptField(groupKey, plaintext, aad);

// Now decrypt with @stablelib, the way the service worker will: raw group-key
// bytes + nonce + ciphertext(+tag) + AAD-as-utf8.
const key = b64(groupKey);
const nonce = b64(field.nonce);
const ct = b64(field.ciphertext);
const aead = new XChaCha20Poly1305(key);
const opened = aead.open(nonce, ct, new TextEncoder().encode(aad));
ok(opened !== null, "stablelib opens libsodium ciphertext");
ok(opened !== null && new TextDecoder().decode(opened) === plaintext, "recovered plaintext matches");

// Wrong AAD must be rejected (context binding holds across implementations).
const bad = aead.open(nonce, ct, new TextEncoder().encode("wrong.aad"));
ok(bad === null, "wrong AAD is rejected");

// Tamper → rejected.
const tampered = ct.slice();
tampered[tampered.length - 1] ^= 1;
ok(aead.open(nonce, tampered, new TextEncoder().encode(aad)) === null, "tampered ciphertext is rejected");

// And the reverse direction: @stablelib seal → libsodium/app decryptField opens.
const key2 = await e2ee.generateGroupKey();
const aead2 = new XChaCha20Poly1305(b64(key2));
const nonce2 = sodium.randombytes_buf(24);
const sealed = aead2.seal(nonce2, new TextEncoder().encode("hi from the SW"), new TextEncoder().encode(aad));
const field2 = {
  nonce: sodium.to_base64(nonce2, sodium.base64_variants.ORIGINAL),
  ciphertext: sodium.to_base64(sealed, sodium.base64_variants.ORIGINAL),
};
ok((await e2ee.decryptField(key2, field2, aad)) === "hi from the SW", "app opens stablelib ciphertext (reverse)");

// The container's length manifest crosses the same boundary. A worker serving a
// byte range is exactly the reader that cannot tell a complete container from a
// trimmed one, so the manifest has to open on this side too, byte for byte.
console.log("\nmedia manifest, libsodium seal → worker open:");
const fileKey = await e2ee.generateFileKey();
const payload = Uint8Array.from({ length: Math.floor(e2ee.MEDIA_CHUNK_SIZE * 2.5) }, (_, i) => i % 251);
const manifest = e2ee.mediaManifestFor(payload);
const sealedManifest = await e2ee.sealMediaManifest(fileKey, manifest, "full");

const swOpened = swOpenMediaManifest(b64(fileKey), sealedManifest, "full");
ok(
  swOpened !== null && swOpened.frames === manifest.frames && swOpened.bytes === manifest.bytes,
  "the worker opens a manifest sealed by the main library",
);
ok(
  swOpenMediaManifest(b64(fileKey), sealedManifest, "thumb") === null,
  "the worker rejects a manifest sealed for another context",
);
ok(
  swOpenMediaManifest(b64(await e2ee.generateFileKey()), sealedManifest, "full") === null,
  "the worker rejects a manifest under the wrong file key",
);

// The worker re-implements the sanity checks, and nothing fed it anything but a
// well-formed manifest. Two implementations that validate differently are two
// implementations that disagree about which files are readable.
async function sealRaw(value: unknown) {
  return e2ee.encryptField(fileKey, JSON.stringify(value), "media.manifest:full");
}
for (const [value, label] of [
  [{ bytes: 10, frames: 0 }, "zero frames"],
  [{ bytes: -1, frames: 1 }, "a negative length"],
  [{ bytes: 10, frames: 1.5 }, "a fractional frame count"],
  [{ bytes: Number.NaN, frames: 1 }, "NaN as a length"],
  [{ bytes: 10, frames: 5000 }, "frames that disagree with bytes"],
  ["not an object", "a plaintext that is not an object"],
  [null, "a plaintext that is null"],
] as [unknown, string][]) {
  ok(
    swOpenMediaManifest(b64(fileKey), await sealRaw(value), "full") === null,
    `the worker returns null for ${label}`,
  );
}
// Its contract is null on any failure, never a throw: a worker declines, it
// does not raise into an event handler nobody is awaiting.
let threw = false;
try {
  swOpenMediaManifest(b64(fileKey), await e2ee.encryptField(fileKey, "{oops", "media.manifest:full"), "full");
} catch {
  threw = true;
}
ok(!threw, "the worker returns null rather than throwing on unparseable JSON");

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
