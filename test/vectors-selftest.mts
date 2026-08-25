/**
 * The committed vectors are the wire-format contract (test/vectors/v1.json).
 *
 *   npm run test:vectors
 *
 * Three promises, checkable forever:
 *
 *  1. **Cross-implementation agreement.** Every sealed vector must open under
 *     BOTH implementations: libsodium (the app) and @stablelib (the worker).
 *     Two codebases, one cipher, no drift.
 *  2. **Format freeze.** The deterministic container vectors state exact
 *     lengths and digests. A change here means stored blobs in real
 *     deployments just got orphaned; the failure message says so.
 *  3. **Reimplementability.** The randomized wraps (Argon2id, sealed box)
 *     record one historical output each; any correct implementation must open
 *     them from the recorded bytes alone, without running this repo's sealer.
 */
import { readFileSync } from "node:fs";
import { XChaCha20Poly1305 } from "@stablelib/xchacha20poly1305";
import { getSodium } from "../src/sodium.ts";
import * as e2ee from "../src/e2ee.ts";
import { b64ToBytes, decryptField as swDecryptField, decryptFrame as swDecryptFrame, unwrapFileKey } from "../sw/decrypt.ts";
import { MEDIA_CHUNK_SIZE, NONCE_BYTES } from "../src/media-format.ts";

const V = JSON.parse(readFileSync(new URL("./vectors/v1.json", import.meta.url), "utf8"));
const sodium = await getSodium();
const b64d = (s: string) => sodium.from_base64(s, sodium.base64_variants.ORIGINAL);
const b64e = (b: Uint8Array) => sodium.to_base64(b, sodium.base64_variants.ORIGINAL);

let pass = 0;
const failures: string[] = [];
const ok = (n: string, c: boolean, d = "") => {
  if (!c) { failures.push(n); console.log(`  ✗ ${n}${d ? `: ${d}` : ""}`); return; }
  pass++; console.log(`  ✓ ${n}`);
};

function pattern(n: number, seed: number): Uint8Array {
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i++) out[i] = (i * 7 + seed) % 251;
  return out;
}

console.log("\nVectors are the contract (format v1)\n");

console.log("Field AEAD: every recorded seal opens under BOTH implementations");
for (const f of V.fieldAead) {
  const label = f.aad || "(no aad)";
  const viaApp = await e2ee.decryptField(f.key, f.sealed, f.aad);
  ok(`libsodium opens [${label}]`, viaApp === f.plaintext);
  const viaSw = swDecryptField(b64d(f.key), { ...f.sealed, aad: f.aad });
  ok(`@stablelib opens [${label}]`, viaSw === f.plaintext);
  const wrong = swDecryptField(b64d(f.key), { ...f.sealed, aad: f.aad + "x" });
  ok(`a bent AAD refuses [${label}]`, wrong === null);
}

console.log("\nMedia container: deterministic seal, frozen bytes, both openers");
for (const c of V.mediaContainer.vectors) {
  const plain = pattern(c.plaintext.length, c.plaintext.seed);
  const nonces = Array.from({ length: c.frames }, (_, f) => pattern(24, 100 + f));
  const sealed = await e2ee.encryptBytesWithNonces(c.fileKey, plain, c.context, nonces);
  ok(`${c.name}: ciphertext length is frozen`, sealed.length === c.cipherLength,
    `got ${sealed.length}, contract says ${c.cipherLength}. A mismatch ORPHANS EVERY STORED BLOB`);
  ok(`${c.name}: digest is frozen`, b64e(sodium.crypto_generichash(32, sealed, null)) === c.cipherBlake2b256,
    "same warning: this is the wire format, not a fixture");
  if (c.ciphertext) {
    ok(`${c.name}: exact bytes match the committed vector`, b64e(sealed) === c.ciphertext);
  }
  const opened = await e2ee.decryptBytes(c.fileKey, sealed, c.context);
  ok(`${c.name}: libsodium round-trips`, opened !== null && Buffer.compare(Buffer.from(opened), Buffer.from(plain)) === 0);
  // The worker's frame walk: FRAME = 24-byte nonce + ct + 16-byte tag.
  const FRAME = 24 + MEDIA_CHUNK_SIZE + 16;
  const key = b64d(c.fileKey);
  const parts: Uint8Array[] = [];
  for (let f = 0; f < c.frames; f++) {
    const frame = sealed.subarray(f * FRAME, Math.min((f + 1) * FRAME, sealed.length));
    const p = swDecryptFrame(key, frame, f, c.context);
    if (p) parts.push(p);
  }
  const swPlain = Buffer.concat(parts);
  ok(`${c.name}: @stablelib walks the frames to the same plaintext`,
    Buffer.compare(swPlain, Buffer.from(plain)) === 0);
  ok(`${c.name}: a transplanted frame refuses`,
    c.frames < 2 || swDecryptFrame(key, sealed.subarray(0, FRAME), 1, c.context) === null,
    "the AAD binds each frame to its index");
}
ok("NONCE_BYTES is what the walk assumed", NONCE_BYTES === 24);

console.log("\nThe filekey wrap: sealed by the app, unwrapped by the worker");
{
  const groupKey = await e2ee.generateGroupKey();
  const fileKey = await e2ee.generateFileKey();
  const wrap = await e2ee.wrapFileKey(fileKey, groupKey);
  const viaWorker = unwrapFileKey(b64d(groupKey), wrap);
  ok("the worker recovers the same raw key bytes",
    viaWorker !== null && Buffer.compare(Buffer.from(viaWorker), Buffer.from(b64d(fileKey))) === 0);
  ok("the worker's base64 agrees with libsodium's",
    Buffer.compare(Buffer.from(b64ToBytes(fileKey)), Buffer.from(b64d(fileKey))) === 0);
}

console.log("\nRandomized wraps: the recorded output opens, forever");
{
  const w = V.wrappedSecret;
  const opened = await e2ee.unwrapSecret(w.wrapped, w.password);
  ok("Argon2id wrap opens under the recorded password", b64e(opened) === w.secret);
  let refused = false;
  try {
    const x = await e2ee.unwrapSecret(w.wrapped, w.password + "!");
    refused = b64e(x) !== w.secret;
  } catch {
    refused = true;
  }
  ok("...and refuses a wrong password", refused);

  const g = V.sealedGrant;
  ok("the sealed-box grant opens for its recipient",
    (await e2ee.openGroupKeyGrant(g.sealed, g.recipient)) === g.groupKey);
}

console.log(`\n${pass} passed, ${failures.length} failed\n`);
if (failures.length) { for (const f of failures) console.log(`  FAILED: ${f}`); process.exit(1); }
