/**
 * Self-test for the change-password keychain re-wrap (Design Mode §3.11a, #56).
 *
 * Run with:  npm run test:rewrap
 *
 * The change-password flow re-wraps each membership's private key from the old
 * password to the new one. The property that makes it safe, and distinguishes
 * it from a forgotten-password reset, is that the *keypair never changes*, so
 * existing Group Key grants keep opening. These assertions pin that invariant:
 *
 *   1. re-wrapped key opens under the NEW password
 *   2. re-wrapped key does NOT open under the OLD password
 *   3. the re-wrapped key is byte-identical to the original (same keypair)
 *   4. a grant sealed to the original public key still opens after re-wrap
 *   5. re-wrapping the wrong password (client-side guard) throws
 *
 * Exits non-zero on any failure so it can gate CI.
 */
import * as e2ee from "../src/e2ee.ts";

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

const OLD = "old-correct-horse-battery";
const NEW = "new-staple-tractor-lantern";

/** Mirror the browser's re-wrap step: unwrap under old, wrap under new. */
async function reWrap(wrapped: e2ee.WrappedSecret, oldPw: string, newPw: string) {
  const priv = await e2ee.unwrapPrivateKey(wrapped, oldPw);
  return e2ee.wrapPrivateKey(priv, newPw);
}

console.log("keychain re-wrap (single membership):");
const kp = await e2ee.generateKeyPair();
const wrappedOld = await e2ee.wrapPrivateKey(kp.privateKey, OLD);
const wrappedNew = await reWrap(wrappedOld, OLD, NEW);

ok((await e2ee.unwrapPrivateKey(wrappedNew, NEW)) === kp.privateKey, "opens under the new password");
await throws(() => e2ee.unwrapPrivateKey(wrappedNew, OLD), "does not open under the old password");
ok(
  (await e2ee.unwrapPrivateKey(wrappedNew, NEW)) === kp.privateKey,
  "recovered private key is byte-identical (same keypair)",
);

console.log("existing grants survive the re-wrap:");
const groupKey = await e2ee.generateGroupKey();
// Grant is sealed to the public key, which never changes across a re-wrap.
const grant = await e2ee.grantGroupKey(groupKey, kp.publicKey);
const privAfter = await e2ee.unwrapPrivateKey(wrappedNew, NEW);
const kpAfter = { publicKey: kp.publicKey, privateKey: privAfter };
ok(
  (await e2ee.openGroupKeyGrant(grant, kpAfter)) === groupKey,
  "grant sealed before the change still opens the Group Key after it",
);

console.log("multi-membership (one password wraps every group's key):");
const members = await Promise.all([e2ee.generateKeyPair(), e2ee.generateKeyPair(), e2ee.generateKeyPair()]);
const wrappedAll = await Promise.all(members.map((m) => e2ee.wrapPrivateKey(m.privateKey, OLD)));
const rewrappedAll = await Promise.all(wrappedAll.map((w) => reWrap(w, OLD, NEW)));
let allOk = true;
for (let i = 0; i < members.length; i++) {
  if ((await e2ee.unwrapPrivateKey(rewrappedAll[i], NEW)) !== members[i].privateKey) allOk = false;
}
ok(allOk, "all three memberships re-wrap and open under the new password");

console.log("wrong current password (client-side guard):");
await throws(() => reWrap(wrappedOld, "not-the-old-password", NEW), "re-wrap throws when the current password is wrong");

console.log("");
console.log(`re-wrap self-test: ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
