// The "sumo" build is required for Argon2id (crypto_pwhash) — the standard build
// omits it. Larger wasm, but Argon2id is central to our key-wrapping design.
//
// libsodium (~½ MB of embedded wasm) is loaded via a dynamic import so it lands
// in its own async chunk, fetched only when a crypto operation actually runs —
// never in the main bundle of pages that don't touch encryption. The type is
// imported separately with `import type`, which is erased and carries no runtime
// cost.
import type _Sodium from "libsodium-wrappers-sumo";

export type Sodium = typeof _Sodium;

let ready: Promise<Sodium> | null = null;

/**
 * Resolve once libsodium's wasm is initialized; returns the sodium API. The
 * promise is created once and reused, so the module loads and initializes at
 * most once per runtime.
 */
export async function getSodium(): Promise<Sodium> {
  if (!ready) {
    ready = import("libsodium-wrappers-sumo").then(async (mod) => {
      const sodium = mod.default;
      await sodium.ready;
      return sodium;
    });
  }
  return ready;
}
