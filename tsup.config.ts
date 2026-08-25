import { defineConfig } from "tsup";

/**
 * Build the published artifact.
 *
 * Three choices here are deliberate and should not be "optimised" later:
 *
 * `minify: false` - readability is the product. Someone deciding whether to
 * trust this library may read the installed files, not just the repo, and a
 * minified crypto core defeats the entire reason it is public.
 *
 * `splitting: false` with one entry per subpath - keeps the zero-crypto
 * subpaths (aad, media-format, media-range) genuinely free of any crypto
 * import. Shared chunks would let a bundler pull libsodium into a service
 * worker that only wanted four integers, which is the exact regression
 * media-format.ts exists to prevent.
 *
 * No `sourcemap` and a fixed `target` - the output should be a function of the
 * input, so an artifact can be rebuilt from a tag and compared. Sourcemaps
 * embed absolute paths and break that.
 */
export default defineConfig({
  // Named entries, so output is dist/e2ee.js rather than dist/src/e2ee.js.
  // The subpath in the exports map should read like the file it serves.
  entry: {
    index: "src/index.ts",
    e2ee: "src/e2ee.ts",
    "account-keys": "src/account-keys.ts",
    aad: "src/aad.ts",
    "media-format": "src/media-format.ts",
    "media-range": "src/media-range.ts",
    "sw-decrypt": "sw/decrypt.ts",
  },
  outDir: "dist",
  format: ["esm"],
  target: "es2022",
  dts: true,
  clean: true,
  minify: false,
  splitting: false,
  sourcemap: false,
  treeshake: false,
});
