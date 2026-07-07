// Reproduce the bundle-size table in the README: each variant bundled for
// the browser with esbuild, minified, then gzipped.

import { gzipSync } from "node:zlib";
import { build } from "esbuild";

for (const file of [
  "reveal-forge.js",
  "reveal-micro.js",
  "reveal-diy.js",
  "reveal-webcrypto.js",
]) {
  const result = await build({
    entryPoints: [file],
    bundle: true,
    format: "esm",
    minify: true,
    write: false,
    logLevel: "silent",
  });
  const minified = result.outputFiles[0].contents;
  const gzipped = gzipSync(minified, { level: 9 });
  console.log(
    `${file.padEnd(21)} minified ${(minified.length / 1000).toFixed(1).padStart(6)} kB ` +
      `  gzipped ${(gzipped.length / 1000).toFixed(1).padStart(5)} kB`,
  );
}
