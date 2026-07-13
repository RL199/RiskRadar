// Bundles the TypeScript benchmark with esbuild (the shared analyzer modules
// use extensionless imports, which plain `node` cannot resolve) and runs it.
// Arguments after the script name are read by the benchmark via process.argv.
import * as esbuild from "esbuild";
import { mkdir } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const outfile = join(root, "test", "data", "phish-bench.bundle.mjs");

await mkdir(dirname(outfile), { recursive: true });
await esbuild.build({
  entryPoints: [join(root, "test", "phish-bench.ts")],
  bundle: true,
  platform: "node",
  format: "esm",
  target: "node24",
  outfile,
  logLevel: "silent",
});

await import(pathToFileURL(outfile).href);
