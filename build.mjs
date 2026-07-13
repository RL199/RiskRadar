import * as esbuild from "esbuild";
import { cp, mkdir, rm, watch } from "node:fs/promises";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(fileURLToPath(import.meta.url));
const outdir = join(root, "dist");
const isWatch = process.argv.includes("--watch");

// TypeScript entry points to bundle. Add background/content/interceptor here
// as those files are created (e.g. "scripts/content/content-main.ts").
const entryPoints = [
  "popup/popup.ts",
  "settings/settings.ts",
  "scripts/background/background.ts",
  "pages/click-gate.ts",
].filter((p) => existsSync(join(root, p)));

// Static files copied verbatim into dist/, preserving their relative paths
// so the manifest's references keep resolving.
const staticPaths = [
  "manifest.json",
  "_locales",
  "styles/theme.css",
  "popup/popup.html",
  "popup/popup.css",
  "settings/settings.html",
  "settings/settings.css",
  "pages/click-gate.html",
  "pages/click-gate.css",
  "assets/icon-plain.svg",
  "assets/icons",
];

async function copyStatic() {
  for (const rel of staticPaths) {
    const from = join(root, rel);
    if (existsSync(from)) {
      await cp(from, join(outdir, rel), { recursive: true });
    }
  }
}

const buildOptions = {
  entryPoints,
  outdir,
  outbase: root,
  bundle: true,
  format: "esm",
  target: "chrome116",
  sourcemap: isWatch,
  minify: !isWatch,
  logLevel: "info",
  // Re-copy static assets after every (re)build so dist/ stays consistent.
  plugins: [
    {
      name: "copy-static",
      setup(build) {
        build.onEnd(() => copyStatic());
      },
    },
  ],
};

await rm(outdir, { recursive: true, force: true });
await mkdir(outdir, { recursive: true });

if (isWatch) {
  const ctx = await esbuild.context(buildOptions);
  await ctx.watch();
  console.log("watching for changes... (TS via esbuild; static files via fs.watch)");

  // esbuild only watches TS inputs; watch static files ourselves.
  for (const rel of staticPaths) {
    const target = join(root, rel);
    if (!existsSync(target)) continue;
    (async () => {
      for await (const _ of watch(target, { recursive: true })) {
        await copyStatic();
      }
    })();
  }
} else {
  await esbuild.build(buildOptions);
  console.log("build complete -> dist/");
}
