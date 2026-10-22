import { build } from "esbuild";
import { readFile, writeFile } from "node:fs/promises";
for (const [entry, name] of [
  ["index.mjs", "page-renderer.js"],
  ["link-client.mjs", "page-link-client.js"],
]) {
  const output = await build({
    entryPoints: [entry],
    bundle: true,
    format: "esm",
    target: ["es2022"],
    legalComments: "inline",
    write: false,
    minify: false,
  });
  const destination = "../src/aweb_naapp/pages/assets/" + name;
  const bytes = output.outputFiles[0].text;
  if (process.argv.includes("--check")) {
    if ((await readFile(destination, "utf8")) !== bytes)
      throw Error(`${name} is stale; npm run build`);
  } else await writeFile(destination, bytes);
}

// Reuse the canonical OSS Paper/Clay tokens, including manual and OS dark mode.
const design = await readFile("../src/aweb_naapp/assets/aweb.css", "utf8");
const tokens = design.slice(
  design.indexOf(":root {"),
  design.indexOf("/* ---- base ---- */"),
);
const css = tokens + (await readFile("styles.css", "utf8"));
const cssPath = "../src/aweb_naapp/pages/assets/page-renderer.css";
if (process.argv.includes("--check")) {
  if ((await readFile(cssPath, "utf8")) !== css)
    throw Error("Renderer CSS is stale; npm run build");
} else await writeFile(cssPath, css);
