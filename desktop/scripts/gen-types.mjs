// Generates src/lib/api/*.gen.ts from the helper's Go types with tygo.
//
//   node scripts/gen-types.mjs           regenerate
//   node scripts/gen-types.mjs --check   fail when the committed files are stale
//
// tygo runs through `go run` at a pinned version, so only a Go toolchain is
// needed. It must run from the repository root so Go resolves the helper's
// module; tygo.yaml names the packages and output paths relative to it.

import { spawnSync } from "node:child_process";
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const TYGO = "github.com/gzuidhof/tygo@v0.2.21";
const here = dirname(fileURLToPath(import.meta.url));
const appDir = resolve(here, "..");
const repoRoot = resolve(appDir, "..");
const outputs = ["activity", "history", "config", "types"].map((n) =>
  join(appDir, "src/lib/api", `${n}.gen.ts`),
);

// Drops constants tygo could not translate (a duration product, for one), with
// their doc comment: they are helper-internal tuning, not wire contract.
function dropUntranslatable(source) {
  return source.replace(/(?:\/\*\*(?:(?!\*\/)[\s\S])*\*\/\n)?export const \w+ = [^\n]*\bany \/\*[^\n]*\n/g, "");
}

function generate() {
  const run = spawnSync("go", ["run", TYGO, "generate", "--config", "desktop/tygo.yaml"], {
    cwd: repoRoot,
    stdio: ["ignore", "inherit", "inherit"],
  });
  if (run.error) throw new Error(`could not run go: ${run.error.message}`);
  if (run.status !== 0) throw new Error(`tygo failed with status ${run.status}`);
  for (const file of outputs) {
    writeFileSync(file, dropUntranslatable(readFileSync(file, "utf8")));
  }
}

const check = process.argv.includes("--check");
const before = outputs.map((f) => (existsSync(f) ? readFileSync(f, "utf8") : null));

try {
  generate();
} catch (error) {
  console.error(error instanceof Error ? error.message : error);
  process.exit(2);
}

if (check) {
  const stale = outputs.filter((f, i) => readFileSync(f, "utf8") !== before[i]);
  if (stale.length > 0) {
    // Put the committed files back: a check must not change the tree.
    outputs.forEach((f, i) => before[i] === null || writeFileSync(f, before[i]));
    console.error(`Generated types are stale: ${stale.map((f) => f.replace(appDir + "/", "")).join(", ")}`);
    console.error("Run `pnpm gen:types` and commit the result.");
    process.exit(1);
  }
  console.log("Generated types are up to date.");
}
