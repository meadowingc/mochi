import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  renameSync,
  rmSync,
  watch,
  writeFileSync,
} from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const stylesheet = path.join(root, "assets/css/bundled_styles.css");
const sourceLayout = path.join(root, "templates/layouts/standard.source.html");
const layout = path.join(root, "templates/layouts/standard.html");
const marker = "__MOCHI_CSS_HASH__";

function build() {
  const expectedNode = readFileSync(path.join(root, ".node-version"), "utf8").trim();
  if (process.versions.node !== expectedNode) {
    throw new Error(`Use Node ${expectedNode}; found ${process.versions.node}`);
  }
  for (const name of ["tailwindcss", "@tailwindcss/cli", "@tailwindcss/node", "@tailwindcss/oxide"]) {
    const filename = path.join(root, "node_modules", name, "package.json");
    if (!existsSync(filename) || JSON.parse(readFileSync(filename, "utf8")).version !== "4.1.18") {
      throw new Error(`Install the locked Tailwind 4.1.18 dependencies with npm ci (invalid ${name})`);
    }
  }
  const template = readFileSync(sourceLayout, "utf8");
  if (template.split(marker).length !== 2) {
    throw new Error("The source layout must contain exactly one CSS hash marker");
  }
  mkdirSync(path.dirname(stylesheet), { recursive: true });
  const temporary = mkdtempSync(path.join(path.dirname(stylesheet), ".css-build-"));
  try {
    const output = path.join(temporary, "bundled_styles.css");
    const result = spawnSync(process.execPath, [
      path.join(root, "node_modules/@tailwindcss/cli/dist/index.mjs"),
      "--input", path.join(root, "main.css"),
      "--output", output,
      "--minify",
    ], { cwd: root, stdio: "inherit" });
    if (result.error) throw result.error;
    if (result.status !== 0) {
      throw new Error(`Tailwind compilation failed (${result.signal ?? result.status})`);
    }
    const css = readFileSync(output);
    if (!css.toString().startsWith("/*! tailwindcss v4.1.18") || css.length === 0) {
      throw new Error("Tailwind did not generate the expected nonempty stylesheet");
    }
    const hash = createHash("sha256").update(css).digest("hex").slice(0, 12);
    const compiledLayout = path.join(temporary, "standard.html");
    writeFileSync(compiledLayout, template.replace(marker, hash));
    renameSync(output, stylesheet);
    renameSync(compiledLayout, layout);
    console.log(`Generated CSS and layout: ${hash}`);
  } finally {
    rmSync(temporary, { recursive: true });
  }
}

if (process.argv.slice(2).some(argument => argument !== "--watch")) {
  throw new Error("Usage: node scripts/build-css.mjs [--watch]");
}
build();

if (process.argv.includes("--watch")) {
  let timer;
  const rebuild = (directory, filename) => {
    if (!filename) throw new Error(`Cannot identify changed CSS source in ${directory}`);
    const changed = path.resolve(directory, filename.toString());
    if (changed === layout) return;
    clearTimeout(timer);
    timer = setTimeout(build, 150);
  };
  const directories = ["templates", "site", "assets/js"].map(name => path.join(root, name));
  const watchers = directories.map(directory =>
    watch(directory, { recursive: true }, (_, filename) => rebuild(directory, filename)));
  watchers.push(watch(root, (_, filename) => {
    if (filename?.toString() === "main.css") rebuild(root, filename);
  }));
  for (const watcher of watchers) watcher.on("error", error => { throw error; });
  for (const signal of ["SIGINT", "SIGTERM"]) {
    process.on(signal, () => {
      clearTimeout(timer);
      for (const watcher of watchers) watcher.close();
      process.exit(0);
    });
  }
  console.log("Watching CSS sources");
}
