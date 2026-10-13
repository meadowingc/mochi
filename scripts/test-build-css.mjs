import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { once } from "node:events";
import {
  copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync,
  symlinkSync, unlinkSync, writeFileSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";

const repository = fileURLToPath(new URL("../", import.meta.url));

function fixture(t) {
  const root = mkdtempSync(path.join(os.tmpdir(), "mochi-css-test-"));
  t.after(() => rmSync(root, { recursive: true }));
  for (const directory of ["scripts", "templates/layouts", "site", "assets/js"]) {
    mkdirSync(path.join(root, directory), { recursive: true });
  }
  copyFileSync(path.join(repository, "scripts/build-css.mjs"), path.join(root, "scripts/build-css.mjs"));
  copyFileSync(path.join(repository, ".node-version"), path.join(root, ".node-version"));
  copyFileSync(path.join(repository, "main.css"), path.join(root, "main.css"));
  symlinkSync(path.join(repository, "node_modules"), path.join(root, "node_modules"), "dir");
  writeFileSync(path.join(root, "templates/layouts/standard.source.html"),
    '<link href="/assets/css/bundled_styles.css?v=__MOCHI_CSS_HASH__"><body class="bg-stone-50"></body>');
  return {
    root,
    script: path.join(root, "scripts/build-css.mjs"),
    css: path.join(root, "assets/css/bundled_styles.css"),
    layout: path.join(root, "templates/layouts/standard.html"),
    source: path.join(root, "templates/layouts/standard.source.html"),
  };
}

function build(f, cwd = f.root) {
  return spawnSync(process.execPath, [f.script], { cwd, encoding: "utf8", timeout: 30_000 });
}

function successfulBuild(f, cwd) {
  const result = build(f, cwd);
  assert.equal(result.status, 0, result.stderr);
  return readFileSync(f.css);
}

test("generates a nonempty pinned bundle and matching cache version from source", t => {
  const f = fixture(t);
  const css = successfulBuild(f);
  const hash = createHash("sha256").update(css).digest("hex").slice(0, 12);
  assert.match(css.toString(), /^\/\*! tailwindcss v4\.1\.18/);
  assert.match(css.toString(), /\.bg-stone-50\{/);
  assert.match(css.toString(), /\.lowercase\{/);
  assert.ok(readFileSync(f.layout, "utf8").includes(`?v=${hash}`));
  assert.ok(!readFileSync(f.layout, "utf8").includes("__MOCHI_CSS_HASH__"));
  assert.ok(readFileSync(f.source, "utf8").includes("__MOCHI_CSS_HASH__"));
});

test("output is byte-identical across working directories and repeated builds", t => {
  const f = fixture(t);
  const first = successfulBuild(f);
  const layout = readFileSync(f.layout);
  assert.deepEqual(successfulBuild(f, os.tmpdir()), first);
  assert.deepEqual(readFileSync(f.layout), layout);
});

test("unrelated files and generated layout cannot pollute source scanning", t => {
  const f = fixture(t);
  const first = successfulBuild(f);
  writeFileSync(path.join(f.root, "unrelated.html"), '<div class="bg-fuchsia-950"></div>');
  writeFileSync(f.layout, '<div class="bg-fuchsia-950"></div>');
  assert.deepEqual(successfulBuild(f), first);
  assert.ok(!readFileSync(f.layout, "utf8").includes("bg-fuchsia-950"));
});

test("a missing or repeated source marker fails without replacing existing outputs", t => {
  const f = fixture(t);
  const before = successfulBuild(f);
  const layout = readFileSync(f.layout);
  for (const content of ["no marker", "__MOCHI_CSS_HASH__ __MOCHI_CSS_HASH__"]) {
    writeFileSync(f.source, content);
    const result = build(f);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /exactly one CSS hash marker/);
    assert.deepEqual(readFileSync(f.css), before);
    assert.deepEqual(readFileSync(f.layout), layout);
  }
});

test("missing locked dependencies fail without a download or output replacement", t => {
  const f = fixture(t);
  const before = successfulBuild(f);
  const layout = readFileSync(f.layout);
  unlinkSync(path.join(f.root, "node_modules"));
  const result = build(f);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /Install the locked Tailwind 4.1.18 dependencies/);
  assert.deepEqual(readFileSync(f.css), before);
  assert.deepEqual(readFileSync(f.layout), layout);
});

test("a compiler failure cannot silently leave a successful stale build", t => {
  const f = fixture(t);
  const before = successfulBuild(f);
  const layout = readFileSync(f.layout);
  writeFileSync(path.join(f.root, "main.css"), '@import "./missing.css";');
  const result = build(f);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /Tailwind compilation failed/);
  assert.deepEqual(readFileSync(f.css), before);
  assert.deepEqual(readFileSync(f.layout), layout);
});

test("an unreviewed Node version is rejected", t => {
  const f = fixture(t);
  writeFileSync(path.join(f.root, ".node-version"), "0.0.0");
  const result = build(f);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /Use Node 0.0.0/);
  assert.ok(!existsSync(f.css));
});

test("watch mode rebuilds CSS and the layout hash without a generated-file loop", async t => {
  const f = fixture(t);
  const child = spawn(process.execPath, [f.script, "--watch"], { cwd: f.root, stdio: ["ignore", "pipe", "pipe"] });
  const exited = once(child, "exit");
  let stdout = "";
  let stderr = "";
  child.stdout.on("data", value => { stdout += value; });
  child.stderr.on("data", value => { stderr += value; });
  async function waitFor(predicate) {
    const deadline = Date.now() + 20_000;
    while (!predicate()) {
      assert.equal(child.exitCode, null, stderr);
      assert.ok(Date.now() < deadline, `Watch timed out: ${stdout}\n${stderr}`);
      await delay(25);
    }
  }
  try {
    await waitFor(() => stdout.includes("Watching CSS sources"));
    const before = readFileSync(f.css);
    writeFileSync(f.source,
      '<link href="/assets/css/bundled_styles.css?v=__MOCHI_CSS_HASH__"><body class="bg-fuchsia-950">updated</body>');
    await waitFor(() => readFileSync(f.css).includes(Buffer.from(".bg-fuchsia-950{")));
    await waitFor(() => readFileSync(f.layout, "utf8").includes("updated"));
    assert.notDeepEqual(readFileSync(f.css), before);
    const hash = createHash("sha256").update(readFileSync(f.css)).digest("hex").slice(0, 12);
    assert.ok(readFileSync(f.layout, "utf8").includes(`?v=${hash}`));
    await delay(500);
    assert.equal(stdout.split("Generated CSS and layout:").length - 1, 2);
  } finally {
    child.kill("SIGTERM");
    const [code, signal] = await exited;
    assert.equal(code, 0, stderr);
    assert.equal(signal, null);
  }
});
