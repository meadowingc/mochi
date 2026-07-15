import { spawn } from "node:child_process";
import { cp, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
let activeChild;
let receivedSignal = false;

function waitForExit(child) {
  return new Promise((resolveExit, reject) => {
    child.once("error", reject);
    child.once("exit", (code, signal) => resolveExit({ code, signal }));
  });
}

function terminateActiveChild(signal = "SIGTERM") {
  if (!activeChild || activeChild.exitCode !== null || activeChild.signalCode !== null) {
    return;
  }

  const child = activeChild;
  if (!Number.isInteger(child.pid)) {
    return;
  }

  try {
    process.kill(-child.pid, signal);
  } catch (error) {
    if (error.code !== "ESRCH") {
      console.error(error);
    }
  }

  if (signal !== "SIGKILL") {
    const forceKillTimer = setTimeout(() => {
      if (child.exitCode === null && child.signalCode === null) {
        try {
          process.kill(-child.pid, "SIGKILL");
        } catch (error) {
          if (error.code !== "ESRCH") {
            console.error(error);
          }
        }
      }
    }, 8_000);
    forceKillTimer.unref();
  }
}

for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, () => {
    receivedSignal = true;
    terminateActiveChild(signal);
  });
}

async function run() {
  const runDirectory = await mkdtemp(join(tmpdir(), "mochi-e2e-"));
  const binaryPath = join(runDirectory, "mochi-e2e");

  try {
    await Promise.all([
      cp(join(repositoryRoot, "templates"), join(runDirectory, "templates"), {
        recursive: true,
      }),
      cp(join(repositoryRoot, "assets"), join(runDirectory, "assets"), {
        recursive: true,
      }),
      writeFile(
        join(runDirectory, ".env"),
        "# Intentionally minimal: debug mode supplies local-only defaults.\n",
        { mode: 0o600 },
      ),
    ]);

    if (receivedSignal) {
      return;
    }

    activeChild = spawn("go", ["build", "-o", binaryPath, "."], {
      cwd: repositoryRoot,
      detached: true,
      stdio: "inherit",
    });
    const buildResult = await waitForExit(activeChild);
    activeChild = undefined;

    if (receivedSignal) {
      return;
    }
    if (buildResult.code !== 0) {
      throw new Error(
        `debug Mochi build failed (${buildResult.signal ?? buildResult.code})`,
      );
    }

    activeChild = spawn(binaryPath, [], {
      cwd: runDirectory,
      detached: true,
      env: {
        ...process.env,
        MOCHI_E2E_MODE: "true",
        SELF_SITE_PUBLIC_ID: "",
      },
      stdio: "inherit",
    });
    const serverResult = await waitForExit(activeChild);
    activeChild = undefined;

    if (!receivedSignal && serverResult.code !== 0) {
      throw new Error(
        `Mochi E2E server exited (${serverResult.signal ?? serverResult.code})`,
      );
    }
  } finally {
    terminateActiveChild();
    await rm(runDirectory, { recursive: true, force: true, maxRetries: 3 });
  }
}

run().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
