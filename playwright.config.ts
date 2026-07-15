import { defineConfig, devices } from "@playwright/test";

const baseURL = "http://localhost:4738";

export default defineConfig({
  testDir: "./e2e",
  fullyParallel: false,
  workers: 1,
  retries: 0,
  timeout: 30_000,
  expect: {
    timeout: 10_000,
  },
  outputDir: "test-results",
  reporter: "list",
  use: {
    baseURL,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    video: "off",
  },
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    },
  ],
  webServer: {
    command: "node scripts/e2e-server.mjs",
    url: baseURL,
    reuseExistingServer: false,
    timeout: 120_000,
    stdout: "pipe",
    stderr: "pipe",
    gracefulShutdown: {
      signal: "SIGTERM",
      timeout: 10_000,
    },
  },
});
