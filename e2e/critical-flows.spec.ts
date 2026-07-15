import { expect, test } from "@playwright/test";

const password = "e2e-password";

function uniqueUsername(prefix: string, retry: number): string {
  return `${prefix}_${process.pid}_${retry}`;
}

async function registerThroughUI(
  page: import("@playwright/test").Page,
  username: string,
) {
  await page.goto("/user/register");
  await page.getByLabel("Username").fill(username);
  await page.getByLabel("Password").fill(password);
  await page.getByRole("button", { name: "Register" }).click();
  await expect(page).toHaveURL(/\/dashboard\/?$/);
  await expect(
    page.getByRole("heading", { name: "Your Sites" }),
  ).toBeVisible();
}

test("registration, session hardening, logout, and login", async ({
  browser,
  page,
}, testInfo) => {
  const username = uniqueUsername("e2e_auth", testInfo.retry);
  await registerThroughUI(page, username);

  const sessionCookie = (await page.context().cookies()).find(
    (cookie) => cookie.name === "authenticated_user_token",
  );
  expect(sessionCookie).toBeDefined();
  expect(sessionCookie).toMatchObject({
    httpOnly: true,
    sameSite: "Lax",
    secure: false,
  });
  const expectedExpiry = Date.now() / 1000 + 30 * 24 * 60 * 60;
  expect(sessionCookie!.expires).toBeGreaterThan(expectedExpiry - 120);
  expect(sessionCookie!.expires).toBeLessThan(expectedExpiry + 120);

  await page.getByRole("link", { name: "Logout" }).click();
  await expect(page).toHaveURL(/\/user\/login$/);
  await expect(page.getByText("You have been logged out successfully.")).toBeVisible();

  await page.getByLabel("Username").fill(username);
  await page.getByLabel("Password").fill("incorrect-password");
  await page.getByRole("button", { name: "Login" }).click();
  await expect(page.getByText("Invalid username or password")).toBeVisible();

  await page.getByLabel("Username").fill(username);
  await page.getByLabel("Password").fill(password);
  await page.getByRole("button", { name: "Login" }).click();
  await expect(page).toHaveURL(/\/dashboard\/?$/);

  const exploitContext = await browser.newContext();
  try {
    await exploitContext.addCookies([
      {
        name: "authenticated_user_token",
        value: `///${username}`,
        url: "http://localhost:4738",
      },
    ]);
    const exploitPage = await exploitContext.newPage();
    await exploitPage.goto("http://localhost:4738/dashboard");
    await expect(exploitPage).toHaveURL(/\/user\/login$/);
    await expect(
      exploitPage.getByRole("heading", { name: "Welcome back 🍡" }),
    ).toBeVisible();
  } finally {
    await exploitContext.close();
  }
});

test("site, opaque embed, legacy routes, and SSRF rejection", async ({
  page,
}, testInfo) => {
  const username = uniqueUsername("e2e_site", testInfo.retry);
  await registerThroughUI(page, username);

  await page.getByRole("button", { name: "Add Site", exact: true }).click();
  await page.getByLabel("Site URL").fill("https://example.test");
  await page.getByRole("button", { name: "Add", exact: true }).click();

  const siteLink = page.getByRole("link", { name: /example\.test/ });
  await expect(siteLink).toBeVisible();
  const siteHref = await siteLink.getAttribute("href");
  const siteMatch = siteHref?.match(/^\/dashboard\/(\d+)\/analytics$/);
  expect(siteMatch).not.toBeNull();
  const siteID = siteMatch![1];

  await siteLink.click();
  await expect(page).toHaveURL(new RegExp(`/dashboard/${siteID}/analytics$`));
  await expect(page.getByText("No visit data in this date range")).toBeVisible();

  await page.getByRole("link", { name: "Site Settings" }).click();
  await expect(page).toHaveURL(new RegExp(`/dashboard/${siteID}/settings$`));
  await expect(page.getByRole("heading", { name: "Site Configuration" })).toBeVisible();

  await page.getByRole("link", { name: "Analytics" }).click();
  await page.getByRole("link", { name: /Embed Instructions/ }).click();
  await expect(page).toHaveURL(
    new RegExp(`/dashboard/${siteID}/analytics/embed-instructions$`),
  );

  const snippet = await page.locator("pre").first().innerText();
  const publicIDMatch = snippet.match(/\/reaper\/([A-Za-z0-9_-]{43})\/embed\.js/);
  expect(publicIDMatch).not.toBeNull();
  const publicID = publicIDMatch![1];
  expect(publicID).toHaveLength(43);
  expect(snippet).not.toContain(username);

  await page.goto("/test-embed-page");
  await page.addScriptTag({ url: `/reaper/${publicID}/embed.js` });
  const hitRequestPromise = page.waitForRequest(
    (request) =>
      request.method() === "POST" &&
      new URL(request.url()).pathname === `/reaper/${publicID}`,
  );
  await page.mouse.move(30, 30);
  const hitRequest = await hitRequestPromise;
  expect(hitRequest.url()).toContain("path=%2Ftest-embed-page");

  const analyticsURL = `/dashboard/${siteID}/analytics`;
  await expect
    .poll(
      async () => {
        const response = await page.request.get(analyticsURL);
        const html = await response.text();
        const visits = html.match(
          /<span class="text-2xl font-bold text-gray-900">(\d+)<\/span>\s*<span class="text-sm text-gray-400 ml-1">visits/,
        );
        return Number(visits?.[1] ?? -1);
      },
      { timeout: 10_000 },
    )
    .toBe(1);

  const legacyEmbed = await page.request.get(
    `/reaper/${username}/embed/${siteID}.js`,
  );
  expect(legacyEmbed.ok()).toBeTruthy();
  expect(legacyEmbed.headers()["deprecation"]).toBe("true");
  const legacyJavaScript = await legacyEmbed.text();
  expect(legacyJavaScript).toContain(
    `const analyticsEndpoint = "http://localhost:4738/reaper/${publicID}"`,
  );
  expect(legacyJavaScript).not.toContain(username);
  expect(legacyJavaScript).not.toContain(
    `/reaper/${username}/embed/${siteID}.js`,
  );

  const publicWebmentions = await page.request.get(
    `/api/webmentions/${publicID}`,
  );
  expect(publicWebmentions.status()).toBe(200);
  expect(publicWebmentions.headers()["content-type"]).toContain(
    "application/json",
  );
  expect(await publicWebmentions.json()).toEqual([]);

  const unsafeCanonicalRequests = [
    {
      source: "http://127.0.0.1/internal",
      target: "https://example.test/article",
    },
    {
      source: "https://source.example.test/post",
      target: "http://169.254.169.254/latest/meta-data",
    },
  ];
  for (const form of unsafeCanonicalRequests) {
    const response = await page.request.post(
      `/webmention/${publicID}/receive`,
      { form },
    );
    expect(response.status()).toBe(400);
  }

  const legacyWebmention = await page.request.post(
    `/webmention/${username}/${siteID}/receive`,
    {
      form: {
        source: "http://[::1]/internal",
        target: "https://example.test/article",
      },
    },
  );
  expect(legacyWebmention.status()).toBe(400);
  expect(legacyWebmention.headers()["deprecation"]).toBe("true");
});
