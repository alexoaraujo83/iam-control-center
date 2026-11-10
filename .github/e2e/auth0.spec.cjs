const { test, expect } = require("@playwright/test");

test("Auth0 login, callback, session persistence and logout", async ({ page }) => {
  const baseURL = process.env.E2E_BASE_URL;
  const username = process.env.AUTH0_E2E_USERNAME;
  const password = process.env.AUTH0_E2E_PASSWORD;
  const trustedOidcToken = process.env.VERCEL_TRUSTED_OIDC_TOKEN;
  const callbackHost = process.env.E2E_CALLBACK_HOST;

  if (!baseURL || !username || !password || !trustedOidcToken || !callbackHost) {
    throw new Error("Required Auth0 E2E configuration is missing.");
  }
  if (callbackHost !== "iam-control-center-preview.vercel.app") {
    throw new Error("Unexpected Auth0 callback Preview host.");
  }

  const previewHost = new URL(baseURL).hostname;
  if (previewHost !== callbackHost) {
    throw new Error("Auth0 E2E must start and return on the same Preview alias so transaction cookies remain same-origin.");
  }
  const trustedHosts = new Set([callbackHost]);
  let callbackRequestSeen = false;
  const context = page.context();
  const cdp = await context.newCDPSession(page);
  const trustedHeader = "x-vercel-trusted-oidc-idp-token";

  // CDP Fetch pauses every network request, including redirect hops. Playwright
  // route.continue() only modified the first request in the chain, leaving the
  // Auth0 callback without the Trusted Sources header.
  await cdp.send("Fetch.enable", {
    patterns: [{ urlPattern: "*", requestStage: "Request" }],
  });

  cdp.on("Fetch.requestPaused", async ({ requestId, request }) => {
    try {
      const requestUrl = new URL(request.url);
      const headers = Object.entries(request.headers)
        .filter(([name]) => name.toLowerCase() !== trustedHeader)
        .map(([name, value]) => ({ name, value: String(value) }));

      // The exact-SHA deployment URL starts the flow; the configured branch
      // alias receives the Auth0 callback. Trust only these two Preview hosts.
      const trustedHost = trustedHosts.has(requestUrl.hostname);
      if (trustedHost) {
        headers.push({ name: trustedHeader, value: trustedOidcToken });
      }
      if (
        requestUrl.hostname === callbackHost &&
        requestUrl.pathname.startsWith("/auth/callback")
      ) {
        callbackRequestSeen = true;
      }

      if (
        trustedHost ||
        requestUrl.hostname === "iam-control-center.us.auth0.com"
      ) {
        console.log(
          `CDP request: ${request.method} ${requestUrl.hostname}${requestUrl.pathname}; trusted header: ${trustedHost ? "attached" : "stripped"}`
        );
      }

      await cdp.send("Fetch.continueRequest", { requestId, headers });
    } catch {
      // Fail closed: never continue a request if host scoping or header
      // construction fails.
      await cdp.send("Fetch.failRequest", {
        requestId,
        errorReason: "Aborted",
      });
    }
  });

  // Anonymous access must enter the Auth0 Authorization Code + PKCE flow.
  await page.goto("/protected");
  await expect(page).toHaveURL(/auth0\.com/);

  const identifier = page.locator('input[name="username"], input[name="email"]').first();
  await expect(identifier).toBeVisible();
  await identifier.fill(username);

  const passwordInput = page.locator('input[name="password"]');
  if (!(await passwordInput.isVisible().catch(() => false))) {
    await page.getByRole("button", { name: /continue/i }).first().click();
  }
  await expect(passwordInput).toBeVisible();
  await passwordInput.fill(password);
  await page.getByRole("button", { name: /continue|log in|sign in/i }).last().click();

  // Reaching the protected route with a server-confirmed authenticated status proves
  // the callback completed and the application session was issued.
  await expect(page).toHaveURL((url) => url.pathname === "/protected", { timeout: 60000 });
  await expect(page.getByRole("status")).toHaveText("Acesso autenticado confirmado.");
  expect(
    callbackRequestSeen,
    "Auth0 callback must reach the configured Preview alias with the Trusted Sources header"
  ).toBe(true);

  // The authenticated session must survive a subsequent request.
  await page.reload();
  await expect(page.getByRole("status")).toHaveText("Acesso autenticado confirmado.");

  // Logout returns to the app root, which is immediately redirected to
  // Auth0 by the Next.js proxy. Verify the login screen, not a transient URL.
  await page.goto("/auth/logout");
  await expect(page).toHaveURL(/iam-control-center\.us\.auth0\.com\/u\/login/, {
    timeout: 60000,
  });
  await expect(
    page.locator('input[name="username"], input[name="email"]').first()
  ).toBeVisible();

  // A fresh protected request must still require authentication after logout.
  await page.goto("/protected");
  await expect(page).toHaveURL(/iam-control-center\.us\.auth0\.com\/u\/login/, {
    timeout: 30000,
  });
  await expect(
    page.locator('input[name="username"], input[name="email"]').first()
  ).toBeVisible();

  await cdp.send("Fetch.disable");
  await cdp.detach();
});
