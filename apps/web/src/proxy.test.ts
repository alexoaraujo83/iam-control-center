import { describe, expect, it, vi } from "vitest";

const { middleware } = vi.hoisted(() => ({
  middleware: vi.fn(async (_request: Request) => new Response("Auth0 handled")),
}));

vi.mock("./lib/auth0", () => ({
  auth0: { middleware },
}));

import { config, proxy } from "./proxy";

describe("Next.js 16 Auth0 proxy", () => {
  it("delegates the incoming standard Request to Auth0 SDK middleware", async () => {
    const request = new Request("https://iam-control-center.example/auth/login");

    const response = await proxy(request);

    expect(middleware).toHaveBeenCalledOnce();
    expect(middleware).toHaveBeenCalledWith(request);
    expect(await response.text()).toBe("Auth0 handled");
  });

  it("keeps the SDK matcher broad while excluding framework assets and metadata", () => {
    expect(config.matcher).toEqual([
      "/((?!_next/static|_next/image|favicon.ico|sitemap.xml|robots.txt).*)",
    ]);
  });
});
