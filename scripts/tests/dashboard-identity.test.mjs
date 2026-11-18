import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import {
  apiIdentityHeaders,
  preset,
  proxyIdentity,
} from "../../dashboard/src/lib/identity.mjs";

const SECRET = "proxy-secret";
/** Like the Fetch Headers class: names are case-insensitive. */
const headers = (values) => {
  const lower = Object.fromEntries(
    Object.entries(values).map(([key, value]) => [key.toLowerCase(), value]),
  );
  return { get: (name) => lower[name.toLowerCase()] ?? null };
};
const env = (preset) => ({
  DASHBOARD_TRUSTED_PROXY_SECRET: SECRET,
  DASHBOARD_AUTH_HEADERS: preset,
});

test("each preset reads its proxy's headers", () => {
  const cases = [
    [
      "authelia",
      {
        "Remote-User": "alice",
        "Remote-Email": "a@x",
        "Remote-Groups": "ops,security",
      },
    ],
    [
      "authentik",
      {
        "X-authentik-username": "alice",
        "X-authentik-email": "a@x",
        "X-authentik-groups": "ops|security",
      },
    ],
    [
      "oauth2-proxy",
      {
        "X-Auth-Request-User": "alice",
        "X-Auth-Request-Email": "a@x",
        "X-Auth-Request-Groups": "ops,security",
      },
    ],
    [
      undefined,
      {
        "x-authenticated-sub": "alice",
        "x-authenticated-email": "a@x",
        "x-authenticated-roles": "ops,security",
      },
    ],
  ];
  for (const [name, values] of cases) {
    const identity = proxyIdentity(
      env(name),
      headers({ ...values, "x-dashboard-proxy-secret": SECRET }),
    );
    assert.deepEqual(
      identity,
      { sub: "alice", email: "a@x", groups: ["ops", "security"] },
      String(name),
    );
  }
});

test("no identity without the ingress's secret or a user", () => {
  const user = { "Remote-User": "alice", "Remote-Groups": "ops" };
  assert.equal(proxyIdentity(env("authelia"), headers(user)), null);
  assert.equal(
    proxyIdentity(
      env("authelia"),
      headers({ ...user, "x-dashboard-proxy-secret": "guess" }),
    ),
    null,
  );
  assert.equal(
    proxyIdentity(
      env("authelia"),
      headers({ "x-dashboard-proxy-secret": SECRET }),
    ),
    null,
  );
  const noSecret = { DASHBOARD_AUTH_HEADERS: "authelia" };
  assert.equal(
    proxyIdentity(
      noSecret,
      headers({ ...user, "x-dashboard-proxy-secret": "" }),
    ),
    null,
  );
  // The preset's headers only: Authelia mode ignores a client's x-authenticated-sub.
  const other = {
    "x-authenticated-sub": "mallory",
    "x-dashboard-proxy-secret": SECRET,
  };
  assert.equal(proxyIdentity(env("authelia"), headers(other)), null);
});

test("unknown presets are refused, and groups that would break the comma list are dropped", () => {
  assert.throws(
    () => preset("pomerium"),
    /DASHBOARD_AUTH_HEADERS must be one of/,
  );
  const values = {
    "X-authentik-username": "a",
    "X-authentik-groups": "ops| a,b |",
    "x-dashboard-proxy-secret": SECRET,
  };
  assert.deepEqual(proxyIdentity(env("authentik"), headers(values)).groups, [
    "ops",
  ]);
});

test("the API receives one fixed form", () => {
  assert.deepEqual(
    apiIdentityHeaders(
      { sub: "alice", email: null, groups: ["ops", "security"] },
      SECRET,
    ),
    {
      "x-dashboard-proxy-secret": SECRET,
      "x-authenticated-sub": "alice",
      "x-authenticated-roles": "ops,security",
    },
  );
});

test("the proxy checks every page in the app", () => {
  const app = path.resolve("dashboard/src/app");
  const source = fs.readFileSync(
    path.resolve("dashboard/src/proxy.ts"),
    "utf8",
  );
  const [, pattern] = source.match(/matcher: \["([^"]+)"\]/);
  const matcher = new RegExp(`^${pattern}$`);
  const pages = fs
    .readdirSync(app, { recursive: true })
    .filter((file) => /(^|\/)(page|route)\.tsx?$/.test(file))
    .map(
      (file) =>
        "/" +
        path
          .dirname(file)
          .replace(/^\.$/, "")
          .replace(/\[([^\]]+)\]/g, "1"),
    );
  assert.ok(pages.length > 10);
  for (const page of [...pages, "/"]) assert.match(page, matcher, page);
  for (const asset of ["/_next/static/chunks/app.js", "/favicon.ico"])
    assert.doesNotMatch(asset, matcher);
});
