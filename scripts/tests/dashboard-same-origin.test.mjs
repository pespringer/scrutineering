import test from "node:test";
import assert from "node:assert/strict";
import { crossSiteMutation } from "../../dashboard/src/lib/sameOrigin.mjs";

const headers = (values) => ({ get: (name) => values[name] ?? null });

test("reads are never refused", () => {
  for (const method of ["GET", "HEAD", "OPTIONS", "get"]) {
    assert.equal(
      crossSiteMutation(method, headers({ "sec-fetch-site": "cross-site" })),
      false,
    );
  }
});

test("browsers' Sec-Fetch-Site decides: only same-origin may change state", () => {
  assert.equal(
    crossSiteMutation("POST", headers({ "sec-fetch-site": "same-origin" })),
    false,
  );
  for (const site of ["cross-site", "same-site", "none"]) {
    assert.equal(
      crossSiteMutation("POST", headers({ "sec-fetch-site": site })),
      true,
      site,
    );
  }
  // Sec-Fetch-Site wins over a matching Origin, which a same-site subdomain could also send.
  const sameSite = {
    "sec-fetch-site": "same-site",
    origin: "http://localhost:3001",
    host: "localhost:3001",
  };
  assert.equal(crossSiteMutation("PUT", headers(sameSite)), true);
});

test("without Sec-Fetch-Site, Origin must match the host the browser used", () => {
  const local = { host: "localhost:3001" };
  assert.equal(
    crossSiteMutation(
      "POST",
      headers({ ...local, origin: "http://localhost:3001" }),
    ),
    false,
  );
  assert.equal(
    crossSiteMutation(
      "POST",
      headers({ ...local, origin: "https://evil.example" }),
    ),
    true,
  );
  assert.equal(
    crossSiteMutation("DELETE", headers({ ...local, origin: "null" })),
    true,
  );
  const proxied = {
    host: "dashboard:3001",
    "x-forwarded-host": "scrutineering.home.lan",
  };
  assert.equal(
    crossSiteMutation(
      "POST",
      headers({ ...proxied, origin: "https://scrutineering.home.lan" }),
    ),
    false,
  );
  assert.equal(
    crossSiteMutation(
      "POST",
      headers({ ...proxied, origin: "https://dashboard:3001" }),
    ),
    true,
  );
});

test("requests without browser headers (curl, the e2e script) are not refused", () => {
  assert.equal(
    crossSiteMutation("POST", headers({ host: "localhost:3001" })),
    false,
  );
});
