import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { anchors, checkLinks, slug } from "../validate-doc-links.mjs";

test("every Markdown link in the repository resolves", () => {
  execFileSync("node", ["scripts/validate-doc-links.mjs"], { stdio: "pipe" });
});

test("headings become GitHub's anchors, repeated ones numbered", () => {
  assert.equal(slug("1. Scan an image"), "1-scan-an-image");
  assert.equal(slug("API and access"), "api-and-access");
  assert.equal(slug("`DATABASE_URL` 🔒"), "database_url-");
  assert.deepEqual(
    [
      ...anchors(
        "# A\n## Set up\n## Set up\n## `GITHUB_TOKEN` scope\n```\n# not a heading\n```\n",
      ),
    ],
    ["a", "set-up", "set-up-1", "github_token-scope"],
  );
});

test("missing files and anchors are reported; code and external links are not checked", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "doc-links-"));
  fs.mkdirSync(path.join(root, "docs"));
  fs.writeFileSync(
    path.join(root, "docs", "other.md"),
    "# Other\n\n## Details\n",
  );
  fs.writeFileSync(
    path.join(root, "docs", "guide.md"),
    [
      "# Guide",
      "[ok](other.md#details) [self](#guide) [external](https://example.invalid/x)",
      "[gone](missing.md) [bad anchor](other.md#nope) `[code](inline.md)`",
      "```",
      "[fenced](fenced.md)",
      "```",
    ].join("\n"),
  );
  assert.deepEqual(checkLinks(["docs/guide.md"], root), [
    "docs/guide.md: missing.md (no such file)",
    "docs/guide.md: other.md#nope (no heading #nope)",
  ]);
});
