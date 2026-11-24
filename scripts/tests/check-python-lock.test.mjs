import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { checkLock, directNames, pins } from "../check-python-lock.mjs";

const HASH = `    --hash=sha256:${"a".repeat(64)}`;

test("the repository's lock pins every direct dependency with hashes", () => {
  execFileSync("node", ["scripts/check-python-lock.mjs"], { stdio: "pipe" });
});

test("direct names are normalised; comments, options and specifiers are ignored", () => {
  const text =
    "# header\n-r other.in\nPyYAML\npydantic_settings>=2\ncryptography==50.0.2  # pinned\n\n";
  assert.deepEqual(directNames(text), [
    "pyyaml",
    "pydantic-settings",
    "cryptography",
  ]);
});

test("pins read markers and record whether each one has a hash", () => {
  const lock = [
    "# generated",
    "colorama==0.4.6 ; sys_platform == 'win32' \\",
    HASH,
    "    # via click",
    "rich==14.0.0",
    "    # via -r requirements.in",
  ].join("\n");
  assert.deepEqual(
    [...pins(lock)],
    [
      ["colorama", true],
      ["rich", false],
    ],
  );
});

test("a valid lock has no problems", () => {
  assert.deepEqual(checkLock("rich\n", `rich==14.0.0 \\\n${HASH}\n`), []);
});

test("a direct dependency missing from the lock is reported", () => {
  assert.deepEqual(checkLock("rich\nhttpx\n", `rich==14.0.0 \\\n${HASH}\n`), [
    "httpx is in requirements.in but not pinned in requirements.txt",
  ]);
});

test("a pin without a hash is reported", () => {
  assert.deepEqual(checkLock("rich\n", "rich==14.0.0\n"), [
    "rich is pinned without a hash",
  ]);
});

test("an empty lock is reported", () => {
  assert.ok(checkLock("", "").includes("requirements.txt pins nothing"));
});
