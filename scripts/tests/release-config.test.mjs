import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";

test("release config requires keyless identity and HTTPS issuer in production", () => {
  const script = "scripts/validate-release-config.mjs";
  assert.throws(() => execFileSync("node", [script], {
    env: { ...process.env, NODE_ENV: "production", RELEASE_EVIDENCE_REQUIRED: "true", COSIGN_CERTIFICATE_IDENTITY: "", COSIGN_OIDC_ISSUER: "" },
  }), /COSIGN_CERTIFICATE_IDENTITY/);
  execFileSync("node", [script], {
    env: { ...process.env, NODE_ENV: "production", RELEASE_EVIDENCE_REQUIRED: "true", COSIGN_CERTIFICATE_IDENTITY: "release@example", COSIGN_OIDC_ISSUER: "https://issuer.example" },
    stdio: "pipe",
  });
});
