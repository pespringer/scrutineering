const required = ["COSIGN_CERTIFICATE_IDENTITY", "COSIGN_OIDC_ISSUER"];
if (process.env.NODE_ENV === "production") {
  for (const name of required) {
    if (!String(process.env[name] || "").trim()) throw new Error(`${name} is required for production release promotion`);
  }
  if (!/^https:\/\//.test(process.env.COSIGN_OIDC_ISSUER)) throw new Error("COSIGN_OIDC_ISSUER must use HTTPS");
}
if (String(process.env.RELEASE_EVIDENCE_REQUIRED || "true").toLowerCase() !== "true") {
  throw new Error("RELEASE_EVIDENCE_REQUIRED must remain true");
}
console.log("PASS production release evidence configuration");
