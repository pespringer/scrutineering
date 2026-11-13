"""External signature-provider adapters for evidence verification."""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path

from .cosign_policy import identity_allowed, load_cosign_policy


class CosignVerifier:
    """Verify a blob signature with cosign without invoking a shell."""

    def __init__(self, cosign_bin: str = "cosign", oidc_issuer: str | None = None, timeout_seconds: int = 30, policy: dict[str, object] | None = None):
        if timeout_seconds < 1:
            raise ValueError("timeout_seconds must be positive")
        self.cosign_bin = cosign_bin
        self.oidc_issuer = oidc_issuer
        self.timeout_seconds = timeout_seconds
        self.policy = policy if policy is not None else {"identity": "*", "issuer": oidc_issuer, "required": False}

    def __call__(self, envelope: dict, artifact_bytes: bytes) -> bool:
        signature = envelope.get("signature", {})
        identity = signature.get("identity")
        if not identity or not identity_allowed(identity, self.policy):
            return False
        expected_issuer = self.policy.get("issuer")
        if expected_issuer and self.oidc_issuer and expected_issuer != self.oidc_issuer:
            return False
        with tempfile.TemporaryDirectory(prefix="scrutineering-cosign-") as temp_dir:
            artifact_path = Path(temp_dir) / "artifact"
            signature_path = Path(temp_dir) / "signature"
            artifact_path.write_bytes(artifact_bytes)
            signature_path.write_text(signature["value"])
            command = [
                self.cosign_bin, "verify-blob", "--signature", str(signature_path),
                "--certificate-identity", identity,
            ]
            certificate = signature.get("certificate")
            if certificate:
                certificate_path = Path(temp_dir) / "certificate.pem"
                certificate_path.write_text(certificate)
                command.extend(["--certificate", str(certificate_path)])
            if self.oidc_issuer:
                command.extend(["--certificate-oidc-issuer", self.oidc_issuer])
            command.append(str(artifact_path))
            try:
                result = subprocess.run(command, capture_output=True, text=True, check=False, timeout=self.timeout_seconds)
            except (OSError, subprocess.TimeoutExpired):
                return False
            return result.returncode == 0
