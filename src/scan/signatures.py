"""External signature-provider adapters for evidence verification."""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path


class CosignVerifier:
    """Verify a blob signature with cosign without invoking a shell."""

    def __init__(self, cosign_bin: str = "cosign", oidc_issuer: str | None = None, timeout_seconds: int = 30):
        if timeout_seconds < 1:
            raise ValueError("timeout_seconds must be positive")
        self.cosign_bin = cosign_bin
        self.oidc_issuer = oidc_issuer
        self.timeout_seconds = timeout_seconds

    def __call__(self, envelope: dict, artifact_bytes: bytes) -> bool:
        signature = envelope.get("signature", {})
        identity = signature.get("identity")
        if not identity:
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
            if self.oidc_issuer:
                command.extend(["--certificate-oidc-issuer", self.oidc_issuer])
            command.append(str(artifact_path))
            try:
                result = subprocess.run(command, capture_output=True, text=True, check=False, timeout=self.timeout_seconds)
            except (OSError, subprocess.TimeoutExpired):
                return False
            return result.returncode == 0
