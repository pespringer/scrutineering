"""Signatures over exports: SBOMs and evidence bundles (docs/design/sbom-evidence.md).

An ECDSA P-256 key, generated on first use on the worker's `signingkeys` volume. A signature is
ECDSA over SHA-256 of the exact bytes, DER-encoded and base64'd: the format `cosign sign-blob`
writes, so `cosign verify-blob --key KEY.pem --signature SIG --insecure-ignore-tlog FILE` and
`openssl dgst -sha256 -verify KEY.pem -signature <(base64 -d SIG) FILE` both check it offline.

The private key never leaves the worker. Its public key goes into `signing_keys`, so the API can
serve it without the volume; old public keys stay there after a rotation.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import os
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

logger = logging.getLogger(__name__)

# The worker's volume (docker-compose.yml: signingkeys). Tests point this at a temporary directory.
KEY_DIR = Path("/var/lib/scrutineering/signing")
PRIVATE_KEY_FILE = "private.pem"


@dataclass(frozen=True)
class Signature:
    value: str  # base64 of the DER ECDSA signature
    key_id: str  # sha256:<hex of the DER public key>


def key_id(public_key: ec.EllipticCurvePublicKey) -> str:
    der = public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return "sha256:" + hashlib.sha256(der).hexdigest()


def public_pem(public_key: ec.EllipticCurvePublicKey) -> str:
    return public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()


def _load_or_create() -> ec.EllipticCurvePrivateKey:
    path = KEY_DIR / PRIVATE_KEY_FILE
    if not path.exists():
        KEY_DIR.mkdir(parents=True, exist_ok=True)
        key = ec.generate_private_key(ec.SECP256R1())
        pem = key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
        try:
            # O_EXCL: if two workers race, one key wins and the other loads it below.
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            pass
        else:
            with os.fdopen(fd, "wb") as handle:
                handle.write(pem)
            logger.info("generated signing key %s", key_id(key.public_key()))
    return serialization.load_pem_private_key(path.read_bytes(), password=None)


def _register(public_key: ec.EllipticCurvePublicKey) -> str:
    """Make sure the public key is in `signing_keys`; returns its key ID."""
    from src.db.connection import get_session
    from src.db.models import SigningKey

    identifier = key_id(public_key)
    with get_session() as session:
        if session.query(SigningKey.id).filter_by(key_id=identifier).first() is None:
            session.add(SigningKey(key_id=identifier, public_key_pem=public_pem(public_key)))
    return identifier


def sign(data: bytes) -> Signature:
    """Sign the exact bytes with this instance's key."""
    private_key = _load_or_create()
    identifier = _register(private_key.public_key())
    der = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
    return Signature(value=base64.b64encode(der).decode(), key_id=identifier)


def verify(data: bytes, signature: str, public_key_pem: str) -> bool:
    """Check a signature the way a verifier would, from the public PEM alone."""
    public_key = serialization.load_pem_public_key(public_key_pem.encode())
    try:
        public_key.verify(base64.b64decode(signature), data, ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError):
        return False
    return True
