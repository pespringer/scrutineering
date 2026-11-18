"""Signed exports (docs/design/sbom-evidence.md): the local key, cosign-format signatures, the key routes."""

from __future__ import annotations

import base64
import shutil
import stat
import subprocess

import pytest
from fastapi.testclient import TestClient

from src import signing
from src.api.app import create_app
from src.db.connection import get_session
from src.db.models import SigningKey
from src.scan import sbom as sboms
from src.scan.records import create_pending_scan

DOCUMENT = '{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"lodash","version":"4.17.20"}]}'


def _keys() -> list[SigningKey]:
    with get_session() as session:
        return session.query(SigningKey).order_by(SigningKey.id).all()


def test_the_key_is_made_once_private_to_the_worker_and_registered(signing_key_dir):
    first = signing.sign(b"one")
    second = signing.sign(b"two")
    assert first.key_id == second.key_id and first.key_id.startswith("sha256:")
    key_file = signing_key_dir / signing.PRIVATE_KEY_FILE
    assert stat.S_IMODE(key_file.stat().st_mode) == 0o600
    [key] = _keys()
    assert key.key_id == first.key_id and "PRIVATE" not in key.public_key_pem
    assert signing.verify(b"one", first.value, key.public_key_pem)


def test_a_changed_byte_or_a_wrong_key_fails_verification():
    signature = signing.sign(DOCUMENT.encode())
    [key] = _keys()
    assert not signing.verify(DOCUMENT.encode() + b" ", signature.value, key.public_key_pem)
    assert not signing.verify(DOCUMENT.encode(), base64.b64encode(b"garbage").decode(), key.public_key_pem)


def test_after_rotation_old_signatures_still_verify(signing_key_dir):
    old = signing.sign(b"before rotation")
    (signing_key_dir / signing.PRIVATE_KEY_FILE).unlink()
    new = signing.sign(b"after rotation")
    assert old.key_id != new.key_id
    pems = {key.key_id: key.public_key_pem for key in _keys()}
    assert signing.verify(b"before rotation", old.value, pems[old.key_id])
    assert signing.verify(b"after rotation", new.value, pems[new.key_id])


@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl is not installed")
def test_openssl_verifies_a_signature_with_the_public_pem_alone(tmp_path):
    """The documented check: `openssl dgst -sha256 -verify KEY.pem -signature <(base64 -d SIG) FILE`."""
    signature = signing.sign(DOCUMENT.encode())
    [key] = _keys()
    (tmp_path / "sbom.json").write_text(DOCUMENT)
    (tmp_path / "key.pem").write_text(key.public_key_pem)
    (tmp_path / "sbom.sig.der").write_bytes(base64.b64decode(signature.value))
    command = ["openssl", "dgst", "-sha256", "-verify", "key.pem", "-signature", "sbom.sig.der"]
    good = subprocess.run([*command, "sbom.json"], cwd=tmp_path, capture_output=True, text=True)
    assert good.returncode == 0 and "Verified OK" in good.stdout
    (tmp_path / "sbom.json").write_text(DOCUMENT.replace("4.17.20", "4.17.21"))
    assert subprocess.run([*command, "sbom.json"], cwd=tmp_path, capture_output=True).returncode != 0


def test_an_unusable_key_leaves_the_sbom_unsigned_not_lost(monkeypatch):
    def broken(data):
        raise PermissionError("read-only volume")

    monkeypatch.setattr(signing, "sign", broken)
    with get_session() as session:
        scan = create_pending_scan(session, "registry:5000/team/app:1.0")
        scan_id, image_id = scan.scan_id, scan.image_id
    stored = sboms.store(scan_id, image_id, DOCUMENT)
    assert stored.signature is None and stored.key_id is None


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("PYTHON_API_KEY", "sign-key")
    client = TestClient(create_app())
    client.headers["x-api-key"] = "sign-key"
    return client


def test_downloads_carry_the_signature_and_the_key_routes_serve_the_public_key(client):
    with get_session() as session:
        scan = create_pending_scan(session, "registry:5000/team/app:1.0")
        scan_id, image_id = scan.scan_id, scan.image_id
    stored = sboms.store(scan_id, image_id, DOCUMENT)

    download = client.get(f"/api/dashboard/scans/{scan_id}/sbom")
    assert download.headers["x-scrutineering-signature"] == stored.signature
    assert download.headers["x-scrutineering-key-id"] == stored.key_id
    sig = client.get(f"/api/dashboard/scans/{scan_id}/sbom.sig")
    assert sig.status_code == 200 and sig.text.strip() == stored.signature

    keys = client.get("/api/dashboard/signing-keys").json()["keys"]
    assert [key["key_id"] for key in keys] == [stored.key_id]
    pem = client.get(f"/api/dashboard/signing-keys/{stored.key_id.removeprefix('sha256:')}.pem")
    assert pem.status_code == 200 and pem.text == keys[0]["public_key_pem"]
    assert signing.verify(download.content, sig.text.strip(), pem.text)
    summary = client.get(f"/api/dashboard/scans/{scan_id}").json()["sbom"]
    assert summary["signed"] is True and summary["key_id"] == stored.key_id

    assert client.get("/api/dashboard/signing-keys/0000.pem").status_code == 404


def test_an_unsigned_sbom_has_no_signature_to_download(client, monkeypatch):
    monkeypatch.setattr(signing, "sign", lambda data: (_ for _ in ()).throw(OSError("no key")))
    with get_session() as session:
        scan = create_pending_scan(session, "registry:5000/team/app:1.0")
        scan_id, image_id = scan.scan_id, scan.image_id
    sboms.store(scan_id, image_id, DOCUMENT)
    assert "x-scrutineering-signature" not in client.get(f"/api/dashboard/scans/{scan_id}/sbom").headers
    response = client.get(f"/api/dashboard/scans/{scan_id}/sbom.sig")
    assert response.status_code == 404 and response.json()["detail"] == "sbom_not_signed"
