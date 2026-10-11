"""load_feed verifies the detached Ed25519 signature on the advisory feed.

The feed is signed by pipeline/sign_feed.sh (openssl pkeyutl -sign -rawin, raw
64-byte signature, base64 in ``immunity-feed.json.sig``). A bad or missing
signature means the feed is refused; no way to check means it is used but
marked unverified -- never a crash.
"""
from __future__ import annotations

import base64
import json
import logging
import shutil
import subprocess
from pathlib import Path

import pytest

pytest.importorskip("cryptography")
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from prismor.runtime import feed as feed_mod  # noqa: E402
from prismor.runtime import feed_signature as fs  # noqa: E402

REPO = Path(__file__).resolve().parents[1]
FEED = {"version": "9.9.9", "advisories": [
    {"id": "T-1", "type": "dependency_vulnerability", "severity": "high"},
    {"id": "T-2", "type": "prompt_injection", "severity": "critical"},
]}


def _openssl_can_ed25519() -> bool:
    if not shutil.which("openssl"):
        return False
    out = subprocess.run(["openssl", "version"], capture_output=True, text=True)
    return out.stdout.startswith("OpenSSL 3")


@pytest.fixture
def home(tmp_path, monkeypatch):
    """A $PRISMOR_HOME data root holding a feed signed by a throwaway key."""
    key = Ed25519PrivateKey.generate()
    (tmp_path / "keys").mkdir()
    (tmp_path / "keys" / "public.pub").write_bytes(key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    (tmp_path / "advisories").mkdir()
    feed = tmp_path / "advisories" / "immunity-feed.json"
    feed.write_text(json.dumps(FEED, indent=2), encoding="utf-8")
    (tmp_path / "advisories" / "immunity-feed.json.sig").write_bytes(
        base64.b64encode(key.sign(feed.read_bytes())) + b"\n")
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path))
    monkeypatch.delenv("PRISMOR_FEED_ALLOW_UNSIGNED", raising=False)
    monkeypatch.setattr(feed_mod, "_WARNED", set())
    monkeypatch.setattr(fs, "_MEMO", {})
    return tmp_path


def _feed(home: Path) -> Path:
    return home / "advisories" / "immunity-feed.json"


def _tamper(home: Path) -> None:
    data = json.loads(_feed(home).read_text())
    data["advisories"].pop()
    _feed(home).write_text(json.dumps(data, indent=2), encoding="utf-8")


# ── the shipped feed ────────────────────────────────────────────────────

def test_shipped_feed_verifies_with_cryptography(monkeypatch):
    monkeypatch.setattr(fs, "_BACKENDS", (fs._verify_cryptography,))
    result = fs.verify_feed_file(REPO / "advisories" / "immunity-feed.json",
                                 pub_path=REPO / "keys" / "public.pub", use_cache=False)
    assert result.status == fs.VERIFIED and result.backend == "cryptography"


@pytest.mark.skipif(not _openssl_can_ed25519(), reason="needs OpenSSL 3.x")
def test_shipped_feed_verifies_with_openssl(monkeypatch):
    monkeypatch.setattr(fs, "_BACKENDS", (fs._verify_openssl,))
    result = fs.verify_feed_file(REPO / "advisories" / "immunity-feed.json",
                                 pub_path=REPO / "keys" / "public.pub", use_cache=False)
    assert result.status == fs.VERIFIED and result.backend == "openssl"


# ── load_feed outcomes ──────────────────────────────────────────────────

def test_valid_signature_loads_feed(home):
    feed = feed_mod.load_feed()
    assert feed["_signature"]["status"] == fs.VERIFIED
    assert feed["_signature"]["trusted"] is True
    assert [a["id"] for a in feed["advisories"]] == ["T-1", "T-2"]


def test_tampered_feed_is_refused(home, caplog):
    _tamper(home)
    with caplog.at_level(logging.WARNING, logger="prismor.feed"):
        feed = feed_mod.load_feed()
    assert feed["advisories"] == []
    assert feed["_signature"]["status"] == fs.MISMATCH
    assert feed["_signature"]["trusted"] is False
    assert "refusing" in caplog.text
    # Downstream consumers see no advisories rather than forged ones.
    assert feed_mod.match_advisories([{"category": "prompt_injection"}], feed) == []


def test_missing_signature_is_refused(home, caplog):
    (home / "advisories" / "immunity-feed.json.sig").unlink()
    with caplog.at_level(logging.WARNING, logger="prismor.feed"):
        feed = feed_mod.load_feed()
    assert feed["advisories"] == []
    assert feed["_signature"]["status"] == fs.MISSING
    assert "refusing" in caplog.text


def test_missing_signature_allowed_by_opt_in(home, monkeypatch):
    (home / "advisories" / "immunity-feed.json.sig").unlink()
    monkeypatch.setenv("PRISMOR_FEED_ALLOW_UNSIGNED", "1")
    feed = feed_mod.load_feed()
    assert len(feed["advisories"]) == 2
    assert feed["_signature"]["trusted"] is False


def test_garbled_signature_is_refused(home):
    (home / "advisories" / "immunity-feed.json.sig").write_text("not base64!!\n")
    feed = feed_mod.load_feed()
    assert feed["advisories"] == []
    assert feed["_signature"]["status"] == fs.MISSING


def test_no_crypto_backend_uses_feed_unverified(home, monkeypatch, caplog):
    monkeypatch.setattr(fs, "_BACKENDS", ())
    with caplog.at_level(logging.WARNING, logger="prismor.feed"):
        feed = feed_mod.load_feed()
    assert len(feed["advisories"]) == 2
    assert feed["_signature"]["status"] == fs.UNAVAILABLE
    assert feed["_signature"]["trusted"] is False
    assert "unverified" in caplog.text


def test_cryptography_missing_falls_back_to_openssl(home, monkeypatch):
    real_import = __import__

    def fake_import(name, *args, **kwargs):
        if name.startswith("cryptography"):
            raise ImportError(name)
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr("builtins.__import__", fake_import)
    result = fs.verify_feed_file(_feed(home), use_cache=False)
    if _openssl_can_ed25519():
        assert (result.status, result.backend) == (fs.VERIFIED, "openssl")
    else:
        assert result.status == fs.UNAVAILABLE


@pytest.mark.skipif(not _openssl_can_ed25519(), reason="needs OpenSSL 3.x")
def test_openssl_detects_tampering(home, monkeypatch):
    monkeypatch.setattr(fs, "_BACKENDS", (fs._verify_openssl,))
    _tamper(home)
    assert fs.verify_feed_file(_feed(home), use_cache=False).status == fs.MISMATCH


def test_openssl_that_cannot_check_is_not_a_mismatch(home, monkeypatch):
    # LibreSSL: non-zero exit without the rejection line.
    monkeypatch.setattr(fs, "_BACKENDS", (fs._verify_openssl,))
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(
        a, 1, b"", b"pkeyutl: Unknown option: -rawin\n"))
    assert fs.verify_feed_file(_feed(home), use_cache=False).status == fs.UNAVAILABLE


def test_openssl_absent_is_unavailable(home, monkeypatch):
    monkeypatch.setattr(fs, "_BACKENDS", (fs._verify_openssl,))

    def boom(*a, **k):
        raise FileNotFoundError("openssl")

    monkeypatch.setattr(subprocess, "run", boom)
    assert fs.verify_feed_file(_feed(home), use_cache=False).status == fs.UNAVAILABLE


# ── caching ─────────────────────────────────────────────────────────────

def test_result_cached_on_disk_and_invalidated_by_tampering(home, monkeypatch):
    calls = []

    def counting(data, sig, pub):
        calls.append(1)
        return fs._verify_cryptography(data, sig, pub)

    monkeypatch.setattr(fs, "_BACKENDS", (counting,))
    assert feed_mod.load_feed()["_signature"]["status"] == fs.VERIFIED
    assert (home / "cache" / "feed-signature.json").exists()

    # A new process: memo gone, disk cache still answers without crypto.
    monkeypatch.setattr(fs, "_MEMO", {})
    assert feed_mod.load_feed()["_signature"]["status"] == fs.VERIFIED
    assert len(calls) == 1

    _tamper(home)
    assert feed_mod.load_feed()["advisories"] == []
    assert len(calls) == 2


def test_unavailable_result_is_not_cached(home, monkeypatch):
    monkeypatch.setattr(fs, "_BACKENDS", ())
    feed_mod.load_feed()
    assert not (home / "cache" / "feed-signature.json").exists()
    monkeypatch.setattr(fs, "_BACKENDS", (fs._verify_cryptography,))
    assert feed_mod.load_feed()["_signature"]["status"] == fs.VERIFIED


def test_forged_cache_for_other_content_is_ignored(home):
    (home / "cache").mkdir()
    (home / "cache" / "feed-signature.json").write_text(json.dumps(
        {"v": 1, "key": "0" * 64, "status": "verified", "backend": "cryptography"}))
    _tamper(home)
    assert feed_mod.load_feed()["advisories"] == []


# ── audit uses the same helper ──────────────────────────────────────────

def test_audit_reports_tampering(home):
    from prismor.runtime.audit import _check_feed_signature
    assert _check_feed_signature(home)[0].severity == "PASS"
    _tamper(home)
    assert _check_feed_signature(home)[0].severity == "CRITICAL"
