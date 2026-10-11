"""Ed25519 verification of the signed advisory feed.

``pipeline/sign_feed.sh`` signs ``advisories/immunity-feed.json`` with the
Ed25519 private key (``openssl pkeyutl -sign -rawin``) and writes the raw
signature, base64-encoded, to ``immunity-feed.json.sig``. ``keys/public.pub``
is the matching PEM public key. This module is the single place that checks
that signature; ``feed.load_feed``, ``prismor audit`` and the setup wizard all
go through it.

Backends, in order: the ``cryptography`` package (the ``signing`` extra, also
used for receipts), then the ``openssl`` CLI. Neither is guaranteed: Windows
ships no openssl and macOS ships LibreSSL, which cannot do Ed25519 ``-rawin``.
"Could not check" is reported as :data:`UNAVAILABLE`, never as a mismatch --
only an explicit rejection is :data:`MISMATCH`.

Hooks load the feed on every tool call, and importing ``cryptography`` alone
costs tens of milliseconds, so definitive results are cached on disk keyed by
the SHA-256 of feed, signature and key bytes. A changed byte in any of them is
a cache miss and a fresh verification.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
from pathlib import Path
from typing import TYPE_CHECKING, Callable, Dict, NamedTuple, Optional, Tuple

if TYPE_CHECKING:  # subprocess/tempfile are imported lazily: hooks pay per call
    import subprocess

VERIFIED = "verified"
MISMATCH = "mismatch"          # a backend explicitly rejected the signature
MISSING = "missing"            # feed present, signature file absent/unreadable/garbled
UNAVAILABLE = "unavailable"    # no backend could answer (no key, no crypto, LibreSSL)

_CACHE_VERSION = 1
_DEFINITIVE = (VERIFIED, MISMATCH)


class SignatureResult(NamedTuple):
    status: str
    backend: Optional[str] = None
    detail: str = ""

    @property
    def ok(self) -> bool:
        return self.status == VERIFIED

    def as_dict(self) -> Dict[str, Optional[str]]:
        return {"status": self.status, "backend": self.backend, "detail": self.detail}


def is_signature_mismatch(result: "subprocess.CompletedProcess") -> bool:
    """Whether openssl actually rejected the signature.

    A non-zero exit is not enough. macOS ships LibreSSL, which cannot load an
    Ed25519 key and has no -rawin, so it exits non-zero for a feed that is
    perfectly intact. Only OpenSSL's explicit rejection line means tampering;
    anything else is a toolchain that could not answer the question.
    """
    output = b"".join(
        part for part in (result.stdout, result.stderr) if isinstance(part, bytes)
    ).decode("utf-8", "replace")
    return "signature verification failure" in output.lower()


# ── backends ────────────────────────────────────────────────────────────
# Each returns a SignatureResult, or None when the backend is not present.

def _verify_cryptography(data: bytes, sig: bytes, pub_pem: bytes) -> Optional[SignatureResult]:
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
    except ImportError:
        return None
    try:
        key = load_pem_public_key(pub_pem)
    except Exception as exc:  # malformed key: cannot answer
        return SignatureResult(UNAVAILABLE, "cryptography", f"unreadable public key: {exc}")
    if not isinstance(key, Ed25519PublicKey):
        return SignatureResult(UNAVAILABLE, "cryptography", "public key is not Ed25519")
    try:
        key.verify(sig, data)
    except InvalidSignature:
        return SignatureResult(MISMATCH, "cryptography", "signature does not match feed")
    return SignatureResult(VERIFIED, "cryptography")


def _verify_openssl(data: bytes, sig: bytes, pub_pem: bytes) -> Optional[SignatureResult]:
    import subprocess
    import tempfile
    tmpdir = tempfile.mkdtemp(prefix="prismor-feedsig-")
    try:
        paths = {}
        for name, blob in (("feed", data), ("sig", sig), ("pub", pub_pem)):
            p = Path(tmpdir) / name
            p.write_bytes(blob)
            paths[name] = str(p)
        try:
            result = subprocess.run(
                ["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", paths["pub"],
                 "-rawin", "-in", paths["feed"], "-sigfile", paths["sig"]],
                capture_output=True, timeout=15,
            )
        except (FileNotFoundError, PermissionError):
            return None
        except (OSError, subprocess.SubprocessError) as exc:
            return SignatureResult(UNAVAILABLE, "openssl", f"openssl failed to run: {exc}")
        if result.returncode == 0:
            return SignatureResult(VERIFIED, "openssl")
        if is_signature_mismatch(result):
            return SignatureResult(MISMATCH, "openssl", "signature does not match feed")
        return SignatureResult(
            UNAVAILABLE, "openssl",
            "openssl could not run the check (needs OpenSSL 3.x for Ed25519 with -rawin)",
        )
    finally:
        for child in Path(tmpdir).iterdir():
            try:
                child.unlink()
            except OSError:
                pass
        try:
            os.rmdir(tmpdir)
        except OSError:
            pass


Backend = Callable[[bytes, bytes, bytes], Optional[SignatureResult]]
_BACKENDS: Tuple[Backend, ...] = (_verify_cryptography, _verify_openssl)


def verify_bytes(data: bytes, sig_b64: bytes, pub_pem: bytes) -> SignatureResult:
    """Verify ``data`` against a base64 Ed25519 signature and a PEM public key."""
    try:
        sig = base64.b64decode(sig_b64.strip(), validate=True)
    except (binascii.Error, ValueError):
        return SignatureResult(MISSING, None, "signature file is not valid base64")
    if len(sig) != 64:
        return SignatureResult(MISSING, None, f"signature is {len(sig)} bytes, expected 64")

    fallback: Optional[SignatureResult] = None
    for backend in _BACKENDS:
        result = backend(data, sig, pub_pem)
        if result is None:
            continue
        if result.status in _DEFINITIVE:
            return result
        fallback = fallback or result
    return fallback or SignatureResult(
        UNAVAILABLE, None,
        "no Ed25519 backend (install prismor[signing] or OpenSSL 3.x)",
    )


# ── on-disk cache ───────────────────────────────────────────────────────

def _cache_path() -> Path:
    home = os.environ.get("PRISMOR_HOME") or str(Path.home() / ".prismor")
    return Path(home).expanduser() / "cache" / "feed-signature.json"


# In-process memo for long-lived processes (proxy, dashboard, test runs).
_MEMO: Dict[str, SignatureResult] = {}


def _cache_key(data: bytes, sig_b64: bytes, pub_pem: bytes) -> str:
    h = hashlib.sha256()
    for blob in (data, sig_b64, pub_pem):
        h.update(hashlib.sha256(blob).digest())
    return h.hexdigest()


def _cache_get(key: str) -> Optional[SignatureResult]:
    try:
        entry = json.loads(_cache_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(entry, dict) or entry.get("v") != _CACHE_VERSION or entry.get("key") != key:
        return None
    status = entry.get("status")
    if status not in _DEFINITIVE:
        return None
    return SignatureResult(status, entry.get("backend"), "cached")


def _cache_put(key: str, result: SignatureResult) -> None:
    if result.status not in _DEFINITIVE:
        return  # "could not check" may succeed once a backend is installed
    import tempfile
    path = _cache_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".feed-signature.")
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump({"v": _CACHE_VERSION, "key": key, "status": result.status,
                       "backend": result.backend}, handle)
        os.replace(tmp, path)
    except OSError:
        pass  # a read-only home just means no cache


def verify_feed_bytes(
    data: bytes,
    sig_path: Path,
    pub_path: Path,
    *,
    use_cache: bool = True,
) -> SignatureResult:
    """Verify already-read feed bytes against the signature and key on disk."""
    try:
        sig_b64 = Path(sig_path).read_bytes()
    except OSError:
        return SignatureResult(MISSING, None, f"signature file not found: {sig_path}")
    try:
        pub_pem = Path(pub_path).read_bytes()
    except OSError:
        return SignatureResult(UNAVAILABLE, None, f"public key not found: {pub_path}")

    if not use_cache:
        return verify_bytes(data, sig_b64, pub_pem)
    key = _cache_key(data, sig_b64, pub_pem)
    result = _MEMO.get(key) or _cache_get(key)
    if result is None:
        result = verify_bytes(data, sig_b64, pub_pem)
        _cache_put(key, result)
    if result.status in _DEFINITIVE:
        _MEMO[key] = result
    return result


def clear_cache() -> None:
    """Forget in-process and on-disk verification results."""
    _MEMO.clear()
    try:
        _cache_path().unlink()
    except OSError:
        pass


def verify_feed_file(
    feed_path: Path,
    sig_path: Optional[Path] = None,
    pub_path: Optional[Path] = None,
    *,
    use_cache: bool = True,
) -> SignatureResult:
    """Verify a feed file. ``sig_path`` defaults to ``<feed>.sig`` and
    ``pub_path`` to the bundled/checkout ``keys/public.pub``."""
    feed_path = Path(feed_path)
    if sig_path is None:
        sig_path = feed_path.with_name(feed_path.name + ".sig")
    if pub_path is None:
        from prismor.runtime.paths import public_key_path
        pub_path = public_key_path()
    data = feed_path.read_bytes()
    return verify_feed_bytes(data, sig_path, pub_path, use_cache=use_cache)
