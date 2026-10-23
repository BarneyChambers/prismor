"""Minimal semver range parsing for advisory matching.

Only handles the forms we actually see in package.json and feed advisories:
exact pins, caret/tilde, comparison operators, and full-floating wildcards.
No full SemVer 2.0 compliance — pre-release tags are stripped.
"""
from __future__ import annotations

import re
from typing import Optional, Tuple

Version = Tuple[int, int, int]
Bound = Optional[Version]
Range = Tuple[Bound, Bound]  # (min_inclusive, max_exclusive)
_EMPTY: Range = ((0, 0, 0), (0, 0, 0))  # unparseable bound: matches nothing

_VERSION_RE = re.compile(r"v?(\d+)(?:\.(\d+))?(?:\.(\d+))?")


def parse_version(spec: str) -> Optional[Version]:
    """Extract (major, minor, patch) from a version string. Returns None if unparseable."""
    if not spec:
        return None
    text = spec.strip()
    match = _VERSION_RE.match(text)
    if not match:
        return None
    # `1.2.x` is a wildcard, not the pin 1.2.0. A prefix match used to stop
    # before the x and invent a patch of 0.
    rest = text[match.end():]
    if rest.startswith(".") and rest[1:2] in ("x", "X", "*"):
        return None
    return (
        int(match.group(1)),
        int(match.group(2) or 0),
        int(match.group(3) or 0),
    )


def parse_npm_range(spec: str) -> Range:
    """Parse an npm-style version range into (min_inclusive, max_exclusive).

    None means unbounded on that side. (None, None) signals full-floating —
    every version satisfies the range.
    """
    if not spec:
        return (None, None)
    s = spec.strip()
    if s in ("*", "x", "latest", ""):
        return (None, None)
    if s.startswith("^"):
        v = parse_version(s[1:])
        if v is None:
            return _EMPTY
        return (v, (v[0] + 1, 0, 0))
    if s.startswith("~"):
        v = parse_version(s[1:])
        if v is None:
            return _EMPTY
        return (v, (v[0], v[1] + 1, 0))
    if s.startswith(">="):
        v = parse_version(s[2:])
        return (v, None) if v else _EMPTY
    if s.startswith(">"):
        v = parse_version(s[1:])
        # Inclusive lower-bound is fine for risk-purposes — slight over-match acceptable.
        return (v, None) if v else _EMPTY
    if s.startswith("<="):
        v = parse_version(s[2:].split("||")[0])
        if v is None:
            return _EMPTY
        return (None, (v[0], v[1], v[2] + 1))
    if s.startswith("<"):
        v = parse_version(s[1:].split("||")[0])
        return (None, v) if v else _EMPTY
    if s.startswith("="):
        v = parse_version(s[1:])
        return (v, (v[0], v[1], v[2] + 1)) if v else _EMPTY
    wild = re.fullmatch(r"v?(\d+)\.(\d+)\.[xX*]", s)
    if wild:
        major, minor = int(wild.group(1)), int(wild.group(2))
        return ((major, minor, 0), (major, minor + 1, 0))
    v = parse_version(s)
    if v is None:
        return _EMPTY
    return (v, (v[0], v[1], v[2] + 1))


def version_satisfies(version: Version, spec: str) -> bool:
    """True if ``version`` matches any ``||`` branch of an npm range."""
    branches = [part.strip() for part in (spec or "").split("||")]
    return any(version_in_range(version, *parse_npm_range(part)) for part in branches if part)


def version_in_range(version: Version, lo: Bound, hi: Bound) -> bool:
    """Return True if lo <= version < hi (None ends unbounded)."""
    if lo is not None and version < lo:
        return False
    if hi is not None and version >= hi:
        return False
    return True


def ranges_overlap(a: Range, b: Range) -> bool:
    """Return True if two ranges share any version."""
    a_lo, a_hi = a
    b_lo, b_hi = b
    if a_hi is not None and b_lo is not None and a_hi <= b_lo:
        return False
    if b_hi is not None and a_lo is not None and b_hi <= a_lo:
        return False
    return True


def is_floating(spec: str) -> bool:
    """True if the version spec could resolve to multiple concrete versions."""
    if not spec:
        return True
    s = spec.strip()
    if not s or s in ("*", "x", "latest"):
        return True
    return s[0] in "^~><="
