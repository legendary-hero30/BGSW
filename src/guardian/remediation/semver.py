"""Just enough semantic versioning to choose a fix version. npm ranges are not parsed here:
only exact versions that tools reported are compared."""

from __future__ import annotations

import re
from dataclasses import dataclass

VERSION = re.compile(
    r"(?<![\w.])v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?(?![\w])"
)


@dataclass(frozen=True, order=False)
class Version:
    major: int
    minor: int
    patch: int
    pre: str | None = None

    def key(self) -> tuple:
        # A prerelease sorts before its release: 1.0.0-rc.1 < 1.0.0.
        return (self.major, self.minor, self.patch, self.pre is None, self.pre or "")

    def __lt__(self, other: Version) -> bool:
        return self.key() < other.key()

    def __le__(self, other: Version) -> bool:
        return self.key() <= other.key()

    def __str__(self) -> str:
        return f"{self.major}.{self.minor}.{self.patch}" + (f"-{self.pre}" if self.pre else "")


def parse(text: str) -> Version | None:
    m = VERSION.search(text.strip())
    if not m:
        return None
    return Version(int(m[1]), int(m[2]), int(m[3]), m[4])


def find_all(text: str) -> list[Version]:
    return [Version(int(m[1]), int(m[2]), int(m[3]), m[4]) for m in VERSION.finditer(text)]


def change_kind(current: Version, target: Version) -> str:
    """'major', 'minor', 'patch' or 'none' (and 'downgrade' if target is older)."""
    if target.key() < current.key():
        return "downgrade"
    if target.major != current.major:
        return "major"
    if target.minor != current.minor:
        return "minor"
    if target.patch != current.patch or target.pre != current.pre:
        return "patch"
    return "none"
