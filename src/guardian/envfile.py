"""Load settings from the repository's ``.env`` (git-ignored) into the process environment.

Only an allow-list of Guardian settings is read; anything else in the file is ignored. Values
already set in the environment win, so a shell export overrides the file. The loader never
prints values. No third-party dependency: the format is ``KEY=value`` lines, ``#`` comments,
optional single or double quotes.
"""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

ALLOWED = frozenset(
    {
        "DEEPINFRA_API_KEY",
        "GUARDIAN_ALLOW_EXTERNAL_MODELS",
        "GUARDIAN_ALLOW_REGISTRY_ACCESS",
        "GUARDIAN_ALLOW_PUSH",
        "GUARDIAN_GITHUB_TOKEN",
        "GUARDIAN_PRICE_IN_PER_M",
        "GUARDIAN_PRICE_OUT_PER_M",
        "GUARDIAN_SANDBOX_IMAGE",
    }
)
DEFAULT_PATH = Path(__file__).resolve().parents[2] / ".env"


def parse(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.removeprefix("export ").strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        elif " #" in value:
            value = value.split(" #", 1)[0].strip()
        if key in ALLOWED and value:
            out[key] = value
    return out


def load_env(path: Path | str = DEFAULT_PATH) -> list[str]:
    """Set allow-listed variables from ``path`` that are not already set. Returns their names."""
    p = Path(path)
    if not p.is_file():
        return []
    if p.stat().st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        print(
            f"warning: {p.name} is readable by other users; run: chmod 600 {p.name}",
            file=sys.stderr,
        )
    loaded = []
    for key, value in parse(p.read_text()).items():
        if key not in os.environ:
            os.environ[key] = value
            loaded.append(key)
    return loaded
