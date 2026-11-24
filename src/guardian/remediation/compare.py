"""Compare two lockfiles and report raw facts (Day 2: "investigate suspicious changes").

Output is verified fact only: what was added, removed or changed, and which provenance signals
moved (integrity hash, resolved host, install-script flag). It makes no judgement; an agent may
reason about it, and that reasoning is labelled inference elsewhere.
"""

from __future__ import annotations

from urllib.parse import urlparse

from guardian.sbom.npm_lock import LockEntry


def _host(url: str | None) -> str | None:
    return (urlparse(url).hostname or None) if url else None


def _by_name(entries: dict[str, LockEntry]) -> dict[str, list[LockEntry]]:
    out: dict[str, list[LockEntry]] = {}
    for path, e in entries.items():
        if path:
            out.setdefault(e.name, []).append(e)
    return out


def compare_lockfiles(
    base: dict[str, LockEntry], head: dict[str, LockEntry], limit: int = 40
) -> dict:
    b, h = _by_name(base), _by_name(head)
    added = sorted(set(h) - set(b))
    removed = sorted(set(b) - set(h))
    changed = []
    for name in sorted(set(b) & set(h)):
        old = {e.version for e in b[name]}
        new = {e.version for e in h[name]}
        be, he = b[name][0], h[name][0]
        signals = []
        if old == new and (be.integrity != he.integrity):
            signals.append("integrity hash changed with the same version")
        if _host(be.resolved) != _host(he.resolved):
            signals.append(f"resolved host {_host(be.resolved)} -> {_host(he.resolved)}")
        if not be.has_install_script and he.has_install_script:
            signals.append("install script appeared")
        if (be.integrity or "").split("-")[0] != (he.integrity or "").split("-")[0]:
            signals.append("integrity algorithm changed")
        if old != new or signals:
            changed.append(
                {"package": name, "from": sorted(old), "to": sorted(new), "signals": signals}
            )
    suspicious = [c for c in changed if c["signals"]]
    new_with_script = [n for n in added if any(e.has_install_script for e in h[n])]
    off_registry = [
        n for n in added if any(_host(e.resolved) not in {"registry.npmjs.org", None} for e in h[n])
    ]
    return {
        "counts": {"base": len(b), "head": len(h), "added": len(added), "removed": len(removed),
                   "changed": len(changed), "with_provenance_signals": len(suspicious)},
        "added": added[:limit],
        "removed": removed[:limit],
        "changed": changed[:limit],
        "provenance_signals": suspicious[:limit],
        "added_with_install_script": new_with_script[:limit],
        "added_from_non_registry_host": off_registry[:limit],
        "note": "Facts from two lockfiles. Signals are not verdicts.",
    }  # fmt: skip
