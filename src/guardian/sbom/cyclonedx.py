"""CycloneDX 1.5 JSON reader and the cross-check against the lockfile graph."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from guardian.schemas.graph import DependencyGraph
from guardian.schemas.sbom import SBOM_FORMAT, SBOM_SPEC_VERSION, DependencyScope


class SbomError(ValueError):
    """Raised when the SBOM is invalid or does not match the expected format."""
    pass


@dataclass(frozen=True)
class CdxComponent:
    """Represents a component from a CycloneDX BOM."""
    bom_ref: str
    type: str
    name: str
    version: str | None
    purl: str | None
    found_by: str | None
    location: str | None


@dataclass(frozen=True)
class CdxBom:
    """Stores parsed CycloneDX BOM metadata, components, and dependencies."""
    spec_version: str
    serial_number: str | None
    components: tuple[CdxComponent, ...]
    dependencies: dict[str, tuple[str, ...]]

    def by_purl_type(self, purl_type: str) -> tuple[CdxComponent, ...]:
        """Return components matching the given package URL type."""
        prefix = f"pkg:{purl_type}/"
        return tuple(c for c in self.components if (c.purl or "").startswith(prefix))


def load_bom(path: Path) -> CdxBom:
    """Load and validate a CycloneDX 1.5 JSON BOM."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SbomError(f"{path.name}: invalid JSON: {exc}") from exc

    # Validate the BOM format and specification version.
    if data.get("bomFormat") != SBOM_FORMAT or data.get("specVersion") != SBOM_SPEC_VERSION:
        raise SbomError(
            f"{path.name}: expected {SBOM_FORMAT} {SBOM_SPEC_VERSION}, got "
            f"{data.get('bomFormat')!r} {data.get('specVersion')!r}"
        )

    # Extract components and relevant Syft properties.
    components = []
    for raw in data.get("components", []):
        props = {p.get("name"): p.get("value") for p in raw.get("properties", [])}
        components.append(
            CdxComponent(
                bom_ref=raw["bom-ref"],
                type=raw.get("type", ""),
                name=raw.get("name", ""),
                version=raw.get("version"),
                purl=raw.get("purl"),
                found_by=props.get("syft:package:foundBy"),
                location=props.get("syft:location:0:path"),
            )
        )

    # Validate dependency references against known component references.
    refs = {c.bom_ref for c in components}
    root_ref = (data.get("metadata", {}).get("component") or {}).get("bom-ref")
    dependencies: dict[str, tuple[str, ...]] = {}
    for dep in data.get("dependencies", []):
        targets = tuple(dep.get("dependsOn", []))
        dangling = ({dep["ref"], *targets} - refs) - {root_ref}
        if dangling:
            raise SbomError(f"{path.name}: dependency refs not in components: {sorted(dangling)}")
        dependencies[dep["ref"]] = targets

    return CdxBom(
        spec_version=data["specVersion"],
        serial_number=data.get("serialNumber"),
        components=tuple(components),
        dependencies=dependencies,
    )


@dataclass(frozen=True)
class CrossCheck:
    """Stores differences between runtime lockfile packages and SBOM npm packages."""

    graph_runtime: int
    sbom_npm: int
    only_in_graph: tuple[str, ...]
    only_in_sbom: tuple[str, ...]

    @property
    def agrees(self) -> bool:
        """Return True when both package sets match."""
        return not self.only_in_graph and not self.only_in_sbom


def cross_check(graph: DependencyGraph, bom: CdxBom) -> CrossCheck:
    """Compare runtime lockfile packages with SBOM npm packages by name and version."""
    graph_set = {graph.label(n.bom_ref) for n in graph.nodes if n.scope is not DependencyScope.DEV}
    sbom_set = {f"{c.name}@{c.version}" if c.version else c.name for c in bom.by_purl_type("npm")}
    return CrossCheck(
        graph_runtime=len(graph_set),
        sbom_npm=len(sbom_set),
        only_in_graph=tuple(sorted(graph_set - sbom_set)),
        only_in_sbom=tuple(sorted(sbom_set - graph_set)),
    )
