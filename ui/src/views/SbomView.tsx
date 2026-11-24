// CycloneDX component list for the run, searchable.
import { useEffect, useState } from "react";
import { api, type SbomView as SbomData } from "../api";
import { Card, Chip, Empty, RiskBadge, Stat } from "../ui";

const PAGE = 50;

export function SbomView({ run }: { run: string }) {
  const [q, setQ] = useState("");
  const [query, setQuery] = useState("");
  const [type, setType] = useState("");
  const [ecosystem, setEcosystem] = useState("");
  const [vulnerable, setVulnerable] = useState(false);
  const [offset, setOffset] = useState(0);
  const [data, setData] = useState<SbomData | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    const id = setTimeout(() => { setQuery(q); setOffset(0); }, 300);
    return () => clearTimeout(id);
  }, [q]);

  useEffect(() => {
    setError("");
    api.sbom(run, { q: query || undefined, type: type || undefined, ecosystem: ecosystem || undefined, vulnerable, limit: PAGE, offset })
      .then(setData)
      .catch((e: Error) => setError(e.message));
  }, [run, query, type, ecosystem, vulnerable, offset]);

  if (error && !data) return <Empty title="No SBOM for this run" hint={error} />;
  if (!data) return <Empty title="Loading the SBOM…" />;
  const d = data.document;
  const licensed = Object.entries(data.summary.top_licenses).filter(([k]) => k !== "unspecified");
  return (
    <div className="space-y-3">
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <Stat label="Format" value={`${d.format ?? "?"} ${d.spec_version ?? ""}`} sub={d.tools.join(", ") || "tool unknown"} />
        <Stat label="Components" value={d.components} sub={`${d.dependency_records} dependency records`} />
        <Stat label="With findings" value={data.summary.with_findings} sub="components that carry at least one finding" />
        <div className="flex items-center justify-between rounded-lg border border-slate-200 bg-white px-3 py-2 shadow-sm">
          <div className="text-xs text-slate-500">
            <div>Subject: <span className="font-mono">{d.subject ?? "—"}</span></div>
            <div>Generated {d.timestamp ?? "—"}</div>
            <div className="break-all">{d.serial_number}</div>
          </div>
        </div>
      </div>

      <Card
        title="Composition"
        right={
          <a href={api.sbomDownloadUrl(run)} download className="rounded bg-slate-900 px-3 py-1 text-xs text-white">
            Download CycloneDX JSON
          </a>
        }
      >
        <div className="flex flex-wrap gap-x-6 gap-y-1 text-xs text-slate-600">
          <div>types: {Object.entries(data.summary.by_type).map(([k, v]) => <Chip key={k}>{k} {v}</Chip>)}</div>
          <div>ecosystems: {Object.entries(data.summary.by_ecosystem).map(([k, v]) => <Chip key={k} tone="info">{k} {v}</Chip>)}</div>
          <div>
            licenses: {licensed.length ? licensed.map(([k, v]) => <Chip key={k} tone="good">{k} {v}</Chip>) : "none recorded"}
            {data.summary.top_licenses.unspecified ? <Chip tone="warn">unspecified {data.summary.top_licenses.unspecified}</Chip> : null}
          </div>
        </div>
        <p className="mt-1 text-[11px] text-slate-400">
          Licenses appear only when the SBOM source recorded them; Syft's lockfile scan usually does not.
        </p>
      </Card>

      <div className="flex flex-wrap items-center gap-2 text-sm">
        <input aria-label="Search components" placeholder="Search name or purl…" value={q} onChange={(e) => setQ(e.target.value)} maxLength={80} className="w-64 rounded border border-slate-300 px-2 py-1" />
        <select aria-label="Type" value={type} onChange={(e) => { setType(e.target.value); setOffset(0); }} className="rounded border border-slate-300 bg-white px-2 py-1">
          <option value="">All types</option>
          {Object.keys(data.summary.by_type).map((t) => <option key={t} value={t}>{t}</option>)}
        </select>
        <select aria-label="Ecosystem" value={ecosystem} onChange={(e) => { setEcosystem(e.target.value); setOffset(0); }} className="rounded border border-slate-300 bg-white px-2 py-1">
          <option value="">All ecosystems</option>
          {Object.keys(data.summary.by_ecosystem).map((t) => <option key={t} value={t}>{t}</option>)}
        </select>
        <label className="flex items-center gap-1"><input type="checkbox" checked={vulnerable} onChange={(e) => { setVulnerable(e.target.checked); setOffset(0); }} /> only components with findings</label>
        <span className="ml-auto text-xs text-slate-500">{data.total} components</span>
      </div>

      <div className="overflow-x-auto rounded-lg border border-slate-200 bg-white">
        <table className="w-full text-left text-xs">
          <thead className="border-b border-slate-200 bg-slate-50 text-slate-600">
            <tr>
              <th className="px-2 py-1.5">Risk</th><th className="px-2">Component</th><th className="px-2">Type</th>
              <th className="px-2">Ecosystem</th><th className="px-2">License</th><th className="px-2">Package URL</th>
              <th className="px-2">Found by</th><th className="px-2 text-right">Findings</th>
            </tr>
          </thead>
          <tbody>
            {data.items.map((c, i) => (
              <tr key={`${c.bom_ref}-${i}`} className="border-b border-slate-100 align-top hover:bg-slate-50">
                <td className="px-2 py-1">{c.risk === "None" ? <span className="text-slate-300">—</span> : <RiskBadge level={c.risk} />}</td>
                <td className="px-2 py-1 font-mono">{c.label}</td>
                <td className="px-2 py-1">{c.type}</td>
                <td className="px-2 py-1">{c.ecosystem ?? "—"}</td>
                <td className="px-2 py-1">{c.licenses.join(", ") || <span className="text-slate-300">—</span>}</td>
                <td className="max-w-[18rem] break-all px-2 py-1 font-mono text-[11px] text-slate-500">{c.purl ?? "—"}</td>
                <td className="px-2 py-1 text-slate-500">{c.found_by ?? "—"}<div className="break-all text-[11px] text-slate-400">{c.location}</div></td>
                <td className="px-2 py-1 text-right">{c.findings || ""}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="flex items-center justify-between text-xs text-slate-600">
        <span>{data.total === 0 ? "0" : `${offset + 1}–${Math.min(offset + PAGE, data.total)}`} of {data.total}</span>
        <span className="space-x-2">
          <button type="button" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE))} className="rounded border border-slate-300 bg-white px-2 py-1 disabled:opacity-40">Previous</button>
          <button type="button" disabled={offset + PAGE >= data.total} onClick={() => setOffset(offset + PAGE)} className="rounded border border-slate-300 bg-white px-2 py-1 disabled:opacity-40">Next</button>
        </span>
      </div>
    </div>
  );
}
