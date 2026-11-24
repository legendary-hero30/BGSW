// The agent's accepted report with the evidence it cites.
import { useEffect, useState } from "react";
import { api } from "../api";
import { Markdown } from "../markdown";
import { Empty } from "../ui";

export function ReportView({ run }: { run: string }) {
  const [md, setMd] = useState<string | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    setMd(null);
    setError("");
    api.agentReport(run).then((r) => setMd(r.markdown)).catch((e: Error) => setError(e.message));
  }, [run]);

  if (error) return <Empty title="No agent report for this run" hint="The agents have not produced one, or this run used the scanner-only baseline." />;
  if (md === null) return <Empty title="Loading the report…" />;
  const partial = md.startsWith("# Guardian report (PARTIAL");
  function download() {
    const url = URL.createObjectURL(new Blob([md ?? ""], { type: "text/markdown" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = `${run.split("/").pop() ?? "guardian"}-report.md`;
    a.click();
    URL.revokeObjectURL(url);
  }
  return (
    <div className="mx-auto max-w-4xl">
      {partial && (
        <div className="mb-3 rounded-lg border border-amber-300 bg-amber-50 p-3 text-sm text-amber-900">
          This is a <b>partial</b> report. The run stopped before the agents produced an accepted report, so only facts recorded by the
          deterministic tools are shown; there is no model-written analysis.
        </div>
      )}
      <div className="mb-2 flex justify-end">
        <button type="button" onClick={download} className="rounded border border-slate-300 bg-white px-3 py-1 text-xs">Download Markdown</button>
      </div>
      <article className="rounded-lg border border-slate-200 bg-white p-5 shadow-sm">
        <Markdown source={md} />
      </article>
    </div>
  );
}
