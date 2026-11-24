// Pass/fail checklist of the run's requirements, each with its evidence.
import { useEffect, useState } from "react";
import { api, type Checklist } from "../api";
import { Chip, Empty } from "../ui";

const TONE = { pass: "good", fail: "bad", "n/a": "neutral" } as const;

export function ChecklistView({ run }: { run: string }) {
  const [data, setData] = useState<Checklist | null>(null);
  const [error, setError] = useState("");
  useEffect(() => {
    setData(null);
    api.checklist(run).then(setData).catch((e: Error) => setError(e.message));
  }, [run]);
  if (error) return <Empty title="Could not evaluate the checklist" hint={error} />;
  if (!data) return <Empty title="Evaluating the checklist against the stored artifacts…" />;
  return (
    <div className="mx-auto max-w-4xl">
      <p className="mb-2 text-sm text-slate-600">
        The Day 1 judging checklist, decided from this run's stored artifacts: {data.counts.pass} pass, {data.counts.fail} fail, {data["counts"]["n/a"] ?? 0} not applicable.
      </p>
      <ul className="divide-y divide-slate-100 rounded-lg border border-slate-200 bg-white">
        {data.items.map((i) => (
          <li key={i.n} className="flex gap-3 p-3">
            <span className="w-6 text-right text-sm text-slate-400">{i.n}</span>
            <div>
              <div className="flex items-center gap-2 text-sm font-medium"><Chip tone={TONE[i.status]}>{i.status}</Chip>{i.text}</div>
              <div className="mt-0.5 text-xs text-slate-500">{i.evidence}</div>
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
}
