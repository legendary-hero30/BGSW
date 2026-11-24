import type { ReactNode } from "react";

// A small Markdown renderer for the agent's report. It builds React elements directly, so
// nothing is ever injected as HTML. Links are shown only for http(s) URLs.

const INLINE = /(`[^`\n]+`|\*\*[^*\n]+\*\*|\[[^\]\n]+\]\(https?:\/\/[^)\s]+\))/g;

function inline(text: string, key: string): ReactNode[] {
  return text.split(INLINE).map((part, i) => {
    const k = `${key}-${i}`;
    if (part.startsWith("`") && part.endsWith("`") && part.length > 1)
      return <code key={k} className="rounded bg-slate-100 px-1 py-0.5 text-[0.85em]">{part.slice(1, -1)}</code>;
    if (part.startsWith("**") && part.endsWith("**") && part.length > 4)
      return <strong key={k}>{inline(part.slice(2, -2), k)}</strong>;
    const link = /^\[([^\]]+)\]\((https?:\/\/[^)\s]+)\)$/.exec(part);
    if (link)
      return (
        <a key={k} href={link[2]} target="_blank" rel="noopener noreferrer" className="text-blue-700 underline">
          {link[1]}
        </a>
      );
    return part;
  });
}

function cells(line: string): string[] {
  return line.trim().replace(/^\|/, "").replace(/\|$/, "").split("|").map((c) => c.trim());
}

export function Markdown({ source }: { source: string }) {
  const lines = source.split("\n");
  const out: ReactNode[] = [];
  let i = 0;
  let n = 0;
  const next = () => `b${n++}`;

  while (i < lines.length) {
    const line = lines[i] ?? "";
    if (line.trim() === "") {
      i++;
      continue;
    }
    if (line.startsWith("```")) {
      const body: string[] = [];
      i++;
      while (i < lines.length && !(lines[i] ?? "").startsWith("```")) body.push(lines[i++] ?? "");
      i++;
      out.push(<pre key={next()} className="my-2 overflow-x-auto rounded bg-slate-900 p-3 text-xs text-slate-100">{body.join("\n")}</pre>);
      continue;
    }
    const heading = /^(#{1,4})\s+(.*)$/.exec(line);
    if (heading) {
      const level = (heading[1] ?? "#").length;
      const cls = ["text-xl font-bold mt-4 mb-2", "text-lg font-semibold mt-4 mb-1.5", "text-base font-semibold mt-3 mb-1", "text-sm font-semibold mt-2 mb-1"][level - 1];
      out.push(<div key={next()} role="heading" aria-level={level} className={cls}>{inline(heading[2] ?? "", `h${n}`)}</div>);
      i++;
      continue;
    }
    if (/^---+\s*$/.test(line)) {
      out.push(<hr key={next()} className="my-4 border-slate-200" />);
      i++;
      continue;
    }
    if (line.trim().startsWith("|") && /^\s*\|?\s*:?-{3,}/.test(lines[i + 1] ?? "")) {
      const head = cells(line);
      i += 2;
      const rows: string[][] = [];
      while (i < lines.length && (lines[i] ?? "").trim().startsWith("|")) rows.push(cells(lines[i++] ?? ""));
      const key = next();
      out.push(
        <div key={key} className="my-2 overflow-x-auto">
          <table className="w-full border-collapse text-xs">
            <thead>
              <tr>{head.map((h, c) => <th key={c} className="border-b border-slate-300 px-2 py-1 text-left font-semibold">{inline(h, `${key}h${c}`)}</th>)}</tr>
            </thead>
            <tbody>
              {rows.map((r, ri) => (
                <tr key={ri} className="border-b border-slate-100 align-top">
                  {r.map((c, ci) => <td key={ci} className="px-2 py-1">{inline(c, `${key}r${ri}c${ci}`)}</td>)}
                </tr>
              ))}
            </tbody>
          </table>
        </div>,
      );
      continue;
    }
    const bullet = /^\s*([-*]|\d+\.)\s+(.*)$/.exec(line);
    if (bullet) {
      const ordered = /\d/.test(bullet[1] ?? "");
      const items: string[] = [];
      while (i < lines.length) {
        const m = /^\s*([-*]|\d+\.)\s+(.*)$/.exec(lines[i] ?? "");
        if (!m) break;
        items.push(m[2] ?? "");
        i++;
      }
      const key = next();
      const children = items.map((t, k) => <li key={k} className="my-0.5">{inline(t, `${key}i${k}`)}</li>);
      out.push(ordered ? <ol key={key} className="my-2 list-decimal pl-6">{children}</ol> : <ul key={key} className="my-2 list-disc pl-6">{children}</ul>);
      continue;
    }
    const para: string[] = [];
    while (i < lines.length && (lines[i] ?? "").trim() !== "" && !/^(#{1,4}\s|```|---+\s*$|\s*([-*]|\d+\.)\s)/.test(lines[i] ?? "")) para.push(lines[i++] ?? "");
    out.push(<p key={next()} className="my-2 leading-relaxed">{inline(para.join(" "), `p${n}`)}</p>);
  }
  return <div className="text-sm text-slate-800">{out}</div>;
}
