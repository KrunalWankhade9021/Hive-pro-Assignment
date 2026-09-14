"use client";

import { useState } from "react";
import { Advisory } from "@/lib/types";

/** Render a small subset of markdown (headings, lists, bold, rules) readably.
 *  Kept deliberately minimal to avoid pulling in a markdown dependency. */
function renderMarkdown(md: string) {
  const blocks: JSX.Element[] = [];
  const lines = md.split("\n");
  let list: string[] = [];

  const bold = (text: string) =>
    text.split(/(\*\*[^*]+\*\*)/g).map((part, i) =>
      part.startsWith("**") && part.endsWith("**") ? (
        <strong key={i} className="font-semibold text-ink">
          {part.slice(2, -2)}
        </strong>
      ) : (
        <span key={i}>{part}</span>
      ),
    );

  const flushList = () => {
    if (list.length === 0) return;
    blocks.push(
      <ul key={`ul-${blocks.length}`} className="my-2 list-disc space-y-1 pl-5 text-muted">
        {list.map((item, i) => (
          <li key={i}>{bold(item)}</li>
        ))}
      </ul>,
    );
    list = [];
  };

  for (const raw of lines) {
    const line = raw.trimEnd();
    if (/^[-*]\s+/.test(line.trim())) {
      list.push(line.trim().replace(/^[-*]\s+/, ""));
      continue;
    }
    flushList();
    const t = line.trim();
    if (!t || t === "---") continue;
    if (t.startsWith("### ")) {
      blocks.push(
        <h4 key={blocks.length} className="mt-4 text-sm font-semibold text-ink">
          {t.slice(4)}
        </h4>,
      );
    } else if (t.startsWith("## ")) {
      blocks.push(
        <h3 key={blocks.length} className="mt-5 text-[11px] font-bold uppercase tracking-wider text-navy">
          {t.slice(3)}
        </h3>,
      );
    } else if (t.startsWith("# ")) {
      blocks.push(
        <h2 key={blocks.length} className="text-sm font-bold text-ink">
          {t.slice(2)}
        </h2>,
      );
    } else if (t.startsWith("*") && t.endsWith("*") && !t.startsWith("**")) {
      blocks.push(
        <p key={blocks.length} className="mt-2 text-xs italic text-muted/70">
          {t.replace(/^\*|\*$/g, "")}
        </p>,
      );
    } else {
      blocks.push(
        <p key={blocks.length} className="mt-2 leading-relaxed text-muted">
          {bold(t)}
        </p>,
      );
    }
  }
  flushList();
  return blocks;
}

export function AdvisoryPanel({ advisory }: { advisory: Advisory }) {
  const [open, setOpen] = useState(false);
  const ransomwareCount = advisory.campaigns.filter(
    (c) => c.ransomware && c.ransomware.toLowerCase().startsWith("yes"),
  ).length;

  return (
    <section className="mb-6 overflow-hidden rounded-md border border-line bg-card">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        className="flex w-full items-center justify-between gap-4 px-4 py-3 text-left transition hover:bg-paper"
      >
        <div>
          <div className="flex items-center gap-2">
            <span className="text-[10px] font-semibold uppercase tracking-wider text-sev-critical">
              MDR Advisory
            </span>
            <span className="text-[10px] uppercase tracking-wider text-muted">
              arrived this morning
            </span>
          </div>
          <p className="mt-1 text-sm text-ink">
            {ransomwareCount} active ransomware-associated campaign
            {ransomwareCount === 1 ? "" : "s"} targeting Gulf fintech: risk level HIGH
          </p>
        </div>
        <span className="flex-none text-[11px] font-medium uppercase tracking-wider text-muted">
          {open ? "Hide" : "Read"}
        </span>
      </button>

      {open && (
        <div className="border-t border-line px-4 py-4 text-sm">
          {renderMarkdown(advisory.raw_markdown)}
        </div>
      )}
    </section>
  );
}
