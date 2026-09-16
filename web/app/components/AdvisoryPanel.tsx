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
      <ul
        key={`ul-${blocks.length}`}
        className="my-2.5 list-disc space-y-1 pl-5 text-muted"
      >
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
        <h4
          key={blocks.length}
          className="mt-5 text-[14px] font-semibold text-ink"
        >
          {t.slice(4)}
        </h4>,
      );
    } else if (t.startsWith("## ")) {
      blocks.push(
        <h3
          key={blocks.length}
          className="mt-6 text-[12px] font-semibold text-signal"
        >
          {t.slice(3)}
        </h3>,
      );
    } else if (t.startsWith("# ")) {
      blocks.push(
        <h2 key={blocks.length} className="text-[15px] font-semibold text-ink">
          {t.slice(2)}
        </h2>,
      );
    } else if (t.startsWith("*") && t.endsWith("*") && !t.startsWith("**")) {
      blocks.push(
        <p key={blocks.length} className="mt-3 text-[12px] italic text-faint">
          {t.replace(/^\*|\*$/g, "")}
        </p>,
      );
    } else {
      blocks.push(
        <p key={blocks.length} className="mt-2.5 leading-relaxed text-muted">
          {bold(t)}
        </p>,
      );
    }
  }
  flushList();
  return blocks;
}

/**
 * The advisory that triggered the assessment, presented as the reason the rest
 * of the page exists rather than as an attachment to it. Set in serif: it is the
 * one human-written document here, everything below it is system output.
 */
export function AdvisoryPanel({ advisory }: { advisory: Advisory }) {
  const [open, setOpen] = useState(false);
  const ransomware = advisory.campaigns.filter(
    (c) => c.ransomware && c.ransomware.toLowerCase().startsWith("yes"),
  );

  return (
    <section
      className="overflow-hidden rounded-lg border border-l-2 border-line border-l-alarm bg-surface"
      aria-label="MDR threat advisory"
    >
      <div className="px-5 py-5 sm:px-6">
        <p className="text-[12px] text-muted">
          MDR advisory, received this morning
        </p>
        <h2 className="mt-2 max-w-2xl font-serif text-[21px] leading-snug text-ink">
          {ransomware.length} active ransomware-associated campaign
          {ransomware.length === 1 ? "" : "s"} are targeting fintech firms in
          the Gulf, with confirmed victims in the UAE this month.
        </h2>

        {advisory.campaigns.length > 0 && (
          <ul className="mt-4 flex flex-wrap gap-x-6 gap-y-2">
            {advisory.campaigns.map((c) => (
              <li key={c.name} className="text-[13px] text-muted">
                <span className="text-ink">{c.name}</span>
                {c.threat_actor ? (
                  <span className="text-faint"> / {c.threat_actor}</span>
                ) : null}
                {c.ransomware &&
                c.ransomware.toLowerCase().startsWith("yes") ? (
                  <span className="text-alarm"> / ransomware</span>
                ) : null}
              </li>
            ))}
          </ul>
        )}

        <button
          type="button"
          onClick={() => setOpen((v) => !v)}
          aria-expanded={open}
          aria-controls="advisory-body"
          className="mt-4 text-[13px] text-signal underline-offset-4 transition hover:underline"
        >
          {open ? "Hide the full advisory" : "Read the full advisory"}
        </button>
      </div>

      <div
        id="advisory-body"
        hidden={!open}
        className="border-t border-line px-5 py-5 font-serif text-[14px] sm:px-6"
      >
        {renderMarkdown(advisory.raw_markdown)}
      </div>
    </section>
  );
}
