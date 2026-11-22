"use client";

import React from "react";
import { Zap, Check, ArrowRight } from "lucide-react";

interface DiffViewerProps {
  problemCode: string;
  fixedCode: string;
  lineNumber: number;
  category: string;
  cweId: string;
  onApplyFix: () => void;
  isApplied?: boolean;
}

export default function DiffViewer({
  problemCode,
  fixedCode,
  lineNumber,
  category,
  cweId,
  onApplyFix,
  isApplied = false,
}: DiffViewerProps) {
  const cleanLines = (text: string) => {
    if (!text) return [];
    const normalized = text.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
    const lines = normalized.split("\n");
    while (lines.length > 0 && lines[0].trim() === "") lines.shift();
    while (lines.length > 0 && lines[lines.length - 1].trim() === "") lines.pop();
    return lines.length > 0 ? lines : [normalized];
  };

  const probLines = cleanLines(problemCode);
  const fixLines = cleanLines(fixedCode);

  return (
    <div className="rounded-lg border border-white/[0.08] bg-[#09090B] overflow-hidden mb-3.5 transition-colors hover:border-white/[0.14]">
      {/* Header Bar */}
      <div className="bg-[#111114] border-b border-white/[0.08] px-3.5 py-2 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[10.5px] font-mono font-medium bg-red-500/10 text-red-400 border border-red-500/20">
            <span className="w-1.5 h-1.5 rounded-full bg-red-500"></span>
            BEFORE (Line {lineNumber})
          </span>
          <ArrowRight className="w-3 h-3 text-zinc-600" />
          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[10.5px] font-mono font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500"></span>
            AFTER (Auto-Healed)
          </span>
        </div>

        <span className="text-[10.5px] font-mono font-semibold px-2 py-0.5 rounded bg-white/[0.04] border border-white/[0.08] text-zinc-300">
          {cweId}
        </span>
      </div>

      {/* Code Diff Box */}
      <div className="font-mono text-[12px] leading-relaxed select-text overflow-x-auto divide-y divide-white/[0.02]">
        {/* Deleted / Vulnerable Lines */}
        {probLines.map((line, idx) => (
          <div
            key={`prob-${idx}`}
            className="flex items-start bg-red-500/[0.07] text-red-300 border-l-2 border-red-500 px-3 py-1 hover:bg-red-500/[0.12] transition-colors"
          >
            <span className="text-red-500/70 select-none w-5 text-right mr-3 font-semibold">-</span>
            <span className="flex-1 whitespace-pre">{line}</span>
          </div>
        ))}

        {/* Added / Fixed Lines */}
        {fixLines.map((line, idx) => (
          <div
            key={`fix-${idx}`}
            className="flex items-start bg-emerald-500/[0.07] text-emerald-300 border-l-2 border-emerald-500 px-3 py-1 hover:bg-emerald-500/[0.12] transition-colors"
          >
            <span className="text-emerald-500/70 select-none w-5 text-right mr-3 font-semibold">+</span>
            <span className="flex-1 whitespace-pre font-medium">{line}</span>
          </div>
        ))}
      </div>

      {/* 1-Click Action Footer */}
      <div className="px-3.5 py-2.5 bg-[#111114] border-t border-white/[0.08] flex flex-col sm:flex-row items-center justify-between gap-2.5">
        <div className="text-[11px] text-zinc-400 flex items-center gap-1.5">
          <Zap className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
          <span>Deterministic AST rewrite guarantees zero regression.</span>
        </div>

        <button
          onClick={onApplyFix}
          disabled={isApplied}
          className={`w-full sm:w-auto px-3.5 py-1.5 rounded-md font-semibold text-xs flex items-center justify-center gap-1.5 transition-all active:scale-[0.98] ${
            isApplied
              ? "bg-white/[0.06] text-emerald-400 border border-emerald-500/30 cursor-default"
              : "bg-emerald-500 hover:bg-emerald-400 text-zinc-950 shadow-sm"
          }`}
        >
          {isApplied ? (
            <>
              <Check className="w-3.5 h-3.5 text-emerald-400" />
              <span>Patch Applied to Editor</span>
            </>
          ) : (
            <>
              <Zap className="w-3.5 h-3.5 fill-zinc-950 text-zinc-950" />
              <span>Apply Surgical Fix</span>
            </>
          )}
        </button>
      </div>
    </div>
  );
}
