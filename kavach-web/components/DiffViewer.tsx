"use client";

import React from "react";
import { Zap, Check, AlertTriangle, ArrowRight } from "lucide-react";

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
  const probLines = problemCode.trim().split("\n");
  const fixLines = fixedCode.trim().split("\n");

  return (
    <div className="rounded-lg border border-obsidian-700 bg-obsidian-950 overflow-hidden shadow-xl mb-4 transition-all hover:border-obsidian-600">
      {/* Header Bar */}
      <div className="bg-obsidian-850 border-b border-obsidian-700 px-3.5 py-2.5 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-bold bg-kavachCrimson/15 text-kavachCrimson border border-kavachCrimson/25">
            <span className="w-1.5 h-1.5 rounded-full bg-kavachCrimson"></span>
            BEFORE (Line {lineNumber})
          </span>
          <ArrowRight className="w-3.5 h-3.5 text-slateText-muted" />
          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-bold bg-kavachEmerald/15 text-kavachEmerald border border-kavachEmerald/25">
            <span className="w-1.5 h-1.5 rounded-full bg-kavachEmerald"></span>
            AFTER (Kavach Auto-Healed)
          </span>
        </div>

        <span className="text-[11px] font-mono text-slateText-muted">
          {cweId}
        </span>
      </div>

      {/* Code Diff Box */}
      <div className="font-mono text-[12px] leading-relaxed select-text overflow-x-auto">
        {/* Deleted / Vulnerable Lines */}
        {probLines.map((line, idx) => (
          <div
            key={`prob-${idx}`}
            className="flex items-start bg-red-950/20 text-red-400 border-l-4 border-red-500 px-3 py-1 hover:bg-red-950/30 transition-colors"
          >
            <span className="text-red-500/70 select-none w-5 text-right mr-3 font-semibold">-</span>
            <span className="flex-1 whitespace-pre">{line}</span>
          </div>
        ))}

        {/* Added / Fixed Lines */}
        {fixLines.map((line, idx) => (
          <div
            key={`fix-${idx}`}
            className="flex items-start bg-emerald-950/20 text-emerald-300 border-l-4 border-emerald-500 px-3 py-1 hover:bg-emerald-950/30 transition-colors"
          >
            <span className="text-emerald-500/70 select-none w-5 text-right mr-3 font-semibold">+</span>
            <span className="flex-1 whitespace-pre font-medium">{line}</span>
          </div>
        ))}
      </div>

      {/* 1-Click Action Footer */}
      <div className="p-3 bg-obsidian-900 border-t border-obsidian-700/80 flex flex-col sm:flex-row items-center justify-between gap-3">
        <div className="text-[11.5px] text-slateText-secondary flex items-center gap-1.5">
          <Zap className="w-3.5 h-3.5 text-kavachEmerald" />
          <span>Deterministic AST rewrite guarantees 0% regression.</span>
        </div>

        <button
          onClick={onApplyFix}
          disabled={isApplied}
          className={`w-full sm:w-auto px-4 py-2 rounded-md font-semibold text-xs flex items-center justify-center gap-2 transition-all ${
            isApplied
              ? "bg-obsidian-800 text-kavachEmerald border border-kavachEmerald/30 cursor-default"
              : "bg-kavachEmerald text-obsidian-950 hover:bg-emerald-400 shadow-[0_0_15px_rgba(34,197,139,0.25)] active:scale-95"
          }`}
        >
          {isApplied ? (
            <>
              <Check className="w-4 h-4 text-kavachEmerald" />
              <span>Patch Applied to Editor</span>
            </>
          ) : (
            <>
              <Zap className="w-4 h-4 fill-obsidian-950" />
              <span>⚡ Apply 1-Click Surgical Fix</span>
            </>
          )}
        </button>
      </div>
    </div>
  );
}
